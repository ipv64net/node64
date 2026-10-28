package healthchecks

import (
	"context"
	"slices"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Abgleich der Checks in der lokalen Gruppe (peer-Paket): Zustand eines Checks fuer andere Nodes liefern und
// Aenderungen anderer Nodes uebernehmen. Regel wie beim hub: die juengere Aenderung gewinnt (Zeitpunkt der
// Aenderung bleibt beim Weiterreichen erhalten), Geloeschtes bleibt geloescht, ausser es wurde danach geaendert.
// Uebernommene Aenderungen gehen nicht in die Outbox des hub (der bekommt sie von der Node, auf der sie entstanden).

type peerKey struct{}

type peerSource struct {
	origin string
	at     time.Time
}

// WithPeer markiert eine Aenderung als von einer anderen Node der Gruppe uebernommen (Herkunft, Zeitpunkt).
func WithPeer(ctx context.Context, origin string, at time.Time) context.Context {
	return context.WithValue(WithRemote(ctx), peerKey{}, peerSource{origin, at})
}

// PeerSource liefert Herkunft und Zeitpunkt einer uebernommenen Aenderung (ok = false: lokal oder vom hub).
func PeerSource(ctx context.Context) (origin string, at time.Time, ok bool) {
	v, ok := ctx.Value(peerKey{}).(peerSource)
	return v.origin, v.at, ok
}

// PeerCheck liefert einen Check fuer die anderen Nodes: Wire-Form, Zeitpunkt der letzten Aenderung; fehlt er,
// den Zeitpunkt der Loeschung (beide leer = unbekannt). Ein lokaler Check ohne Liste der messenden Nodes
// bekommt diese Node als Messstelle (sonst wuerde die Empfaengerin ihn selbst messen).
func (m *Module) PeerCheck(ctx context.Context, token, self string) (*wire.Check, time.Time, time.Time, error) {
	c, err := m.st.Check(ctx, token)
	if err != nil {
		return nil, time.Time{}, time.Time{}, err
	}
	if c == nil {
		return nil, time.Time{}, m.TombstoneAt(ctx, token), nil
	}
	w := m.WireCheck(c, nil)
	if c.Execution != "online" && len(w.Nodes) == 0 && (c.Owner == "" || c.Owner == "self") && self != "" {
		w.Nodes = []string{self}
	}
	if m.notifyStore != nil { // Kanaele ueber ihre Kennung im Cluster (der Cluster laesst sie weg, wenn der Bereich aus ist)
		uids := []string{}
		for _, id := range c.Channels {
			if uid := m.notifyStore.ClusterUIDOf(ctx, id); uid != "" {
				uids = append(uids, uid)
			}
		}
		w.ChannelUIDs = &uids
	}
	return &w, c.UpdatedAt, time.Time{}, nil
}

// TombstoneAt: Zeitpunkt, zu dem ein Check hier geloescht wurde (leer = nie).
func (m *Module) TombstoneAt(ctx context.Context, token string) time.Time {
	var t string
	_ = m.st.r.QueryRowContext(ctx, `SELECT deleted_at FROM hc_tombstones WHERE token = ?`, token).Scan(&t)
	return pt(t)
}

// PeerTokens: alle Checks (fuer den ersten Abgleich nach dem Beitritt).
func (m *Module) PeerTokens(ctx context.Context) []string {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.Token)
	}
	return out
}

// ApplyPeerCheck uebernimmt einen Check einer anderen Node, wenn ihre Aenderung juenger ist. Kanaele bleiben
// je Node lokal, ausser beide Nodes gleichen die Kanaele ab (w.ChannelUIDs): dann gelten die Kanaele der anderen
// Node ueber ihre Kennung, Kanaele hier ausserhalb des Clusters (z. B. die des Portals) bleiben. Sicht auf den Besitz
// (self/other/online) ergibt sich aus den messenden Nodes.
func (m *Module) ApplyPeerCheck(ctx context.Context, w wire.Check, changedAt time.Time, origin, self string) (bool, error) {
	cur, err := m.st.Check(ctx, w.Token)
	if err != nil {
		return false, err
	}
	if cur != nil && changedAt.Equal(cur.UpdatedAt) && w.ChannelUIDs != nil && m.notifyStore != nil {
		// gleicher Stand (z. B. Kanaele gerade eingeschaltet): Kanaele beider Seiten vereinen, ohne neue Aenderung -
		// beide Nodes kommen so zum selben Ergebnis
		if both := m.peerChannels(ctx, cur.Channels, *w.ChannelUIDs, true); !slices.Equal(both, cur.Channels) {
			_, err = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET channels = ? WHERE token = ?`, joinInts(both), w.Token)
		}
		return false, err
	}
	if cur != nil && !changedAt.After(cur.UpdatedAt) {
		return false, nil // hier gleich alt oder juenger
	}
	if cur == nil {
		if del := m.TombstoneAt(ctx, w.Token); !del.IsZero() && !changedAt.After(del) {
			return false, nil // hier nach dieser Aenderung geloescht
		}
	}
	switch {
	case w.Execution == "online":
		w.Owner = "online"
	case len(w.Nodes) > 0 && w.Nodes[0] == self:
		w.Owner = "self"
	default:
		w.Owner = "other"
	}
	w.Channels = []int64{}
	if cur != nil {
		w.Channels = append(w.Channels, cur.Channels...) // Kanaele sind je Node verschieden
		if w.Revision <= cur.Revision {
			w.Revision = 0 // Revision des hub nur uebernehmen, wenn sie neuer ist
		}
	}
	if w.ChannelUIDs != nil && m.notifyStore != nil {
		w.Channels = m.peerChannels(ctx, w.Channels, *w.ChannelUIDs, false)
	}
	pctx := WithPeer(ctx, origin, changedAt)
	if err := m.ApplyWireCheck(pctx, w, nil); err != nil {
		return false, err
	}
	_, err = m.st.w.ExecContext(ctx, `UPDATE hc_checks SET updated_at = ?, updated_by = ? WHERE token = ?`, ft(changedAt), "peer:"+origin, w.Token)
	return true, err
}

// peerChannels: Kanaele eines Checks aus dem Cluster. keep = alle bisherigen behalten (vereinen), sonst nur die
// ausserhalb des Clusters; dazu die Kanaele der Kennungen, die es hier gibt (eine noch fehlende faellt weg).
func (m *Module) peerChannels(ctx context.Context, local []int64, uids []string, keep bool) []int64 {
	out := []int64{}
	for _, id := range local {
		if (keep || m.notifyStore.ClusterUIDOf(ctx, id) == "") && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, uid := range uids {
		if id := m.notifyStore.ClusterIDOf(ctx, uid); id > 0 && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// DeletePeerCheck loescht einen Check, den eine andere Node geloescht hat (nicht, wenn er hier danach geaendert wurde).
func (m *Module) DeletePeerCheck(ctx context.Context, token string, deletedAt time.Time, origin string) (bool, error) {
	cur, err := m.st.Check(ctx, token)
	if err != nil {
		return false, err
	}
	if cur != nil && cur.UpdatedAt.After(deletedAt) {
		return false, nil
	}
	if cur != nil {
		if err := m.RemoveRemoteCheck(WithPeer(ctx, origin, deletedAt), token); err != nil {
			return false, err
		}
	}
	// Zeitpunkt der Loeschung wie bei der Urheberin (spaetere, aeltere Aenderungen holen ihn nicht zurueck)
	_, err = m.st.w.ExecContext(ctx, `INSERT INTO hc_tombstones (token, revision, deleted_at) VALUES (?, 0, ?)
		ON CONFLICT(token) DO UPDATE SET deleted_at = excluded.deleted_at`, token, ft(deletedAt))
	return cur != nil, err
}
