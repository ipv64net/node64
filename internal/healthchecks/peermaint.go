package healthchecks

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Wartungsfenster in der lokalen Gruppe (peer-Paket): Die lokale Nummer ist je Node verschieden, daher hat jedes
// Fenster eine feste Kennung (uid). Dasselbe Fenster kann auf zwei Nodes verschiedene Kennungen haben (beide vom
// hub angelegt); erkannt wird es dann an der Server-ID. Kennungen werden nie umbenannt, und geloescht wird nur
// mit einem echten Loeschvermerk (m:<uid>, Server-ID in revision) – sonst koennte eine Loeschung bis zum hub laufen.

// PeerMaint ist ein Wartungsfenster fuer die anderen Nodes (ID = Server-ID, 0 = nur lokal).
type PeerMaint struct {
	UID string `json:"uid"`
	wire.Maintenance
}

type deletedUIDKey struct{}

// DeletedMaintUID liefert im "delete"-Hook die Kennung des geloeschten Wartungsfensters.
func DeletedMaintUID(ctx context.Context) string {
	v, _ := ctx.Value(deletedUIDKey{}).(string)
	return v
}

// WithDeletedRemote setzt die Server-ID fuer den "delete"-Hook (Weiterreichen einer Loeschung an den hub).
func WithDeletedRemote(ctx context.Context, rid int64) context.Context {
	return context.WithValue(ctx, deletedRemoteKey{}, rid)
}

func newUID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// changeTime: Zeitpunkt einer Aenderung (von einer anderen Node uebernommen: deren Zeitpunkt).
func changeTime(ctx context.Context) time.Time {
	if _, at, ok := PeerSource(ctx); ok {
		return at
	}
	return time.Now()
}

// MaintUID liefert die Kennung zur lokalen Nummer.
func (m *Module) MaintUID(ctx context.Context, localID string) string {
	var uid string
	_ = m.st.r.QueryRowContext(ctx, `SELECT uid FROM hc_maintenance WHERE id = ?`, localID).Scan(&uid)
	return uid
}

// PeerMaintUIDs: alle Wartungsfenster (fuer den ersten Abgleich).
func (m *Module) PeerMaintUIDs(ctx context.Context) []string {
	rows, err := m.st.r.QueryContext(ctx, `SELECT uid FROM hc_maintenance WHERE uid != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid string
		if rows.Scan(&uid) == nil {
			out = append(out, uid)
		}
	}
	return out
}

// PeerMaintenance liefert ein Wartungsfenster mit Zeitpunkt der letzten Aenderung; fehlt es, Zeitpunkt und
// Server-ID des Loeschvermerks (alles leer = unbekannt).
func (m *Module) PeerMaintenance(ctx context.Context, uid string) (*PeerMaint, time.Time, time.Time, int64, error) {
	var id int64
	var upd string
	err := m.st.r.QueryRowContext(ctx, `SELECT id, updated_at FROM hc_maintenance WHERE uid = ?`, uid).Scan(&id, &upd)
	if err == nil {
		mw, err := m.MaintenanceByID(ctx, id)
		if err != nil || mw == nil {
			return nil, time.Time{}, time.Time{}, 0, err
		}
		return &PeerMaint{UID: uid, Maintenance: m.WireMaintenance(*mw)}, pt(upd), time.Time{}, 0, nil
	}
	var del string
	var rid int64
	_ = m.st.r.QueryRowContext(ctx, `SELECT deleted_at, revision FROM hc_tombstones WHERE token = ?`, "m:"+uid).Scan(&del, &rid)
	return nil, time.Time{}, pt(del), rid, nil
}

// findMaint sucht ein Fenster ueber die Kennung, sonst ueber die Server-ID.
func (m *Module) findMaint(ctx context.Context, uid string, remote int64) (int64, time.Time) {
	var id int64
	var upd string
	if m.st.r.QueryRowContext(ctx, `SELECT id, updated_at FROM hc_maintenance WHERE uid = ?`, uid).Scan(&id, &upd) == nil {
		return id, pt(upd)
	}
	if remote > 0 && m.st.r.QueryRowContext(ctx, `SELECT id, updated_at FROM hc_maintenance WHERE remote_id = ? ORDER BY id LIMIT 1`, remote).Scan(&id, &upd) == nil {
		return id, pt(upd)
	}
	return 0, time.Time{}
}

// ApplyPeerMaintenance uebernimmt ein Wartungsfenster einer anderen Node, wenn ihre Aenderung juenger ist.
// Liefert die lokale Nummer (fuer das Weiterreichen an den hub).
func (m *Module) ApplyPeerMaintenance(ctx context.Context, p PeerMaint, at time.Time, origin string) (int64, bool, error) {
	id, upd := m.findMaint(ctx, p.UID, p.ID)
	if id > 0 && !at.After(upd) {
		return id, false, nil // hier gleich alt oder juenger
	}
	if id == 0 {
		var del string
		_ = m.st.r.QueryRowContext(ctx, `SELECT deleted_at FROM hc_tombstones WHERE token = ?`, "m:"+p.UID).Scan(&del)
		if d := pt(del); !d.IsZero() && !at.After(d) {
			return 0, false, nil // hier nach dieser Aenderung geloescht
		}
	}
	mw := Maintenance{ID: id, UID: p.UID, RemoteID: p.ID, Name: p.Name, StartAt: p.StartAt, EndAt: p.EndAt, Repeat: p.Repeat,
		RepeatUntil: p.RepeatUntil, Tokens: p.Tokens, Active: p.Active}
	if p.ID > 0 {
		mw.Revision = p.Revision
	}
	if mw.Repeat == "" {
		mw.Repeat = "none"
	}
	if mw.Tokens == nil {
		mw.Tokens = []string{}
	}
	pctx := WithPeer(ctx, origin, at)
	var err error
	if id > 0 {
		err = m.st.MaintenanceUpdate(pctx, &mw)
	} else {
		mw.CreatedAt = time.Now()
		err = m.st.MaintenanceInsert(pctx, &mw)
	}
	if err != nil {
		return 0, false, err
	}
	if p.ID > 0 { // dasselbe Fenster unter anderer Kennung (z. B. vom hub und aus der Gruppe): zusammenfuehren
		if res, _ := m.st.w.ExecContext(ctx, `DELETE FROM hc_maintenance WHERE remote_id = ? AND id != ?`, p.ID, mw.ID); res != nil {
			if n, _ := res.RowsAffected(); n > 0 {
				m.st.reloadMaintenance(ctx)
			}
		}
	}
	return mw.ID, true, nil
}

// DeletePeerMaintenance loescht ein Fenster, das eine andere Node geloescht hat (nicht, wenn es hier danach
// geaendert wurde). Liefert lokale Nummer und Server-ID des geloeschten Fensters.
func (m *Module) DeletePeerMaintenance(ctx context.Context, uid string, remote int64, at time.Time, origin string) (int64, bool, error) {
	id, upd := m.findMaint(ctx, uid, remote)
	if id == 0 || upd.After(at) {
		return 0, false, nil
	}
	if err := m.st.MaintenanceDelete(WithPeer(ctx, origin, at), id); err != nil {
		return 0, false, err
	}
	return id, true, nil
}

// LogMaintenanceRemote meldet der Gruppe, dass ein Fenster seine Server-ID bekommen hat (nach dem ack), damit
// die anderen Nodes es dem Fenster vom hub zuordnen koennen.
func (m *Module) LogMaintenanceRemote(ctx context.Context, localID int64) {
	if f := m.st.OnAnyChange; f != nil {
		_, _ = m.st.w.ExecContext(ctx, `UPDATE hc_maintenance SET updated_at = ? WHERE id = ?`, ft(time.Now()), localID)
		f(WithRemote(ctx), "maintenance", strconv.FormatInt(localID, 10), "upsert")
	}
}
