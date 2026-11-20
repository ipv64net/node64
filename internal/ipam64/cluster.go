package ipam64

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// IPAM64 im Cluster (verbunden ueber ipam64/ipamcluster, damit das Modul nicht vom Cluster abhaengt). Drei Bereiche,
// je Eintrag die uid: Praefixe, Adressbereiche, feste Adressen. Es gewinnt die juengere Aenderung (Cluster-Protokoll).
// Sichtungen, Scan-Einstellung und letzter Scan bleiben je Node.
//
// Gleiches Praefix bzw. gleiche Adresse unter zwei uids (auf zwei Nodes gleichzeitig angelegt): Es gilt die kleinere
// uid. Kommt sie von aussen, ersetzt sie den Eintrag hier (die eigene uid geht als geloescht hinaus); ist die eigene
// kleiner, wird der fremde Eintrag nicht uebernommen - die andere Node ersetzt ihren, sobald sie unseren bekommt. Eine
// verdraengte eigene Adresse ist ein Fund (Konflikt "double", 24 Stunden, mit Benachrichtigung): "naechste freie
// Adresse vergeben" ist nur je Node am Stueck, zwei Nodes koennen dieselbe Adresse gleichzeitig vergeben. Stammt der
// Eintrag hier von derselben Node wie die ankommende Aenderung, ist er dort schon geaendert (z. B. zwei Adressen
// getauscht) und nur noch nicht angekommen: kein Doppel, er macht still Platz.
//
// Uebernommene Eintraege schreiben nichts nach DNS64 durch (Stufe I3): die Eintraege dort kommen ueber den Abgleich
// von DNS64 (Plan E1).

// Bereiche im Cluster (Modul ipam64).
const (
	ClusterModuleID      = "ipam64"
	ClusterTitleKey      = "cluster.mod.ipam64"
	ClusterItemPrefixes  = "prefixes"
	ClusterItemRanges    = "ranges"
	ClusterItemAddresses = "addresses"
)

var errClusterItem = errors.New("ipam64 cluster: unknown area or entry")

// ClusterHooks verbinden das Modul mit dem Cluster; leer = kein Cluster.
type ClusterHooks struct {
	// Change meldet eine eigene Aenderung (ctx traegt bei Uebernahmen die Herkunft).
	Change func(ctx context.Context, item, id string, deleted bool)
	// ForeignDNS64 meldet, ob eine Node die Eintraege von DNS64 mit dieser abgleicht, nicht aber die Adressen von
	// IPAM64: dann kommen gekennzeichnete Eintraege, deren Adressen diese Node nicht kennt (keine Waisen).
	ForeignDNS64 func(ctx context.Context) bool
	// Stale meldet, ob der hier geltende Stand des Eintrags id von derselben Node stammt wie die ankommende Aenderung
	// (ctx): dann ist er dort schon geaendert und nur noch nicht hier angekommen, keine gleichzeitige Doppelvergabe.
	Stale func(ctx context.Context, item, id string) bool
}

// doubleKeep: so lange bleibt eine verdraengte Adresse als Fund stehen.
const doubleKeep = 24 * time.Hour

// double ist eine eigene Adresse, die eine andere Node gleichzeitig vergeben hat (ihre uid gewann).
type double struct {
	IP, Name string
	At       time.Time
}

// noteDouble merkt eine verdraengte eigene Adresse (Fund "double").
func (m *Module) noteDouble(ip, name string) {
	m.log.Warn("ipam64: address assigned on two nodes at the same time, own entry replaced", "address", ip, "name", name)
	m.recMu.Lock()
	defer m.recMu.Unlock()
	m.doubles = append(m.doubles, double{IP: ip, Name: name, At: m.now()})
}

// doubleFindings liefert die verdraengten eigenen Adressen der letzten doubleKeep.
func (m *Module) doubleFindings() []Finding {
	m.recMu.Lock()
	defer m.recMu.Unlock()
	var out []Finding
	keep := m.doubles[:0]
	for _, d := range m.doubles {
		if m.now().Sub(d.At) < doubleKeep {
			keep = append(keep, d)
			out = append(out, Finding{Kind: "double", Severity: "conflict", IP: d.IP, Name: d.Name})
		}
	}
	m.doubles = keep
	return out
}

// SetCluster haengt den Cluster an (vor Start).
func (m *Module) SetCluster(h ClusterHooks) { m.cluster = h }

// changed meldet eine Aenderung an den Cluster und verwirft den Zwischenstand der Zusammenfuehrung.
func (m *Module) changed(ctx context.Context, item, id string, deleted bool) {
	m.invalidate()
	if m.cluster.Change != nil && id != "" {
		m.cluster.Change(ctx, item, id, deleted)
	}
}

// ClusterIDs liefert alle Eintraege eines Bereichs.
func (m *Module) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	table, err := clusterTable(item)
	if err != nil {
		return nil, err
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT uid FROM `+table+` ORDER BY uid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func clusterTable(item string) (string, error) {
	switch item {
	case ClusterItemPrefixes:
		return "ipam_prefixes", nil
	case ClusterItemRanges:
		return "ipam_ranges", nil
	case ClusterItemAddresses:
		return "ipam_addresses", nil
	}
	return "", errClusterItem
}

// ClusterGet liefert den Stand eines Eintrags (found=false: gibt es nicht).
func (m *Module) ClusterGet(ctx context.Context, item, id string) (json.RawMessage, bool, error) {
	if !uidRe.MatchString(id) {
		return nil, false, nil
	}
	var v any
	var err error
	switch item {
	case ClusterItemPrefixes:
		var p *Prefix
		if p, err = m.prefixByUID(ctx, id); p != nil {
			v = p
		}
	case ClusterItemRanges:
		var r *Range
		if r, err = m.rangeByUID(ctx, id); r != nil {
			v = r
		}
	case ClusterItemAddresses:
		var a *Address
		if a, err = m.addressWhere(ctx, `uid = ?`, id); a != nil {
			v = a
		}
	default:
		return nil, false, errClusterItem
	}
	if err != nil || v == nil {
		return nil, false, err
	}
	b, err := json.Marshal(v)
	return b, err == nil, err
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node.
func (m *Module) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	if !uidRe.MatchString(id) {
		return errClusterItem
	}
	table, err := clusterTable(item)
	if err != nil {
		return err
	}
	defer m.invalidate()
	if deleted {
		_, err := m.core.Writer().ExecContext(ctx, `DELETE FROM `+table+` WHERE uid = ?`, id)
		return err
	}
	switch item {
	case ClusterItemPrefixes:
		var p Prefix
		if err := json.Unmarshal(data, &p); err != nil {
			return err
		}
		updated, by := p.Updated, p.UpdatedBy
		if err := normalizePrefix(&p); err != nil {
			return err
		}
		p.UID, p.Updated, p.UpdatedBy = id, updated, by
		if keep, err := m.clusterDouble(ctx, item, table, "prefix", p.Prefix, id); err != nil || keep {
			return err
		}
		return m.writePrefix(ctx, p)
	case ClusterItemRanges:
		var r Range
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		updated, by := r.Updated, r.UpdatedBy
		if err := normalizeRange(&r); err != nil {
			return err
		}
		r.UID, r.Updated, r.UpdatedBy = id, updated, by
		return m.writeRange(ctx, r)
	default:
		var a Address
		if err := json.Unmarshal(data, &a); err != nil {
			return err
		}
		updated, by := a.Updated, a.UpdatedBy
		if err := normalizeAddress(&a); err != nil {
			return err
		}
		a.UID, a.Updated, a.UpdatedBy = id, updated, by
		if keep, err := m.clusterDouble(ctx, item, table, "address", a.Address, id); err != nil || keep {
			return err
		}
		return m.writeAddress(ctx, a)
	}
}

// clusterDouble behandelt denselben Wert (Praefix, Adresse) unter einer anderen uid: keep=true, wenn die eigene uid
// kleiner ist (fremder Eintrag wird nicht uebernommen); sonst wird der eigene Eintrag ersetzt und als geloescht
// gemeldet.
func (m *Module) clusterDouble(ctx context.Context, item, table, col, value, id string) (bool, error) {
	var other string
	err := m.core.Reader().QueryRowContext(ctx, `SELECT uid FROM `+table+` WHERE `+col+` = ?`, value).Scan(&other)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && other == id) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if m.cluster.Stale != nil && m.cluster.Stale(ctx, item, other) {
		// kein Doppel: die Urheberin hat den eigenen Eintrag schon verschoben (z. B. zwei Adressen getauscht), sein
		// neuer Stand kommt noch - hier nur Platz machen, nichts melden
		_, err := m.core.Writer().ExecContext(ctx, `DELETE FROM `+table+` WHERE uid = ?`, other)
		return false, err
	}
	if other < id {
		return true, nil
	}
	var lost *Address
	if item == ClusterItemAddresses {
		lost, _ = m.addressWhere(ctx, `uid = ?`, other)
	}
	if _, err := m.core.Writer().ExecContext(ctx, `DELETE FROM `+table+` WHERE uid = ?`, other); err != nil {
		return false, err
	}
	if lost != nil {
		m.noteDouble(lost.Address, lost.Name)
	}
	if m.cluster.Change != nil {
		m.cluster.Change(ctx, item, other, true)
	}
	return false, nil
}
