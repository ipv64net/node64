package monitor64

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Migration von Proxmox-Gaesten im Cluster (#165). Ein Gast, der an einem Proxmox-Host uebernommen ist und auf eine
// andere Node desselben Clusters zieht (Migration, HA), gilt nicht als verschwunden:
//
//   - Der Sammler des Hosts sucht seine uebernommenen Gaeste, die auf der Node fehlen, in /cluster/resources und
//     liefert sie mit MovedTo = neue Node (Follow vor jeder Runde, apis/pve.go).
//   - Ist die neue Node in Monitor64 als Host mit Proxmox-Zugang eingetragen (nicht pausiert, gleicher Cluster),
//     uebergibt der Kern den Dienst dorthin: Name, Soll-Zustand, Melden und Schwellen "dieser Host" ziehen mit, der
//     Verlauf wird umbenannt; am alten Host ist der Dienst weg (nicht "verschwunden"). Im Ablauf des neuen Hosts steht
//     "migriert von Node A nach Node B" (Uebersicht, Zuletzt).
//   - Sonst bleibt der Dienst am bisherigen Host und wird dort mit den Werten aus dem Cluster weitergefuehrt ("laeuft
//     auf Node B"); auch das steht einmal im Ablauf, ebenso die Rueckkehr.
//
// Uebergeben wird nur auf der meldenden Node (roleReport); Dienste, die am Host nicht uebernommen sind, werden fuer
// andere Nodes weder vorgeschlagen noch bewertet.

// migratedKind ist die Art des Ereignisses im Ablauf des Hosts.
const migratedKind = "migrated"

// guestFollower: Sammler, der uebernommene Gaeste im Cluster weiterverfolgt (Proxmox VE).
type guestFollower interface {
	Follow(keys []string)
	Cluster() string
	Node() string
}

func followerOf(c collector) guestFollower {
	a, ok := c.(*apiAdapter)
	if !ok {
		return nil
	}
	f, _ := a.src.(guestFollower)
	return f
}

// isGuestKey: Dienst eines Proxmox-Gasts (vm:101, ct:200).
func isGuestKey(k string) bool {
	return strings.HasPrefix(k, "vm:") || strings.HasPrefix(k, "ct:")
}

// followKeys: am Host uebernommene Gaeste (auch schon verschwundene: tauchen sie im Cluster auf, gilt das nicht mehr).
func followKeys(rows []*ServiceRow) []string {
	out := []string{}
	for _, r := range rows {
		if r.Adopted == 1 && isGuestKey(r.Key) {
			out = append(out, r.Key)
		}
	}
	return out
}

// setFollow gibt den Proxmox-Sammlern des Hosts die uebernommenen Gaeste (vor dem Abfragen). Nach dem Start einmal
// aus der Datenbank, danach aus der vorigen Runde.
func (m *Module) setFollow(rt *hostRT) {
	var fs []guestFollower
	for _, a := range rt.accs {
		if f := followerOf(a.col); f != nil {
			fs = append(fs, f)
		}
	}
	if len(fs) == 0 {
		return
	}
	if rt.follow == nil {
		ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
		rows, err := m.store.Services(ctx, rt.host.UID)
		cancel()
		if err != nil {
			return
		}
		rt.follow = followKeys(rows)
	}
	for _, f := range fs {
		f.Follow(rt.follow)
	}
}

// migrateTarget sucht den Host der Proxmox-Node node im Cluster cluster (ausser self): Proxmox-Zugang aktiv, Host
// nicht pausiert. Stimmt der Cluster eines Zugangs aus seiner letzten Runde nicht, zaehlt er nicht (gleiche
// Node-Namen in zwei Clustern); unbekannt (Host einer anderen Node64 im Cluster) zaehlt der Node-Name.
func (m *Module) migrateTarget(ctx context.Context, self, node, cluster string) (*Host, error) {
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT a.uid, a.host_uid FROM m64_access a JOIN m64_hosts h ON h.uid = a.host_uid
		WHERE a.type = 'pve' AND a.deleted = 0 AND a.enabled = 1 AND h.deleted = 0 AND h.paused = 0 AND a.host_uid != ?
		AND COALESCE(json_extract(CASE WHEN json_valid(a.config) THEN a.config ELSE '{}' END, '$.node'), '') = ?
		ORDER BY h.name, h.uid`, self, node)
	if err != nil {
		return nil, err
	}
	type cand struct{ acc, host string }
	var list []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.acc, &c.host); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pick := ""
	for _, c := range list {
		cl, known := m.pveSeen.ClusterOf(c.acc)
		if known && cl != cluster {
			continue
		}
		if known || pick == "" { // bekannter gleicher Cluster vor unbekanntem
			pick = c.host
			if known {
				break
			}
		}
	}
	if pick == "" {
		return nil, nil
	}
	return m.store.Host(ctx, pick)
}

// MoveService uebergibt einen uebernommenen Dienst an einen anderen Host: dort uebernommen mit Name, Art, Soll,
// Melden und Schwellen (ist er dort schon uebernommen, bleiben dessen Einstellungen), hier entfernt. history: der
// Dienst war am Ziel noch nicht uebernommen (dort gibt es keinen eigenen Verlauf, der bisherige zieht um).
func (s *Store) MoveService(ctx context.Context, fromHost, toHost, key string) (moved, history bool, err error) {
	tx, err := s.st.Writer().BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var name, kind, hostRule, soll, report string
	err = tx.QueryRowContext(ctx, `SELECT name, kind, host_rule, soll, report FROM m64_services WHERE host_uid = ? AND key = ? AND adopted = 1 AND deleted = 0`,
		fromHost, key).Scan(&name, &kind, &hostRule, &soll, &report)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	now, sys := tsNow(), SystemActor.json()
	var adopted, deleted int
	err = tx.QueryRowContext(ctx, `SELECT adopted, deleted FROM m64_services WHERE host_uid = ? AND key = ?`, toHost, key).Scan(&adopted, &deleted)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		history = true
		if _, err := tx.ExecContext(ctx, `INSERT INTO m64_services (uid, host_uid, key, name, kind, adopted, host_rule, soll, report, updated_at, updated_by)
			VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`, newUID(), toHost, key, name, kind, hostRule, soll, report, now, sys); err != nil {
			return false, false, err
		}
	case err != nil:
		return false, false, err
	case adopted == 1 && deleted == 0: // am Ziel schon uebernommen: dessen Einstellungen und Verlauf gelten
	default:
		history = true
		if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET name = ?, kind = ?, adopted = 1, deleted = 0, vanished_at = '', via = '', host_rule = ?, soll = ?, report = ?,
			updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ?`, name, kind, hostRule, soll, report, now, sys, toHost, key); err != nil {
			return false, false, err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE m64_services SET deleted = 1, updated_at = ?, updated_by = ? WHERE host_uid = ? AND key = ? AND deleted = 0`,
		now, sys, fromHost, key); err != nil {
		return false, false, err
	}
	return true, history, tx.Commit()
}

// seriesRenamer: Verlauf eines Dienstes an einen anderen Host haengen (tsdb).
type seriesRenamer interface {
	RenameSeriesPrefix(ctx context.Context, from, to string) (int, error)
}

// migrated behandelt Gaeste, die der Sammler auf einer anderen Node gefunden hat (MovedTo): Uebergabe an den Host
// der Node bzw. Weiterfuehren hier. Liefert die Dienste ohne die uebergebenen. found verliert alle migrierten
// Gaeste, die hier nicht uebernommen sind, und die uebergebenen.
func (m *Module) migrated(ctx context.Context, h *Host, rt *hostRT, rows []*ServiceRow, found map[string]foundSvc, role int, now time.Time) []*ServiceRow {
	adopted := map[string]*ServiceRow{}
	for _, r := range rows {
		if r.Adopted == 1 {
			adopted[r.Key] = r
		}
	}
	follower := map[string]guestFollower{}
	for _, a := range rt.accs {
		if f := followerOf(a.col); f != nil {
			follower[a.row.UID] = f
		}
	}
	gone := map[string]bool{}
	for k, g := range found {
		if !isGuestKey(k) {
			continue
		}
		f := follower[g.acc]
		if g.svc.MovedTo == "" { // (wieder) auf dieser Node
			if prev := rt.Moved[k]; prev != "" && adopted[k] != nil && f != nil && role == roleReport {
				m.event(ctx, "", h.UID, k, migratedKind, i18nText("monitor64.detail.guest_back", "from", prev, "to", f.Node()), SystemActor, now)
			}
			delete(rt.Moved, k)
			continue
		}
		r := adopted[k]
		if r == nil || f == nil {
			delete(found, k) // hier nicht uebernommen: nicht vorschlagen, nicht bewerten
			continue
		}
		if role != roleReport {
			continue // ohne Meldung keine Uebergabe; weiter hier messen
		}
		to, err := m.migrateTarget(ctx, h.UID, g.svc.MovedTo, f.Cluster())
		if err != nil {
			m.log.Warn("monitor64: migrate target", "host", h.Name, "key", k, "err", err)
			continue
		}
		if to == nil { // neue Node nicht eingetragen: hier weiterfuehren
			if rt.Moved[k] != g.svc.MovedTo {
				m.event(ctx, "", h.UID, k, migratedKind, i18nText("monitor64.detail.guest_followed", "from", firstNonEmpty(rt.Moved[k], f.Node()), "to", g.svc.MovedTo), SystemActor, now)
				rt.Moved[k], rt.dirty = g.svc.MovedTo, true
			}
			continue
		}
		moved, history, err := m.store.MoveService(ctx, h.UID, to.UID, k)
		if err != nil {
			m.log.Warn("monitor64: migrate service", "host", h.Name, "to", to.Name, "key", k, "err", err)
			continue
		}
		if !moved {
			continue
		}
		if history {
			if ren, ok := m.seriesStore().(seriesRenamer); ok {
				if _, err := ren.RenameSeriesPrefix(ctx, seriesKey(h.UID, k, ""), seriesKey(to.UID, k, "")); err != nil {
					m.log.Warn("monitor64: migrate history", "host", h.Name, "to", to.Name, "key", k, "err", err)
				}
			}
		}
		m.event(ctx, "", to.UID, k, migratedKind, i18nText("monitor64.detail.guest_migrated", "from", firstNonEmpty(rt.Moved[k], f.Node()),
			"to", g.svc.MovedTo, "host", h.Name), SystemActor, now)
		m.log.Info("monitor64: guest migrated", "key", k, "from", h.Name, "to", to.Name)
		rt.forget(k)
		delete(found, k)
		gone[k] = true
		m.repoll(to.UID)
	}
	if len(gone) == 0 {
		return rows
	}
	out := rows[:0:0]
	for _, r := range rows {
		if !gone[r.Key] {
			out = append(out, r)
		}
	}
	return out
}

// forget raeumt den Laufzeitstand eines Dienstes ab (an einen anderen Host uebergeben).
func (rt *hostRT) forget(key string) {
	prefix := key + "|"
	for k := range rt.Trackers {
		if strings.HasPrefix(k, prefix) {
			delete(rt.Trackers, k)
		}
	}
	for k := range rt.Kinds {
		if strings.HasPrefix(k, prefix) {
			delete(rt.Kinds, k)
		}
	}
	delete(rt.Missing, key)
	delete(rt.Provider, key)
	delete(rt.Rising, key)
	delete(rt.Local, key)
	delete(rt.Trend, key)
	delete(rt.Moved, key)
	rt.dirty = true
}
