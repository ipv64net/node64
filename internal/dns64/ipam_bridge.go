package dns64

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
)

// Schnittstelle zu IPAM64 (Plan docs/PLAN-NODE64-IPAM64.md, Stufe I2, Entscheidung E1). IPAM64 ist fuehrend fuer feste
// Eintraege und schreibt sie gekennzeichnet hierher (origin = "ipam64", ref = uid der Adresse in IPAM64):
// DHCP-Reservierungen, Ausnahmen im DHCP-Adressbereich und A/AAAA-Eintraege (PTR wie immer aus A/AAAA). DHCP-Server und
// DNS lesen wie bisher aus ihren Tabellen; so haben auch die Reserve-Node und Nodes ohne IPAM64 die Eintraege (ueber
// den Abgleich von DNS64), und nichts geht verloren, wenn IPAM64 aus ist.
//
// Solange IPAM64 laeuft, lassen sich gekennzeichnete Eintraege hier nicht aendern (Oberflaeche, API): Hinweis mit
// Link zu IPAM64. Ohne IPAM64 sind sie normal bearbeitbar. ReleaseIPAM nimmt das Kennzeichen weg (Uebergabe an DNS64).

// OriginIPAM ist die Herkunft der Eintraege aus IPAM64.
const OriginIPAM = "ipam64"

// DHCPExclude ist eine Ausnahme im DHCP-Adressbereich (die Adresse vergibt der Server nie).
type DHCPExclude struct {
	ID      int64  `json:"id"`
	ScopeID int64  `json:"scope_id"`
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
	Origin  string `json:"origin,omitempty"`
	Ref     string `json:"ref,omitempty"`
}

// IPAMState sind alle Eintraege, die IPAM64 hier besitzt (Abgleich in IPAM64).
type IPAMState struct {
	Reservations []DHCPReservation `json:"reservations"`
	Excludes     []DHCPExclude     `json:"excludes"`
	Records      []Record          `json:"records"`
}

var errIPAMManaged = errCfg("err_ipam_managed")

// ErrKey liefert den i18n-Schluessel eines Eingabefehlers von DNS64 (dns64.err.*, "" = kein solcher Fehler), damit
// IPAM64 ihn uebersetzt anzeigen kann.
func ErrKey(err error) string {
	var ce *cfgError
	if errors.As(err, &ce) {
		return "dns64.err." + strings.TrimPrefix(ce.Key, "err_")
	}
	return ""
}

// SetIPAM meldet, ob IPAM64 laeuft (main.go); nur dann sind gekennzeichnete Eintraege hier gesperrt.
func (m *Module) SetIPAM(running func() bool) { m.ipamRunning = running }

// IPAMLocked: ein Eintrag mit dieser Herkunft ist hier gesperrt (IPAM64 laeuft und besitzt ihn).
func (m *Module) IPAMLocked(origin string) bool {
	return origin == OriginIPAM && m.ipamRunning != nil && m.ipamRunning()
}

// lockedRow prueft die Herkunft einer Zeile (table: dns64_records, dns64_dhcp_reservations).
func (m *Module) lockedRow(ctx context.Context, table string, id int64) error {
	var origin string
	err := m.core.Reader().QueryRowContext(ctx, `SELECT origin FROM `+table+` WHERE id = ?`, id).Scan(&origin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // "nicht gefunden" meldet die Aenderung selbst
	}
	if err != nil {
		return err
	}
	if m.IPAMLocked(origin) {
		return errIPAMManaged
	}
	return nil
}

// DHCPLeases liefert die Vergaben des laufenden DHCP-Servers (nil = DHCP aus). Aus dem Entwurf von UlrichSchwarz.
func (m *Module) DHCPLeases() []dhcp.Lease {
	s := m.dhcpSrv.Load()
	if s == nil {
		return nil
	}
	var out []dhcp.Lease
	for _, sv := range s.Snapshot().Scopes {
		out = append(out, sv.Leases...)
	}
	return out
}

// DHCPExcludes liefert alle Ausnahmen im DHCP-Adressbereich.
func (m *Module) DHCPExcludes(ctx context.Context) ([]DHCPExclude, error) {
	return m.dhcpExcludesWhere(ctx, "1 = 1")
}

func (m *Module) dhcpExcludesWhere(ctx context.Context, where string, args ...any) ([]DHCPExclude, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, scope_id, ip, comment, origin, ref FROM dns64_dhcp_excludes WHERE `+where+` ORDER BY scope_id, id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DHCPExclude{}
	for rows.Next() {
		var x DHCPExclude
		if err := rows.Scan(&x.ID, &x.ScopeID, &x.IP, &x.Comment, &x.Origin, &x.Ref); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// IPAMEntries liefert alle Eintraege, die IPAM64 hier besitzt.
func (m *Module) IPAMEntries(ctx context.Context) (IPAMState, error) {
	st := IPAMState{Reservations: []DHCPReservation{}, Records: []Record{}}
	res, err := m.DHCPReservations(ctx)
	if err != nil {
		return st, err
	}
	for _, r := range res {
		if r.Origin == OriginIPAM {
			st.Reservations = append(st.Reservations, r)
		}
	}
	if st.Excludes, err = m.dhcpExcludesWhere(ctx, `origin = ?`, OriginIPAM); err != nil {
		return st, err
	}
	recs, err := m.Records(ctx)
	if err != nil {
		return st, err
	}
	for _, r := range recs {
		if r.Origin == OriginIPAM {
			st.Records = append(st.Records, r)
		}
	}
	return st, nil
}

// dhcpScopeFor liefert das DHCP-Netz, in dem ip liegt (das kleinste; errCfg err_dhcp_scope = keins).
func (m *Module) dhcpScopeFor(ctx context.Context, ip netip.Addr) (DHCPScope, error) {
	scopes, err := m.DHCPScopes(ctx)
	if err != nil {
		return DHCPScope{}, err
	}
	var best DHCPScope
	bits := -1
	for _, s := range scopes {
		if p, err := netip.ParsePrefix(s.Subnet); err == nil && p.Contains(ip) && p.Bits() > bits {
			best, bits = s, p.Bits()
		}
	}
	if bits < 0 {
		return best, errCfg("err_dhcp_scope")
	}
	return best, nil
}

// ipamDHCPChanged startet den DHCP-Server neu und meldet Netze und feste Adressen an den Cluster.
func (m *Module) ipamDHCPChanged(ctx context.Context) {
	m.dhcpApply(ctx)
	m.dhcpSynced(ctx)
}

// PutIPAMReservation legt die DHCP-Reservierung einer Adresse aus IPAM64 an bzw. ersetzt sie (MAC oder IP neu). Das
// Netz ist das DHCP-Netz, in dem ip liegt. Eine gleiche Reservierung von Hand (MAC und IP) wird gekennzeichnet statt
// doppelt angelegt; eine andere mit derselben MAC oder IP ist ein Fehler. Eine Ausnahme derselben Adresse aus IPAM64
// faellt weg (Reservierung geht vor).
func (m *Module) PutIPAMReservation(ctx context.Context, ref, mac, ip, name string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || ref == "" {
		return errCfg("err_dhcp_res_ip")
	}
	sc, err := m.dhcpScopeFor(ctx, a.Unmap())
	if err != nil {
		return err
	}
	r := DHCPReservation{ScopeID: sc.ID, MAC: mac, IP: a.Unmap().String(), Name: name}
	if err := m.normalizeDHCPReservation(ctx, &r, true); err != nil {
		return err
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `SELECT id, mac, ip, origin, ref FROM dns64_dhcp_reservations WHERE scope_id = ? AND (mac = ? OR ip = ?)`, r.ScopeID, r.MAC, r.IP)
	if err != nil {
		return err
	}
	var claim int64
	for rows.Next() {
		var id int64
		var omac, oip, origin, oref string
		if err := rows.Scan(&id, &omac, &oip, &origin, &oref); err != nil {
			rows.Close()
			return err
		}
		switch {
		case origin == OriginIPAM && oref == ref: // eigene, wird ersetzt
		case origin == "" && omac == r.MAC && oip == r.IP:
			claim = id
		default:
			rows.Close()
			return errCfg("err_dhcp_res_dup")
		}
	}
	rows.Close()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns64_dhcp_reservations WHERE origin = ? AND ref = ?`, OriginIPAM, ref); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns64_dhcp_excludes WHERE origin = ? AND ref = ?`, OriginIPAM, ref); err != nil {
		return err
	}
	if claim > 0 {
		_, err = tx.ExecContext(ctx, `UPDATE dns64_dhcp_reservations SET origin = ?, ref = ?, name = ? WHERE id = ?`, OriginIPAM, ref, r.Name, claim)
	} else {
		_, err = tx.ExecContext(ctx, `INSERT INTO dns64_dhcp_reservations (scope_id, mac, ip, name, comment, origin, ref) VALUES (?,?,?,?,?,?,?)`,
			r.ScopeID, r.MAC, r.IP, r.Name, "", OriginIPAM, ref)
	}
	if isUnique(err) {
		return errCfg("err_dhcp_res_dup")
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.ipamDHCPChanged(ctx)
	return nil
}

// DeleteIPAMReservation loescht die DHCP-Reservierung einer Adresse aus IPAM64 (keine = kein Fehler).
func (m *Module) DeleteIPAMReservation(ctx context.Context, ref string) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_dhcp_reservations WHERE origin = ? AND ref = ?`, OriginIPAM, ref)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		m.ipamDHCPChanged(ctx)
	}
	return nil
}

// PutIPAMExclude nimmt eine Adresse aus IPAM64 aus der Vergabe des DHCP-Servers (Ausnahme im Adressbereich), z. B.
// ein fest eingestelltes Geraet im Pool. Eine Reservierung derselben Adresse aus IPAM64 faellt weg; eine andere
// Reservierung dieser IP ist ein Fehler.
func (m *Module) PutIPAMExclude(ctx context.Context, ref, ip, comment string) error {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil || ref == "" {
		return errCfg("err_dhcp_res_ip")
	}
	a = a.Unmap()
	sc, err := m.dhcpScopeFor(ctx, a)
	if err != nil {
		return err
	}
	p, _ := netip.ParsePrefix(sc.Subnet)
	if a == p.Masked().Addr() || a == dhcp.Broadcast(p) {
		return errCfg("err_dhcp_res_ip")
	}
	if comment = strings.TrimSpace(comment); len(comment) > 200 {
		return errCfg("err_comment")
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_dhcp_reservations WHERE scope_id = ? AND ip = ? AND NOT (origin = ? AND ref = ?)`,
		sc.ID, a.String(), OriginIPAM, ref).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errCfg("err_dhcp_res_dup")
	}
	for _, q := range []string{`DELETE FROM dns64_dhcp_reservations WHERE origin = ? AND ref = ?`, `DELETE FROM dns64_dhcp_excludes WHERE origin = ? AND ref = ?`} {
		if _, err := tx.ExecContext(ctx, q, OriginIPAM, ref); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_dhcp_excludes (scope_id, ip, comment, origin, ref) VALUES (?,?,?,?,?)
		ON CONFLICT (scope_id, ip) DO UPDATE SET comment = excluded.comment, origin = excluded.origin, ref = excluded.ref`, sc.ID, a.String(), comment, OriginIPAM, ref); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.ipamDHCPChanged(ctx)
	return nil
}

// DeleteIPAMExclude loescht die Ausnahme einer Adresse aus IPAM64 (keine = kein Fehler).
func (m *Module) DeleteIPAMExclude(ctx context.Context, ref string) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_dhcp_excludes WHERE origin = ? AND ref = ?`, OriginIPAM, ref)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		m.ipamDHCPChanged(ctx)
	}
	return nil
}

// PutIPAMRecords setzt die A/AAAA-Eintraege einer Adresse aus IPAM64: name (voller Name) mit genau diesen Adressen;
// ptr = Rueckwaertssuche aus den Eintraegen. Was IPAM64 fuer ref vorher hatte und nicht mehr gilt, faellt weg. Ein
// gleicher Eintrag von Hand wird gekennzeichnet statt doppelt angelegt; gehoert er einer anderen Adresse aus IPAM64
// oder steht ein CNAME auf dem Namen, ist das ein Fehler.
func (m *Module) PutIPAMRecords(ctx context.Context, ref, name string, addrs []netip.Addr, ptr bool) error {
	if ref == "" || len(addrs) == 0 {
		return errCfg("err_ipam_input")
	}
	var want []Record
	for _, a := range addrs {
		r := Record{Name: name, Type: "A", Value: a.Unmap().String(), NoPTR: !ptr}
		if a.Unmap().Is6() {
			r.Type = "AAAA"
		}
		if err := normalizeRecord(&r); err != nil {
			return err
		}
		want = append(want, r)
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, type, value, origin, ref FROM dns64_records WHERE name = ?`, want[0].Name)
	if err != nil {
		return err
	}
	type row struct {
		id                       int64
		typ, value, origin, oref string
	}
	var have []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.id, &x.typ, &x.value, &x.origin, &x.oref); err != nil {
			rows.Close()
			return err
		}
		have = append(have, x)
	}
	rows.Close()
	claim := map[int64]bool{}
	for _, w := range want {
		for _, h := range have {
			switch {
			case h.typ == "CNAME":
				return errCfg("err_cname")
			case h.typ != w.Type || h.value != w.Value || (h.origin == OriginIPAM && h.oref == ref):
			case h.origin == "":
				claim[h.id] = true
			default:
				return errCfg("err_dup")
			}
		}
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM dns64_records WHERE origin = ? AND ref = ?`, OriginIPAM, ref); err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, w := range want {
		done := false
		for id := range claim {
			for _, h := range have {
				if h.id == id && h.typ == w.Type && h.value == w.Value {
					if _, err := tx.ExecContext(ctx, `UPDATE dns64_records SET origin = ?, ref = ?, no_ptr = ?, local_only = 0, enabled = 1 WHERE id = ?`,
						OriginIPAM, ref, w.NoPTR, id); err != nil {
						return err
					}
					done = true
				}
			}
		}
		if done {
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, comment, no_ptr, local_only, dynamic, enabled, created_at, origin, ref)
			VALUES (?,?,?,?,?,?,0,0,1,?,?,?)`, w.Name, w.Type, w.Value, w.TTL, "", w.NoPTR, now, OriginIPAM, ref); err != nil {
			if isUnique(err) {
				return errCfg("err_dup")
			}
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return m.loadRecords(ctx)
}

// DeleteIPAMRecords loescht die A/AAAA-Eintraege einer Adresse aus IPAM64 (keine = kein Fehler).
func (m *Module) DeleteIPAMRecords(ctx context.Context, ref string) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM dns64_records WHERE origin = ? AND ref = ?`, OriginIPAM, ref)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return m.loadRecords(ctx)
	}
	return nil
}

// ReleaseIPAM nimmt das Kennzeichen von den Eintraegen aus IPAM64 (ref "" = alle): sie bleiben und sind hier wieder
// normal bearbeitbar (Uebergabe an DNS64, z. B. beim Abschalten von IPAM64). Liefert die Zahl der Eintraege.
func (m *Module) ReleaseIPAM(ctx context.Context, ref string) (int64, error) {
	where, args := `origin = ?`, []any{OriginIPAM}
	if ref != "" {
		where, args = where+` AND ref = ?`, append(args, ref)
	}
	var total, dhcpN int64
	for _, t := range []string{"dns64_dhcp_reservations", "dns64_dhcp_excludes", "dns64_records"} {
		res, err := m.core.Writer().ExecContext(ctx, `UPDATE `+t+` SET origin = '', ref = '' WHERE `+where, args...)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if t != "dns64_records" {
			dhcpN += n
		}
	}
	if dhcpN > 0 {
		m.ipamDHCPChanged(ctx)
	}
	if total > dhcpN {
		return total, m.loadRecords(ctx)
	}
	return total, nil
}
