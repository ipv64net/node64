package dns64

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Dynamische Updates (RFC 2136) mit TSIG: DHCP-Server wie pfSense/OPNsense (ISC), Kea oder nsupdate tragen Namen
// selbst ein. Je Zone einschaltbar, Schluessel (HMAC-SHA256) erzeugt die Node. Unterstuetzt: Vorbedingungen
// (Name/RRset vorhanden oder nicht, RRset mit genau diesen Werten) und Aenderungen (hinzufuegen, RRset bzw. Name
// bzw. einzelnen Eintrag loeschen) fuer A, AAAA, CNAME, TXT, PTR, SRV, MX und DHCID. Alles oder nichts.

var updateTypes = map[uint16]bool{dns.TypeA: true, dns.TypeAAAA: true, dns.TypeCNAME: true, dns.TypeTXT: true, dns.TypePTR: true,
	dns.TypeSRV: true, dns.TypeMX: true, dns.TypeDHCID: true}

// TSIGSecret: Schluessel einer Zone mit dynamischen Updates (dnsserver.Updater).
func (m *Module) TSIGSecret(name string) (string, bool) {
	t := m.zns.Load()
	if t == nil {
		return "", false
	}
	for _, z := range t.byName {
		if z.Dynamic && z.TSIGName == name && z.TSIGSecret != "" {
			return z.TSIGSecret, true
		}
	}
	return "", false
}

// rrRecord: Eintrag zu einem RR eines Updates (Name und Wert wie bei eigenen Eintraegen vereinheitlicht).
func rrRecord(rr dns.RR) (Record, bool) {
	h := rr.Header()
	r := Record{Name: strings.TrimSuffix(strings.ToLower(h.Name), "."), TTL: int(h.Ttl)}
	switch x := rr.(type) {
	case *dns.A:
		r.Type, r.Value = "A", x.A.String()
	case *dns.AAAA:
		r.Type, r.Value = "AAAA", x.AAAA.String()
	case *dns.CNAME:
		r.Type, r.Value = "CNAME", x.Target
	case *dns.PTR:
		r.Type, r.Value = "PTR", x.Ptr
	case *dns.TXT:
		r.Type, r.Value = "TXT", strings.Join(x.Txt, "")
	case *dns.MX:
		r.Type, r.Value = "MX", strconv.Itoa(int(x.Preference))+" "+x.Mx
	case *dns.SRV:
		r.Type, r.Value = "SRV", fmt.Sprintf("%d %d %d %s", x.Priority, x.Weight, x.Port, x.Target)
	case *dns.DHCID:
		r.Type, r.Value = "DHCID", x.Digest
	default:
		return r, false
	}
	if r.TTL < 1 {
		r.TTL = 300
	}
	return r, normalizeRecord(&r) == nil
}

// Update wendet ein geprueftes Update auf zone an (dnsserver.Updater).
func (m *Module) Update(zone, key string, msg *dns.Msg) int {
	m.updMu.Lock()
	defer m.updMu.Unlock()
	ctx := context.Background()
	t := m.zns.Load()
	if t == nil {
		return dns.RcodeNotAuth
	}
	z, ok := t.byName[zone]
	if !ok {
		return dns.RcodeNotAuth // keine (eingeschaltete) Zone hier
	}
	if !z.Dynamic || z.TSIGName != key {
		return dns.RcodeRefused
	}
	in := func(name string) bool { return name == zone || strings.HasSuffix(name, "."+zone) }
	recs, err := m.Records(ctx)
	if err != nil {
		return dns.RcodeServerFailure
	}
	// Vorbedingungen (RFC 2136 3.2)
	type rrset struct{ name, typ string }
	want := map[rrset][]string{} // Klasse IN: RRset muss genau diese Werte haben
	for _, rr := range msg.Answer {
		h := rr.Header()
		name := strings.TrimSuffix(strings.ToLower(h.Name), ".")
		if !in(name) {
			return dns.RcodeNotZone
		}
		typ := dns.TypeToString[h.Rrtype]
		exists := func(typ string) bool {
			for _, r := range recs {
				if r.Name == name && r.Enabled && (typ == "ANY" || r.Type == typ) {
					return true
				}
			}
			return false
		}
		switch h.Class {
		case dns.ClassANY:
			if !exists(typ) {
				if h.Rrtype == dns.TypeANY {
					return dns.RcodeNameError
				}
				return dns.RcodeNXRrset
			}
		case dns.ClassNONE:
			if exists(typ) {
				if h.Rrtype == dns.TypeANY {
					return dns.RcodeYXDomain
				}
				return dns.RcodeYXRrset
			}
		case dns.ClassINET:
			r, ok := rrRecord(rr)
			if !ok {
				return dns.RcodeFormatError
			}
			want[rrset{name, r.Type}] = append(want[rrset{name, r.Type}], r.Value)
		default:
			return dns.RcodeFormatError
		}
	}
	for k, vals := range want {
		var have []string
		for _, r := range recs {
			if r.Name == k.name && r.Type == k.typ && r.Enabled {
				have = append(have, r.Value)
			}
		}
		if !sameSet(have, vals) {
			return dns.RcodeNXRrset
		}
	}
	// Aenderungen pruefen, dann anwenden (RFC 2136 3.4)
	for _, rr := range msg.Ns {
		h := rr.Header()
		name := strings.TrimSuffix(strings.ToLower(h.Name), ".")
		if !in(name) {
			return dns.RcodeNotZone
		}
		if h.Rrtype != dns.TypeANY && !updateTypes[h.Rrtype] {
			return dns.RcodeRefused // SOA, NS und andere Typen nicht per Update
		}
		switch h.Class { // alles pruefen, bevor etwas geschrieben wird (sonst halb angewendet)
		case dns.ClassINET, dns.ClassNONE:
			if _, ok := rrRecord(rr); !ok {
				return dns.RcodeFormatError
			}
		case dns.ClassANY:
		default:
			return dns.RcodeFormatError
		}
	}
	// alle Aenderungen in einer Transaktion: klappt eine nicht, bleibt alles beim Alten
	w, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		m.log.Warn("dns update", "zone", zone, "err", err)
		return dns.RcodeServerFailure
	}
	defer w.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, rr := range msg.Ns {
		h := rr.Header()
		name := strings.TrimSuffix(strings.ToLower(h.Name), ".")
		typ := dns.TypeToString[h.Rrtype]
		var err error
		switch h.Class {
		case dns.ClassINET: // hinzufuegen (gleicher Eintrag: nur TTL), CNAME ersetzt nichts anderes
			r, ok := rrRecord(rr)
			if !ok {
				return dns.RcodeFormatError
			}
			var conflict int
			_ = w.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns64_records WHERE name = ? AND ((type = 'CNAME') != (? = 'CNAME'))`, r.Name, r.Type).Scan(&conflict)
			if conflict > 0 {
				continue // RFC 2136: CNAME neben anderen Typen wird still ignoriert
			}
			if r.Type == "CNAME" {
				_, err = w.ExecContext(ctx, `DELETE FROM dns64_records WHERE name = ? AND type = 'CNAME' AND local_only = 0`, r.Name)
			}
			if err == nil {
				_, err = w.ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, dynamic, enabled, created_at) VALUES (?,?,?,?,1,1,?)
					ON CONFLICT (name, type, value) DO UPDATE SET ttl = excluded.ttl, enabled = 1`, r.Name, r.Type, r.Value, r.TTL, now)
			}
		case dns.ClassANY: // RRset bzw. alle des Namens loeschen
			if h.Rrtype == dns.TypeANY {
				_, err = w.ExecContext(ctx, `DELETE FROM dns64_records WHERE name = ? AND local_only = 0`, name)
			} else {
				_, err = w.ExecContext(ctx, `DELETE FROM dns64_records WHERE name = ? AND type = ? AND local_only = 0`, name, typ)
			}
		case dns.ClassNONE: // einzelnen Eintrag loeschen
			r, ok := rrRecord(rr)
			if !ok {
				return dns.RcodeFormatError
			}
			_, err = w.ExecContext(ctx, `DELETE FROM dns64_records WHERE name = ? AND type = ? AND value = ? AND local_only = 0`, r.Name, r.Type, r.Value)
		default:
			return dns.RcodeFormatError
		}
		if err != nil {
			m.log.Warn("dns update", "zone", zone, "err", err)
			return dns.RcodeServerFailure
		}
	}
	if err := w.Commit(); err != nil {
		m.log.Warn("dns update", "zone", zone, "err", err)
		return dns.RcodeServerFailure
	}
	if err := m.loadRecords(ctx); err != nil {
		return dns.RcodeServerFailure
	}
	return dns.RcodeSuccess
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, x := range a {
		seen[x]++
	}
	for _, x := range b {
		if seen[x]--; seen[x] < 0 {
			return false
		}
	}
	return true
}

// SetZoneDynamic schaltet dynamische Updates einer Zone; beim ersten Einschalten (oder renew) gibt es einen neuen
// Schluessel (32 Byte, HMAC-SHA256, Name node64-<zone>).
func (m *Module) SetZoneDynamic(ctx context.Context, id int64, on, renew bool) error {
	zones, err := m.Zones(ctx)
	if err != nil {
		return err
	}
	for _, z := range zones {
		if z.ID != id {
			continue
		}
		name, secret := z.TSIGName, z.TSIGSecret
		if renew || secret == "" {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			name, secret = "node64-"+z.Name, base64.StdEncoding.EncodeToString(b)
		}
		return m.zoneExec(ctx, `UPDATE dns64_zones SET dynamic = ?, tsig_name = ?, tsig_secret = ? WHERE id = ?`, on, name, secret, id)
	}
	return errNotFound
}
