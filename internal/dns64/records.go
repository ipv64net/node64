package dns64

import (
	"context"
	"encoding/base64"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

// Eigene DNS-Eintraege (Tabelle dns64_records in node64.db, damit sie in Backup und Export sind). Der
// DNS-Dienst fragt eine unveraenderliche Momentaufnahme ab; Aenderungen gelten sofort, ohne Neustart und ohne
// den Cache zu leeren (eigene Eintraege kommen vor dem Cache).

// Record ist ein eigener Eintrag.
type Record struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`  // klein, ohne Punkt am Ende; "*.example.lan" = alle Unternamen
	Type      string    `json:"type"`  // A, AAAA, CNAME, TXT, MX, SRV, PTR, CAA
	Value     string    `json:"value"` // IP, Zielname, Text bzw. "10 mail.home.lan" (MX), "0 5 5060 sip.home.lan" (SRV), "0 issue letsencrypt.org" (CAA)
	TTL       int       `json:"ttl"`
	Comment   string    `json:"comment,omitempty"`
	NoPTR     bool      `json:"no_ptr,omitempty"`     // A/AAAA: keine Rueckwaertssuche aus diesem Eintrag
	LocalOnly bool      `json:"local_only,omitempty"` // nur diese Node (nie im Cluster abgeglichen)
	Dynamic   bool      `json:"dynamic,omitempty"`    // per dynamischem Update (RFC 2136) angelegt
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

var recordTypes = []string{"A", "AAAA", "CNAME", "TXT", "MX", "SRV", "PTR", "CAA"}

// recordTable ist die Momentaufnahme fuer den DNS-Dienst.
type recordTable struct {
	exact map[string][]Record
	wild  map[string][]Record // Schluessel: Name ohne "*."
	ptr   map[string]Record   // in-addr.arpa/ip6.arpa-Name -> A/AAAA-Eintrag
}

// Lookup beantwortet name/qtype aus den eigenen Eintraegen (dnsserver.Records). ok = Name bekannt.
func (m *Module) Lookup(name string, qtype uint16) ([]dns.RR, bool) {
	t := m.recs.Load()
	if t == nil {
		return nil, false
	}
	recs, ok := t.exact[name]
	if !ok {
		for s := name; !ok; {
			i := strings.IndexByte(s, '.')
			if i < 0 {
				break
			}
			s = s[i+1:]
			recs, ok = t.wild[s]
		}
	}
	if !ok {
		if r, isPtr := t.ptr[name]; isPtr && qtype == dns.TypePTR {
			return []dns.RR{&dns.PTR{Hdr: hdr(name, dns.TypePTR, r.TTL), Ptr: dns.Fqdn(r.Name)}}, true
		}
		return nil, false
	}
	var out []dns.RR
	for _, r := range recs {
		switch {
		case r.Type == "CNAME": // CNAME steht allein
			return []dns.RR{&dns.CNAME{Hdr: hdr(name, dns.TypeCNAME, r.TTL), Target: dns.Fqdn(r.Value)}}, true
		case dns.StringToType[r.Type] == qtype:
			if rr := recordRR(name, r); rr != nil {
				out = append(out, rr)
			}
		}
	}
	return out, true // leer = Name bekannt, aber kein Eintrag dieses Typs (NODATA, geht nicht ins Internet)
}

// recordRR baut die Antwort eines (geprueften) Eintrags fuer name.
func recordRR(name string, r Record) dns.RR {
	f := strings.Fields(r.Value)
	n := func(i int) uint16 { v, _ := strconv.ParseUint(f[i], 10, 16); return uint16(v) }
	h := hdr(name, dns.StringToType[r.Type], r.TTL)
	switch r.Type {
	case "A":
		return &dns.A{Hdr: h, A: netip.MustParseAddr(r.Value).AsSlice()}
	case "AAAA":
		return &dns.AAAA{Hdr: h, AAAA: netip.MustParseAddr(r.Value).AsSlice()}
	case "TXT":
		return &dns.TXT{Hdr: h, Txt: splitTXT(r.Value)}
	case "PTR":
		return &dns.PTR{Hdr: h, Ptr: dns.Fqdn(r.Value)}
	case "MX":
		return &dns.MX{Hdr: h, Preference: n(0), Mx: dns.Fqdn(f[1])}
	case "SRV":
		return &dns.SRV{Hdr: h, Priority: n(0), Weight: n(1), Port: n(2), Target: dns.Fqdn(f[3])}
	case "DHCID":
		return &dns.DHCID{Hdr: h, Digest: r.Value}
	case "CAA":
		flag, _ := strconv.ParseUint(f[0], 10, 8)
		return &dns.CAA{Hdr: h, Flag: uint8(flag), Tag: f[1], Value: strings.Join(f[2:], " ")}
	}
	return nil
}

// splitTXT teilt einen Text in Stuecke zu hoechstens 255 Bytes (Grenze je Zeichenkette im TXT-Eintrag).
func splitTXT(s string) []string {
	var out []string
	for len(s) > 255 {
		out, s = append(out, s[:255]), s[255:]
	}
	return append(out, s)
}

func hdr(name string, t uint16, ttl int) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: t, Class: dns.ClassINET, Ttl: uint32(ttl)}
}

// loadRecords baut die Momentaufnahme neu (nach jeder Aenderung und beim Start) und meldet Aenderungen an den Cluster.
func (m *Module) loadRecords(ctx context.Context) error {
	if err := m.buildRecords(ctx); err != nil {
		return err
	}
	m.clChanged(ctx, ItemRecords)
	return nil
}

// reloadRecordsSoon baut die Momentaufnahme kurz nach Uebernahmen aus dem Cluster neu (gebuendelt: beim Abgleich
// tausender Eintraege nicht je Eintrag).
func (m *Module) reloadRecordsSoon() {
	m.clMu.Lock()
	defer m.clMu.Unlock()
	if m.recReload != nil {
		return
	}
	m.recReload = time.AfterFunc(100*time.Millisecond, func() {
		m.clMu.Lock()
		m.recReload = nil
		m.clMu.Unlock()
		if err := m.buildRecords(context.Background()); err != nil {
			m.log.Warn("dns64 records after cluster sync", "err", err)
		}
	})
}

// buildRecords baut nur die Momentaufnahme fuer den DNS-Dienst.
func (m *Module) buildRecords(ctx context.Context) error {
	list, err := m.Records(ctx)
	if err != nil {
		return err
	}
	t := &recordTable{exact: map[string][]Record{}, wild: map[string][]Record{}, ptr: map[string]Record{}}
	for _, r := range list {
		if !r.Enabled {
			continue
		}
		if rest, ok := strings.CutPrefix(r.Name, "*."); ok {
			t.wild[rest] = append(t.wild[rest], r)
			continue
		}
		t.exact[r.Name] = append(t.exact[r.Name], r)
		if (r.Type == "A" || r.Type == "AAAA") && !r.NoPTR {
			if arpa, err := dns.ReverseAddr(r.Value); err == nil {
				if _, dup := t.ptr[strings.TrimSuffix(arpa, ".")]; !dup {
					t.ptr[strings.TrimSuffix(arpa, ".")] = r
				}
			}
		}
	}
	m.recs.Store(t)
	return nil
}

// Records liefert alle eigenen Eintraege, nach Name sortiert.
func (m *Module) Records(ctx context.Context) ([]Record, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, type, value, ttl, comment, no_ptr, local_only, dynamic, enabled, created_at FROM dns64_records ORDER BY name, type, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var created string
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Comment, &r.NoPTR, &r.LocalOnly, &r.Dynamic, &r.Enabled, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// normalizeRecord prueft einen Eintrag (Fehler mit i18n-Schluessel unter dns64.records.).
func normalizeRecord(r *Record) error {
	r.Name = strings.TrimSuffix(strings.ToLower(filter.ToASCII(strings.TrimSpace(r.Name))), ".") // IDN als Punycode
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)
	r.Comment = strings.TrimSpace(r.Comment)
	if len(r.Comment) > 200 {
		return errCfg("err_comment")
	}
	if r.Type == "PTR" { // Name darf die IP sein: 192.168.1.10 -> 10.1.168.192.in-addr.arpa
		if a, err := netip.ParseAddr(strings.Trim(r.Name, "[]")); err == nil {
			arpa, _ := dns.ReverseAddr(a.String())
			r.Name = strings.TrimSuffix(arpa, ".")
		}
	}
	if r.Type != "A" && r.Type != "AAAA" {
		r.NoPTR = false
	}
	if r.TTL == 0 {
		r.TTL = 300
	}
	if r.TTL < 1 || r.TTL > 86400 {
		return errCfg("err_ttl")
	}
	if !validName(strings.TrimPrefix(r.Name, "*.")) {
		return errCfg("err_name")
	}
	switch r.Type {
	case "A", "AAAA":
		a, err := netip.ParseAddr(strings.Trim(r.Value, "[]"))
		if err != nil || (r.Type == "A") != a.Is4() || a.Zone() != "" || a.Is4In6() { // Zone/::ffff: passen nicht in DNS
			return errCfg("err_ip_" + strings.ToLower(r.Type))
		}
		r.Value = a.String()
	case "CNAME", "PTR":
		r.Value = hostName(r.Value)
		if !validName(r.Value) || r.Value == r.Name {
			return errCfg("err_target")
		}
	case "TXT":
		if r.Value == "" || len(r.Value) > 2048 || strings.ContainsFunc(r.Value, func(c rune) bool { return c < ' ' || c == 0x7f }) {
			return errCfg("err_txt")
		}
	case "MX":
		f := strings.Fields(r.Value)
		if len(f) == 1 { // nur der Name: Vorrang 10
			f = []string{"10", f[0]}
		}
		if len(f) != 2 || !isUint(f[0], 16) || !validName(hostName(f[1])) {
			return errCfg("err_mx")
		}
		r.Value = num(f[0]) + " " + hostName(f[1])
	case "SRV":
		f := strings.Fields(r.Value)
		if len(f) != 4 || !isUint(f[0], 16) || !isUint(f[1], 16) || !isUint(f[2], 16) || !validName(hostName(f[3])) {
			return errCfg("err_srv")
		}
		r.Value = num(f[0]) + " " + num(f[1]) + " " + num(f[2]) + " " + hostName(f[3])
	case "DHCID": // Kennung des DHCP-Clients (RFC 4701), kommt nur per dynamischem Update
		if _, err := base64.StdEncoding.DecodeString(r.Value); err != nil || r.Value == "" {
			return errCfg("err_txt")
		}
	case "CAA":
		f := strings.Fields(strings.ReplaceAll(r.Value, `"`, " "))
		if len(f) == 2 { // ohne Flag: 0
			f = append([]string{"0"}, f...)
		}
		if len(f) < 3 || !isUint(f[0], 8) {
			return errCfg("err_caa")
		}
		tag := strings.ToLower(f[1])
		if tag != "issue" && tag != "issuewild" && tag != "iodef" {
			return errCfg("err_caa")
		}
		r.Value = num(f[0]) + " " + tag + " " + strings.Join(f[2:], " ")
	default:
		return errCfg("err_type")
	}
	return nil
}

// hostName: Zielname klein, als Punycode, ohne Punkt am Ende.
func hostName(s string) string {
	return strings.TrimSuffix(strings.ToLower(filter.ToASCII(strings.TrimSpace(s))), ".")
}

func isUint(s string, bits int) bool { _, err := strconv.ParseUint(s, 10, bits); return err == nil }

// num: Zahl ohne fuehrende Nullen.
func num(s string) string { v, _ := strconv.ParseUint(s, 10, 64); return strconv.FormatUint(v, 10) }

func validName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for _, c := range l {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// AddRecord legt einen Eintrag an. CNAME und andere Typen schliessen sich je Name aus.
func (m *Module) AddRecord(ctx context.Context, r Record) (Record, error) {
	if err := m.checkRecord(ctx, &r, 0); err != nil {
		return r, err
	}
	r.Enabled, r.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, comment, no_ptr, local_only, dynamic, enabled, created_at) VALUES (?,?,?,?,?,?,?,?,1,?)`,
		r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, r.LocalOnly, r.Dynamic, r.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, m.loadRecords(ctx)
}

// UpdateRecord aendert einen Eintrag (Name, Typ, Wert, TTL, Kommentar, PTR); an/aus bleibt.
func (m *Module) UpdateRecord(ctx context.Context, id int64, r Record) (Record, error) {
	if err := m.checkRecord(ctx, &r, id); err != nil {
		return r, err
	}
	r.ID = id
	if err := m.recordExec(ctx, `UPDATE dns64_records SET name = ?, type = ?, value = ?, ttl = ?, comment = ?, no_ptr = ?, local_only = ? WHERE id = ?`,
		r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, r.LocalOnly, id); err != nil {
		return r, err
	}
	list, err := m.Records(ctx) // gespeicherter Stand (an/aus, angelegt)
	for _, x := range list {
		if x.ID == id {
			return x, err
		}
	}
	return r, err
}

// checkRecord prueft einen Eintrag gegen die vorhandenen (ausser self): doppelt, CNAME neben anderen Typen.
func (m *Module) checkRecord(ctx context.Context, r *Record, self int64) error {
	if err := normalizeRecord(r); err != nil {
		return err
	}
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, type, value FROM dns64_records WHERE name = ?`, r.Name)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var typ, value string
		if err := rows.Scan(&id, &typ, &value); err != nil {
			return err
		}
		if id == self {
			continue
		}
		if typ == r.Type && value == r.Value {
			return errCfg("err_dup")
		}
		if typ == "CNAME" || r.Type == "CNAME" {
			return errCfg("err_cname")
		}
	}
	return rows.Err()
}

// DeleteRecord loescht einen Eintrag.
func (m *Module) DeleteRecord(ctx context.Context, id int64) error {
	return m.recordExec(ctx, `DELETE FROM dns64_records WHERE id = ?`, id)
}

// SetRecordEnabled schaltet einen Eintrag an oder aus.
func (m *Module) SetRecordEnabled(ctx context.Context, id int64, on bool) error {
	return m.recordExec(ctx, `UPDATE dns64_records SET enabled = ? WHERE id = ?`, on, id)
}

func (m *Module) recordExec(ctx context.Context, q string, args ...any) error {
	res, err := m.core.Writer().ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.loadRecords(ctx)
}
