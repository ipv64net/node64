package dns64

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Eigene DNS-Eintraege (Tabelle dns64_records in node64.db, damit sie in Backup und Export sind). Der
// DNS-Dienst fragt eine unveraenderliche Momentaufnahme ab; Aenderungen gelten sofort, ohne Neustart und ohne
// den Cache zu leeren (eigene Eintraege kommen vor dem Cache).

// Record ist ein eigener Eintrag.
type Record struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`  // klein, ohne Punkt am Ende; "*.example.lan" = alle Unternamen
	Type      string    `json:"type"`  // A, AAAA, CNAME
	Value     string    `json:"value"` // IP bzw. Zielname
	TTL       int       `json:"ttl"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

var recordTypes = []string{"A", "AAAA", "CNAME"}

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
		case r.Type == "A" && qtype == dns.TypeA:
			out = append(out, &dns.A{Hdr: hdr(name, dns.TypeA, r.TTL), A: netip.MustParseAddr(r.Value).AsSlice()})
		case r.Type == "AAAA" && qtype == dns.TypeAAAA:
			out = append(out, &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA, r.TTL), AAAA: netip.MustParseAddr(r.Value).AsSlice()})
		}
	}
	return out, true // leer = Name bekannt, aber kein Eintrag dieses Typs (NODATA, geht nicht ins Internet)
}

func hdr(name string, t uint16, ttl int) dns.RR_Header {
	return dns.RR_Header{Name: dns.Fqdn(name), Rrtype: t, Class: dns.ClassINET, Ttl: uint32(ttl)}
}

// loadRecords baut die Momentaufnahme neu (nach jeder Aenderung und beim Start).
func (m *Module) loadRecords(ctx context.Context) error {
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
		if r.Type == "A" || r.Type == "AAAA" {
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
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, type, value, ttl, enabled, created_at FROM dns64_records ORDER BY name, type, value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var created string
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Enabled, &created); err != nil {
			return nil, err
		}
		r.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, r)
	}
	return out, rows.Err()
}

// normalizeRecord prueft einen Eintrag (Fehler mit i18n-Schluessel unter dns64.records.).
func normalizeRecord(r *Record) error {
	r.Name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(r.Name)), ".")
	r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
	r.Value = strings.TrimSpace(r.Value)
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
		if err != nil || (r.Type == "A") != a.Is4() {
			return errCfg("err_ip_" + strings.ToLower(r.Type))
		}
		r.Value = a.String()
	case "CNAME":
		r.Value = strings.TrimSuffix(strings.ToLower(r.Value), ".")
		if !validName(r.Value) || r.Value == r.Name {
			return errCfg("err_target")
		}
	default:
		return errCfg("err_type")
	}
	return nil
}

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
	if err := normalizeRecord(&r); err != nil {
		return r, err
	}
	list, err := m.Records(ctx)
	if err != nil {
		return r, err
	}
	for _, x := range list {
		if x.Name != r.Name {
			continue
		}
		if x.Type == r.Type && x.Value == r.Value {
			return r, errCfg("err_dup")
		}
		if x.Type == "CNAME" || r.Type == "CNAME" {
			return r, errCfg("err_cname")
		}
	}
	r.Enabled, r.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, enabled, created_at) VALUES (?,?,?,?,1,?)`,
		r.Name, r.Type, r.Value, r.TTL, r.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return r, err
	}
	r.ID, _ = res.LastInsertId()
	return r, m.loadRecords(ctx)
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
