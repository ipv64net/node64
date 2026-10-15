package cdn64

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ipv64api"
)

// DNS-Eintrag bei ipv64 beim Anlegen eines Hosts: fuer jeden Namen, der in einer ipv64-Domain des Accounts liegt,
// ein CNAME (z. B. auf die DynDNS-Domain, deren IP der Updater aktuell haelt) oder ein A/AAAA-Record. Vorhandene
// Eintraege werden nie ueberschrieben.

// Record ist ein DNS-Record bei ipv64 (Ausschnitt).
type Record struct {
	Prefix  string
	Type    string
	Content string
}

// DNSRecords ist der Zugriff auf die DNS-Records des ipv64-Accounts.
type DNSRecords interface {
	Ready(ctx context.Context) bool
	Domains(ctx context.Context) ([]string, error)
	Records(ctx context.Context, domain string) ([]Record, error)
	Add(ctx context.Context, domain, typ, prefix, content string) error
}

// IPv64Records ist DNSRecords ueber den zentralen API-Key.
func IPv64Records(k *ipv64api.Key) DNSRecords { return ipv64Records{k} }

type ipv64Records struct{ k *ipv64api.Key }

func (r ipv64Records) Ready(ctx context.Context) bool { return r.k != nil && r.k.Get(ctx) != "" }

func (r ipv64Records) Domains(ctx context.Context) ([]string, error) {
	list, err := r.k.Client().Domains(ctx, r.k.Get(ctx))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(list))
	for _, d := range list {
		out = append(out, strings.ToLower(d.Name))
	}
	return out, nil
}

func (r ipv64Records) Records(ctx context.Context, domain string) ([]Record, error) {
	list, err := r.k.Client().Records(ctx, r.k.Get(ctx), domain)
	if err != nil {
		return nil, err
	}
	out := make([]Record, 0, len(list))
	for _, x := range list {
		out = append(out, Record{Prefix: strings.ToLower(x.Prefix), Type: strings.ToUpper(x.Type), Content: x.Content})
	}
	return out, nil
}

func (r ipv64Records) Add(ctx context.Context, domain, typ, prefix, content string) error {
	_, err := r.k.Client().AddRecord(ctx, r.k.Get(ctx), domain, typ, prefix, content)
	return err
}

// SetDNSRecords haengt den Zugriff auf die ipv64-Records an (nil = Funktion nicht verfuegbar).
func (m *Module) SetDNSRecords(d DNSRecords) { m.dnsrec = d }

// DNSRequest: welcher Eintrag angelegt werden soll.
type DNSRequest struct {
	Type    string `json:"type"`    // CNAME, A oder AAAA
	Content string `json:"content"` // Ziel-Domain bzw. IP
}

// DNSResult ist das Ergebnis fuer einen Namen.
type DNSResult struct {
	Name   string `json:"name"`
	Result string `json:"result"` // created, exists, not_ipv64, apex_cname, error
	Error  string `json:"error,omitempty"`
}

func (q *DNSRequest) normalize() error {
	q.Type = strings.ToUpper(strings.TrimSpace(q.Type))
	q.Content = strings.TrimSpace(q.Content)
	switch q.Type {
	case "CNAME":
		n, err := edge.NormalizeName(q.Content)
		if err != nil || strings.HasPrefix(n, "*") {
			return ferr("dns_content", "cdn64.err.dns_content")
		}
		q.Content = n
	case "A", "AAAA":
		a, err := netip.ParseAddr(q.Content)
		if err != nil || (q.Type == "A") != a.Is4() {
			return ferr("dns_content", "cdn64.err.dns_content")
		}
		q.Content = a.String()
	default:
		return ferr("dns_type", "cdn64.err.dns_type")
	}
	return nil
}

// createRecords legt fuer die Namen eines Hosts die Records an (vorhandene bleiben unberuehrt).
func (m *Module) createRecords(ctx context.Context, names []string, q DNSRequest) ([]DNSResult, error) {
	if m.dnsrec == nil || !m.dnsrec.Ready(ctx) {
		return nil, errors.New("no ipv64 API key")
	}
	if err := q.normalize(); err != nil {
		return nil, err
	}
	domains, err := m.dnsrec.Domains(ctx)
	if err != nil {
		return nil, fmt.Errorf("ipv64 domains: %w", err)
	}
	cache := map[string][]Record{}
	var out []DNSResult
	for _, n := range names {
		zone := ""
		base := strings.TrimPrefix(n, "*.")
		for _, d := range domains {
			if (base == d || strings.HasSuffix(base, "."+d)) && len(d) > len(zone) {
				zone = d
			}
		}
		if zone == "" {
			out = append(out, DNSResult{Name: n, Result: "not_ipv64"})
			continue
		}
		prefix := strings.TrimSuffix(strings.TrimSuffix(n, zone), ".")
		if prefix == "" && q.Type == "CNAME" {
			out = append(out, DNSResult{Name: n, Result: "apex_cname"})
			continue
		}
		if q.Type == "CNAME" && q.Content == n {
			out = append(out, DNSResult{Name: n, Result: "error", Error: "cname to itself"})
			continue
		}
		recs, ok := cache[zone]
		if !ok {
			if recs, err = m.dnsrec.Records(ctx, zone); err != nil {
				out = append(out, DNSResult{Name: n, Result: "error", Error: err.Error()})
				continue
			}
			cache[zone] = recs
		}
		exists := false
		for _, r := range recs {
			if r.Prefix == prefix && (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME") {
				exists = true
			}
		}
		if exists {
			out = append(out, DNSResult{Name: n, Result: "exists"})
			continue
		}
		if err := m.dnsrec.Add(ctx, zone, q.Type, prefix, q.Content); err != nil {
			out = append(out, DNSResult{Name: n, Result: "error", Error: err.Error()})
			continue
		}
		cache[zone] = append(cache[zone], Record{Prefix: prefix, Type: q.Type, Content: q.Content})
		out = append(out, DNSResult{Name: n, Result: "created"})
	}
	return out, nil
}

// dnsSummary: kurze Zusammenfassung fuer Meldung und Audit.
func dnsSummary(res []DNSResult) (created int, text string) {
	var parts []string
	for _, r := range res {
		if r.Result == "created" {
			created++
		}
		s := r.Name + "=" + r.Result
		if r.Error != "" {
			s += "(" + r.Error + ")"
		}
		parts = append(parts, s)
	}
	return created, strings.Join(parts, ", ")
}
