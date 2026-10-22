package dns64

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Unterpunkt "Lokaler DNS" (/dns64/local): Zonen links, ihre Eintraege rechts, Zonendatei (BIND-Format) je Zone.

// zoneOfName: die laengste Zone, zu der name gehoert ("" = keine).
func zoneOfName(zones []Zone, name string) string {
	best := ""
	name = strings.TrimPrefix(name, "*.")
	for _, z := range zones {
		if (name == z.Name || strings.HasSuffix(name, "."+z.Name)) && len(z.Name) > len(best) {
			best = z.Name
		}
	}
	return best
}

// localView fuellt die Seite: Zonen mit Zaehlern, gewaehlte Zone (?zone=, sonst die erste), ihre Eintraege.
func (m *Module) localView(r *http.Request, d *pageData) error {
	ctx := r.Context()
	recs, err := m.Records(ctx)
	if err != nil {
		return err
	}
	if d.Zones, err = m.Zones(ctx); err != nil {
		return err
	}
	d.DNames = m.DeviceNames()
	d.ZCount = map[string]int{"*": len(recs)}
	of := make([]string, len(recs))
	for i, x := range recs {
		z := zoneOfName(d.Zones, x.Name)
		if z == "" {
			z = "-"
		}
		of[i] = z
		d.ZCount[z]++
	}
	d.Sel = r.URL.Query().Get("zone")
	if d.Sel == "" {
		d.Sel = "*"
		if len(d.Zones) > 0 {
			d.Sel = d.Zones[0].Name
		}
	}
	for i := range d.Zones {
		if d.Zones[i].Name == d.Sel {
			d.SelZone = &d.Zones[i]
		}
	}
	if d.SelZone == nil && d.Sel != "-" {
		d.Sel = "*"
	}
	d.Records = []Record{}
	for i, x := range recs {
		if d.Sel == "*" || of[i] == d.Sel {
			d.Records = append(d.Records, x)
		}
	}
	d.Back = "/dns64/local?zone=" + d.Sel
	return nil
}

// ---- Zonendatei (BIND-Format) ----

// zoneFile schreibt eine Zone mit ihren Eintraegen im BIND-Format ($ORIGIN, $TTL, SOA, NS, relative Namen).
func (m *Module) zoneFile(ctx context.Context, z Zone) ([]byte, error) {
	recs, err := m.Records(ctx)
	if err != nil {
		return nil, err
	}
	zones, err := m.Zones(ctx)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "; Node64 DNS64 – Zone %s (%s)\n$ORIGIN %s\n$TTL %d\n", z.Name, time.Now().UTC().Format(time.RFC3339), dns.Fqdn(z.Name), z.TTL)
	soa := zoneSOA(z, uint32(time.Now().Unix()))
	fmt.Fprintf(&b, "@\tIN\tSOA\t%s %s %d %d %d %d %d\n@\tIN\tNS\t%s\n", soa.Ns, soa.Mbox, soa.Serial, soa.Refresh, soa.Retry, soa.Expire, soa.Minttl, soa.Ns)
	for _, r := range recs {
		if !r.Enabled || zoneOfName(zones, r.Name) != z.Name {
			continue
		}
		rr := recordRR(r.Name, r)
		if r.Type == "CNAME" {
			rr = &dns.CNAME{Hdr: hdr(r.Name, dns.TypeCNAME, r.TTL), Target: dns.Fqdn(r.Value)}
		}
		if rr == nil {
			continue
		}
		line := rr.String() // name TTL IN TYP Wert
		owner := relName(r.Name, z.Name)
		if i := strings.IndexByte(line, '\t'); i > 0 {
			line = owner + line[i:]
		}
		if r.Comment != "" {
			line += " ; " + strings.ReplaceAll(r.Comment, "\n", " ")
		}
		b.WriteString(line + "\n")
	}
	return b.Bytes(), nil
}

// relName: name relativ zur Zone ("@" = die Zone selbst).
func relName(name, zone string) string {
	if name == zone {
		return "@"
	}
	return strings.TrimSuffix(name, "."+zone)
}

// isZoneFile: der Text sieht nach einer Zonendatei aus ($ORIGIN/$TTL oder "name [TTL] IN TYP …").
func isZoneFile(text string) bool {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "$ORIGIN") || strings.HasPrefix(line, "$TTL") {
			return true
		}
		f := strings.Fields(line)
		return slices.Contains(f, "IN") && len(f) >= 4
	}
	return false
}

// parseZoneFile liest Eintraege aus einer Zonendatei (origin: Zone fuer relative Namen ohne $ORIGIN). SOA und NS
// der Zone selbst uebernimmt DNS64 nicht als Eintrag (soa liefert die Werte); andere Typen zaehlen als uebersprungen.
func parseZoneFile(text, origin string) (list []Record, soa *dns.SOA, skipped, bad int) {
	zp := dns.NewZoneParser(strings.NewReader(text), dns.Fqdn(origin), "")
	zp.SetDefaultTTL(300)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		h := rr.Header()
		name := strings.TrimSuffix(strings.ToLower(h.Name), ".")
		ttl := int(h.Ttl)
		var typ, value string
		switch x := rr.(type) {
		case *dns.SOA:
			soa = x
			continue
		case *dns.NS:
			skipped++
			continue
		case *dns.A:
			typ, value = "A", x.A.String()
		case *dns.AAAA:
			typ, value = "AAAA", x.AAAA.String()
		case *dns.CNAME:
			typ, value = "CNAME", x.Target
		case *dns.PTR:
			typ, value = "PTR", x.Ptr
		case *dns.TXT:
			typ, value = "TXT", strings.Join(x.Txt, "")
		case *dns.MX:
			typ, value = "MX", strconv.Itoa(int(x.Preference))+" "+x.Mx
		case *dns.SRV:
			typ, value = "SRV", fmt.Sprintf("%d %d %d %s", x.Priority, x.Weight, x.Port, x.Target)
		case *dns.CAA:
			typ, value = "CAA", fmt.Sprintf("%d %s %s", x.Flag, x.Tag, x.Value)
		default:
			skipped++
			continue
		}
		list = append(list, Record{Name: name, Type: typ, Value: value, TTL: ttl})
	}
	if zp.Err() != nil {
		bad++
	}
	return list, soa, skipped, bad
}

// importZoneFile legt die Eintraege einer Zonendatei an; gibt es die Zone hier, uebernimmt sie die SOA-Werte.
func (m *Module) importZoneFile(ctx context.Context, text, zone string) (importResult, error) {
	list, soa, skipped, bad := parseZoneFile(text, zone)
	res := importResult{Skipped: skipped, Invalid: bad}
	if soa != nil {
		name := strings.TrimSuffix(strings.ToLower(soa.Hdr.Name), ".")
		zones, err := m.Zones(ctx)
		if err != nil {
			return res, err
		}
		for _, z := range zones {
			if z.Name == name {
				z.Refresh, z.Retry, z.Expire, z.Minimum = int(soa.Refresh), int(soa.Retry), int(soa.Expire), int(soa.Minttl)
				if _, err := m.UpdateZone(ctx, z.ID, z); err != nil {
					res.Invalid++
				}
			}
		}
	}
	return res, m.addBatch(ctx, list, &res)
}

func (m *Module) pageZoneFile(w http.ResponseWriter, r *http.Request) {
	zones, err := m.Zones(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	for _, z := range zones {
		if z.ID == pathID(r) {
			body, err := m.zoneFile(r.Context(), z)
			if err != nil {
				m.fail(w, err)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Content-Disposition", `attachment; filename="`+z.Name+`.zone"`)
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write(body)
			return
		}
	}
	http.NotFound(w, r)
}
