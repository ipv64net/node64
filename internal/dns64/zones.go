package dns64

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

// Lokale Zonen (Tabelle dns64_zones): Namen unter einer Zone wie home.lan beantwortet DNS64 selbst. Die eigenen
// Eintraege gehen vor; dazu kommen auf Wunsch die Geraete der Gruppen mit Namen als <name>.<zone> (IP aus der
// Nachbartabelle, auch Rueckwaertssuche), SOA/NS der Zone und fuer unbekannte Namen NXDOMAIN ("zustaendig") bzw.
// der Weg ueber Weiterleitung und Router (nicht zustaendig).

// Zone ist eine lokale Zone.
type Zone struct {
	ID            int64     `json:"id"`
	Name          string    `json:"name"`
	Authoritative bool      `json:"authoritative"` // unbekannte Namen: NXDOMAIN (sonst weiter an Weiterleitung/Router)
	Devices       bool      `json:"devices"`       // Geraete der Gruppen mit Namen als <name>.<zone>
	Comment       string    `json:"comment,omitempty"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
}

type zoneTable struct {
	byName map[string]Zone
	serial uint32
}

// devTable: Geraetenamen (aus den Bezeichnungen der Gruppen-Mitglieder mit MAC oder IP).
type devTable map[string][]groups.Member

const zoneTTL = 60

// deviceSlug macht aus einer Bezeichnung einen DNS-Namen: "Tablet Lea" -> tablet-lea, Umlaute als ae/oe/ue/ss.
func deviceSlug(label string) string {
	r := strings.NewReplacer("ä", "ae", "ö", "oe", "ü", "ue", "ß", "ss", "Ä", "ae", "Ö", "oe", "Ü", "ue")
	s := strings.ToLower(r.Replace(strings.TrimSpace(label)))
	var b strings.Builder
	dash := false
	for _, c := range s {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			b.WriteRune(c)
			dash = false
		} else if !dash && b.Len() > 0 {
			b.WriteByte('-')
			dash = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if len(out) > 63 {
		out = strings.TrimRight(out[:63], "-")
	}
	return out
}

// buildDeviceNames merkt sich die Geraete mit Namen (nach jeder Aenderung der Gruppen).
func (m *Module) buildDeviceNames(list []groups.Group) {
	t := devTable{}
	for _, g := range list {
		for _, x := range g.Members {
			if x.Kind == groups.KindNet {
				continue
			}
			if s := deviceSlug(x.Label); s != "" {
				t[s] = append(t[s], x)
			}
		}
	}
	m.devs.Store(&t)
}

// deviceIPs: aktuelle Adressen eines Geraetenamens (MAC ueber die Nachbartabelle).
func (m *Module) deviceIPs(slug string) []netip.Addr {
	t := m.devs.Load()
	if t == nil {
		return nil
	}
	var out []netip.Addr
	for _, x := range (*t)[slug] {
		switch x.Kind {
		case groups.KindMAC:
			out = append(out, m.grp.IPs(x.Value)...)
		case groups.KindIP:
			if a, err := netip.ParseAddr(x.Value); err == nil {
				out = append(out, a)
			}
		}
	}
	return out
}

// deviceFor: Geraetename zu einer Adresse (Rueckwaertssuche), "" = keiner.
func (m *Module) deviceFor(ip netip.Addr) string {
	t := m.devs.Load()
	if t == nil {
		return ""
	}
	mac := m.grp.MAC(ip)
	best := ""
	for slug, list := range *t {
		for _, x := range list {
			if (x.Kind == groups.KindMAC && mac != "" && x.Value == mac) || (x.Kind == groups.KindIP && x.Value == ip.String()) {
				if best == "" || slug < best { // stabil bei mehreren Namen
					best = slug
				}
			}
		}
	}
	return best
}

// zoneFor: die laengste Zone, zu der name gehoert.
func (t *zoneTable) zoneFor(name string) (Zone, bool) {
	for s := name; ; {
		if z, ok := t.byName[s]; ok {
			return z, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return Zone{}, false
		}
		s = s[i+1:]
	}
}

func (t *zoneTable) soa(z Zone) dns.RR {
	return &dns.SOA{Hdr: hdr(z.Name, dns.TypeSOA, zoneTTL), Ns: dns.Fqdn("ns." + z.Name), Mbox: dns.Fqdn("hostmaster." + z.Name),
		Serial: t.serial, Refresh: 3600, Retry: 600, Expire: 86400, Minttl: zoneTTL}
}

// zoneAnswer beantwortet Namen lokaler Zonen (dnsserver.ZoneFunc); ok=false: weiter wie bisher.
func (m *Module) zoneAnswer(name string, qtype uint16) (ans, ns []dns.RR, rcode int, ok bool) {
	t := m.zns.Load()
	if t == nil || len(t.byName) == 0 {
		return nil, nil, 0, false
	}
	if qtype == dns.TypePTR { // Rueckwaertssuche fuer Geraete mit Namen
		if ip, isArpa := arpaAddr(name); isArpa {
			if slug := m.deviceFor(ip); slug != "" {
				for _, z := range t.byName {
					if z.Devices {
						return []dns.RR{&dns.PTR{Hdr: hdr(name, dns.TypePTR, zoneTTL), Ptr: dns.Fqdn(slug + "." + z.Name)}}, nil, dns.RcodeSuccess, true
					}
				}
			}
		}
		return nil, nil, 0, false
	}
	z, found := t.zoneFor(name)
	if !found {
		return nil, nil, 0, false
	}
	soa := []dns.RR{t.soa(z)}
	if name == z.Name {
		switch qtype {
		case dns.TypeSOA:
			return soa, nil, dns.RcodeSuccess, true
		case dns.TypeNS:
			return []dns.RR{&dns.NS{Hdr: hdr(z.Name, dns.TypeNS, zoneTTL), Ns: dns.Fqdn("ns." + z.Name)}}, nil, dns.RcodeSuccess, true
		}
		return nil, soa, dns.RcodeSuccess, true // Zone selbst: NODATA
	}
	if z.Devices {
		if label, rest, _ := strings.Cut(name, "."); rest == z.Name {
			if ips := m.deviceIPs(label); len(ips) > 0 {
				for _, ip := range ips {
					switch {
					case qtype == dns.TypeA && ip.Is4():
						ans = append(ans, &dns.A{Hdr: hdr(name, dns.TypeA, zoneTTL), A: ip.AsSlice()})
					case qtype == dns.TypeAAAA && ip.Is6():
						ans = append(ans, &dns.AAAA{Hdr: hdr(name, dns.TypeAAAA, zoneTTL), AAAA: ip.AsSlice()})
					}
				}
				if len(ans) == 0 {
					return nil, soa, dns.RcodeSuccess, true // Geraet bekannt, kein Eintrag dieses Typs
				}
				return ans, nil, dns.RcodeSuccess, true
			}
		}
	}
	if z.Authoritative {
		return nil, soa, dns.RcodeNameError, true
	}
	return nil, nil, 0, false
}

// arpaAddr: in-addr.arpa/ip6.arpa-Name -> Adresse.
func arpaAddr(name string) (netip.Addr, bool) {
	if v4, ok := strings.CutSuffix(name, ".in-addr.arpa"); ok {
		p := strings.Split(v4, ".")
		if len(p) != 4 {
			return netip.Addr{}, false
		}
		a, err := netip.ParseAddr(p[3] + "." + p[2] + "." + p[1] + "." + p[0])
		return a, err == nil
	}
	if v6, ok := strings.CutSuffix(name, ".ip6.arpa"); ok {
		p := strings.Split(v6, ".")
		if len(p) != 32 {
			return netip.Addr{}, false
		}
		var b strings.Builder
		for i := 31; i >= 0; i-- {
			b.WriteString(p[i])
			if i%4 == 0 && i > 0 {
				b.WriteByte(':')
			}
		}
		a, err := netip.ParseAddr(b.String())
		return a, err == nil
	}
	return netip.Addr{}, false
}

// loadZones baut die Momentaufnahme der Zonen neu.
func (m *Module) loadZones(ctx context.Context) error {
	list, err := m.Zones(ctx)
	if err != nil && !m.noTable(err) {
		return err
	}
	t := &zoneTable{byName: map[string]Zone{}, serial: uint32(time.Now().Unix())}
	for _, z := range list {
		if z.Enabled {
			t.byName[z.Name] = z
		}
	}
	m.zns.Store(t)
	return nil
}

// Zones liefert alle Zonen, nach Name sortiert.
func (m *Module) Zones(ctx context.Context) ([]Zone, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT id, name, authoritative, devices, comment, enabled, created_at FROM dns64_zones ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Zone{}
	for rows.Next() {
		var z Zone
		var created string
		if err := rows.Scan(&z.ID, &z.Name, &z.Authoritative, &z.Devices, &z.Comment, &z.Enabled, &created); err != nil {
			return nil, err
		}
		z.CreatedAt, _ = time.Parse(time.RFC3339, created)
		out = append(out, z)
	}
	return out, rows.Err()
}

func normalizeZone(z *Zone) error {
	z.Name = strings.TrimPrefix(hostName(z.Name), "*.")
	if !validName(z.Name) || strings.HasSuffix(z.Name, ".arpa") || z.Name == "arpa" {
		return errCfg("err_zone_name")
	}
	z.Comment = strings.TrimSpace(z.Comment)
	if len(z.Comment) > 200 {
		return errCfg("err_comment")
	}
	return nil
}

// AddZone legt eine Zone an (Name eindeutig).
func (m *Module) AddZone(ctx context.Context, z Zone) (Zone, error) {
	if err := normalizeZone(&z); err != nil {
		return z, err
	}
	z.Enabled, z.CreatedAt = true, time.Now().UTC()
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO dns64_zones (name, authoritative, devices, comment, enabled, created_at) VALUES (?,?,?,?,1,?)`,
		z.Name, z.Authoritative, z.Devices, z.Comment, z.CreatedAt.Format(time.RFC3339))
	if isUnique(err) {
		return z, errCfg("err_zone_dup")
	}
	if err != nil {
		return z, err
	}
	z.ID, _ = res.LastInsertId()
	return z, m.loadZones(ctx)
}

// UpdateZone aendert eine Zone; an/aus bleibt.
func (m *Module) UpdateZone(ctx context.Context, id int64, z Zone) (Zone, error) {
	if err := normalizeZone(&z); err != nil {
		return z, err
	}
	err := m.zoneExec(ctx, `UPDATE dns64_zones SET name = ?, authoritative = ?, devices = ?, comment = ? WHERE id = ?`, z.Name, z.Authoritative, z.Devices, z.Comment, id)
	if isUnique(err) {
		return z, errCfg("err_zone_dup")
	}
	z.ID = id
	return z, err
}

// DeleteZone loescht eine Zone.
func (m *Module) DeleteZone(ctx context.Context, id int64) error {
	return m.zoneExec(ctx, `DELETE FROM dns64_zones WHERE id = ?`, id)
}

// SetZoneEnabled schaltet eine Zone an oder aus.
func (m *Module) SetZoneEnabled(ctx context.Context, id int64, on bool) error {
	return m.zoneExec(ctx, `UPDATE dns64_zones SET enabled = ? WHERE id = ?`, on, id)
}

func (m *Module) zoneExec(ctx context.Context, q string, args ...any) error {
	res, err := m.core.Writer().ExecContext(ctx, q, args...)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return m.loadZones(ctx)
}

// deviceName ist ein Geraetename mit seinen Adressen (Seite und API).
type deviceName struct {
	Name string       `json:"name"`
	IPs  []netip.Addr `json:"ips"`
}

// DeviceNames: Geraetenamen fuer alle Zonen mit Geraeten.
func (m *Module) DeviceNames() []deviceName {
	t, d := m.zns.Load(), m.devs.Load()
	if t == nil || d == nil {
		return nil
	}
	var out []deviceName
	for _, z := range t.byName {
		if !z.Devices {
			continue
		}
		for slug := range *d {
			out = append(out, deviceName{Name: slug + "." + z.Name, IPs: m.deviceIPs(slug)})
		}
	}
	slices.SortFunc(out, func(a, b deviceName) int { return strings.Compare(a.Name, b.Name) })
	return out
}
