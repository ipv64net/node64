package dns64

import (
	"context"
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/dhcp"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/module"
)

func dhcpMux(m *Module) *http.ServeMux {
	pass := func(h http.Handler) http.Handler { return h }
	g := module.Guards{Enabled: pass, Auth: pass, T: func(_ *http.Request, key string, _ ...any) string { return key }}
	m.g = g
	mux := http.NewServeMux()
	m.dhcpRoutes(mux, g)
	return mux
}

func TestNormalizeDHCPScope(t *testing.T) {
	ok := DHCPScope{Iface: "eth0", Subnet: "192.168.1.7/24", Start: "192.168.1.100", End: "192.168.1.199", Router: "192.168.1.1", DNS: []string{" 192.168.1.2 "}, Domain: "Home.LAN."}
	if err := normalizeDHCPScope(&ok); err != nil {
		t.Fatal(err)
	}
	if ok.Subnet != "192.168.1.0/24" || ok.Domain != "home.lan" || ok.LeaseHours != 24 || ok.DNS[0] != "192.168.1.2" {
		t.Fatalf("normalized %+v", ok)
	}
	for name, mod := range map[string]func(*DHCPScope){
		"iface":     func(s *DHCPScope) { s.Iface = "eth0; rm" },
		"subnet v6": func(s *DHCPScope) { s.Subnet = "fd00::/64" },
		"subnet 31": func(s *DHCPScope) { s.Subnet = "192.168.1.0/31" },
		"range out": func(s *DHCPScope) { s.End = "192.168.2.10" },
		"range rev": func(s *DHCPScope) { s.Start, s.End = "192.168.1.199", "192.168.1.100" },
		"broadcast": func(s *DHCPScope) { s.End = "192.168.1.255" },
		"router":    func(s *DHCPScope) { s.Router = "10.0.0.1" },
		"dns":       func(s *DHCPScope) { s.DNS = []string{"x"} },
		"lease":     func(s *DHCPScope) { s.LeaseHours = 9000 },
		"boot":      func(s *DHCPScope) { s.BootBIOS = "a b" },
	} {
		s := DHCPScope{Iface: "eth0", Subnet: "192.168.1.0/24", Start: "192.168.1.100", End: "192.168.1.199"}
		mod(&s)
		if normalizeDHCPScope(&s) == nil {
			t.Errorf("%s: accepted %+v", name, s)
		}
	}
}

func TestSuggestScope(t *testing.T) {
	s := suggestScope("eth0", netip.MustParsePrefix("10.0.5.20/16"), netip.MustParseAddr("10.0.0.1"))
	if s.Subnet != "10.0.0.0/16" || s.Start != "10.0.5.100" || s.End != "10.0.5.199" || s.Router != "10.0.0.1" {
		t.Fatalf("%+v", s)
	}
	s = suggestScope("eth1", netip.MustParsePrefix("192.168.9.5/28"), netip.MustParseAddr("192.168.1.1"))
	if s.Subnet != "192.168.9.0/28" || s.Start != "192.168.9.8" || s.End != "192.168.9.14" || s.Router != "" {
		t.Fatalf("%+v", s)
	}
}

// API: Netz anlegen (je Schnittstelle eins), feste Adresse (MAC normalisiert, IP im Netz), Schalter ohne
// laufendes Modul: gespeichert, aber kein Server. Netz loeschen nimmt die festen Adressen mit.
func TestAPIDHCP(t *testing.T) {
	m, _ := testModule(t)
	old := dhcpBridge
	dhcpBridge = func() bool { return false } // Tests laufen auch in Containern
	t.Cleanup(func() { dhcpBridge = old })
	mux := dhcpMux(m)
	w := apiDo(mux, "POST", "/api/dns64/dhcp/scopes", `{"interface":"eth9","subnet":"192.168.50.0/24","range_start":"192.168.50.100","range_end":"192.168.50.150","authoritative":true}`)
	if w.Code != 201 {
		t.Fatalf("add scope: %d %s", w.Code, w.Body)
	}
	var s DHCPScope
	_ = json.Unmarshal(w.Body.Bytes(), &s)
	if s.ID == 0 || !s.Enabled || s.LeaseHours != 24 {
		t.Fatalf("scope %+v", s)
	}
	if w := apiDo(mux, "POST", "/api/dns64/dhcp/scopes", `{"interface":"eth9","subnet":"10.0.0.0/24","range_start":"10.0.0.10","range_end":"10.0.0.20"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "dhcp_iface_dup") {
		t.Fatalf("dup iface: %d %s", w.Code, w.Body)
	}
	sid := strconv.FormatInt(s.ID, 10)
	if w := apiDo(mux, "POST", "/api/dns64/dhcp/reservations", `{"scope_id":`+sid+`,"mac":"AA-BB-CC-DD-EE-01","ip":"192.168.50.20","name":"nas"}`); w.Code != 201 || !strings.Contains(w.Body.String(), `"mac":"aa:bb:cc:dd:ee:01"`) {
		t.Fatalf("add res: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/dhcp/reservations", `{"scope_id":`+sid+`,"mac":"aa:bb:cc:dd:ee:02","ip":"192.168.50.20"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "dhcp_res_dup") {
		t.Fatalf("dup ip: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "POST", "/api/dns64/dhcp/reservations", `{"scope_id":`+sid+`,"mac":"aa:bb:cc:dd:ee:03","ip":"10.1.1.1"}`); w.Code != 400 || !strings.Contains(w.Body.String(), "dhcp_res_ip") {
		t.Fatalf("ip outside: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PUT", "/api/dns64/dhcp/mode", `{"mode":"observe"}`); w.Code != 200 || m.dhcpMode(context.Background()) != dhcpObserve || m.dhcpSrv.Load() != nil {
		t.Fatalf("mode: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "PUT", "/api/dns64/dhcp/mode", `{"mode":"maybe"}`); w.Code != 400 {
		t.Fatalf("bad mode: %d", w.Code)
	}
	if w := apiDo(mux, "GET", "/api/dns64/dhcp", ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"mode":"observe"`) || !strings.Contains(w.Body.String(), `"running":false`) {
		t.Fatalf("state: %d %s", w.Code, w.Body)
	}
	if w := apiDo(mux, "DELETE", "/api/dns64/dhcp/scopes/"+sid, ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	if res, _ := m.DHCPReservations(context.Background()); len(res) != 0 {
		t.Fatalf("reservations left: %+v", res)
	}
}

// Leases ueberleben den Neustart (Speicher in node64.db); dieselbe IP an eine andere MAC loescht den alten Eintrag.
func TestDHCPStore(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	s, err := m.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150"})
	if err != nil {
		t.Fatal(err)
	}
	st := dhcpStore{m}
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	ip := netip.MustParseAddr("192.168.50.100")
	_ = st.SaveLease(dhcp.Lease{Scope: s.ID, MAC: "02:00:00:00:00:0a", IP: ip, Hostname: "laptop", Expires: exp, State: dhcp.StateBound})
	_ = st.SaveLease(dhcp.Lease{Scope: s.ID, MAC: "02:00:00:00:00:0b", IP: ip, Expires: exp, State: dhcp.StateBound})
	cfg, err := m.dhcpConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Leases) != 1 || cfg.Leases[0].MAC != "02:00:00:00:00:0b" || !cfg.Leases[0].Expires.Equal(exp) || len(cfg.Scopes) != 1 {
		t.Fatalf("config %+v", cfg)
	}
}

// tview ersetzt die View des Kerns fuer den Render-Test der Seite.
type tview struct {
	Data pageData
	CSRF string
}

func (tview) T(key string, _ ...any) string { return key }
func (tview) Time(t time.Time) string       { return t.Format(time.RFC3339) }
func (tview) Doc(string) template.HTML      { return "" }

func TestDHCPPageRenders(t *testing.T) {
	tpl, err := template.ParseFS(templateFS, "templates/pages/dhcp.html")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sc := DHCPScope{ID: 1, Name: "LAN", Iface: "eth0", Subnet: "192.168.1.0/24", Start: "192.168.1.100", End: "192.168.1.199", Router: "192.168.1.1", DNS: []string{"192.168.1.2"},
		LeaseHours: 24, Authoritative: true, BootUEFI: "x.efi", Enabled: true}
	lease := dhcp.Lease{Scope: 1, MAC: "02:00:00:00:00:0a", IP: netip.MustParseAddr("192.168.1.100"), Hostname: "laptop", Expires: now.Add(time.Hour), State: dhcp.StateBound}
	for _, mode := range []string{dhcpOff, dhcpObserve, dhcpOn} {
		v := tview{CSRF: "c", Data: pageData{DHCP: dhcpPage{Mode: mode, Running: mode != dhcpOff, ResScope: map[int64]string{1: "LAN (eth0)"},
			Scopes:  []dhcpScopeView{{DHCPScope: sc, State: dhcp.ScopeView{ID: 1, Self: netip.MustParseAddr("192.168.1.2"), Size: 100, Used: 1, Leases: []dhcp.Lease{lease}}, Pct: 1}},
			Res:     []dhcpResView{{DHCPReservation{ID: 1, ScopeID: 1, MAC: "02:00:00:00:00:0b", IP: "192.168.1.20", Name: "nas"}, "nas.home.lan"}},
			Groups:  []groups.Group{{ID: 3, Name: "Kinder"}},
			Reserve: dhcpReserveView{Cluster: true, Role: dhcpReserve, Peers: []DHCPPeer{{Name: "node-a", Online: true}}, Names: "node-a", Standby: mode == dhcpOn},
			Leases:  []dhcpLeaseView{{Lease: lease, ScopeName: "LAN (eth0)", Active: true}},
			Events:  []dhcp.Event{{Time: now, Scope: 1, Type: "discover", MAC: lease.MAC, IP: lease.IP, Result: "offer"}},
			Foreign: []dhcp.Foreign{{Scope: 1, Server: netip.MustParseAddr("192.168.1.1"), LastSeen: now}},
			Ifaces:  []dhcpIface{{Name: "eth0", Addrs: []netip.Prefix{netip.MustParsePrefix("192.168.1.2/24")}, Suggest: sc}}, Suggest: sc}}}
		if err := tpl.ExecuteTemplate(io.Discard, "content", v); err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
	}
	for _, kind := range []string{"iface", "addr", "listen", ""} {
		v := tview{Data: pageData{DHCP: dhcpPage{Mode: dhcpOn, Running: true, Scopes: []dhcpScopeView{{DHCPScope: sc, State: dhcp.ScopeView{ID: 1, Error: "x", ErrKind: kind}}}}}}
		if err := tpl.ExecuteTemplate(io.Discard, "content", v); err != nil {
			t.Fatalf("error %q: %v", kind, err)
		}
	}
	if err := tpl.ExecuteTemplate(io.Discard, "content", tview{Data: pageData{DHCP: dhcpPage{Mode: dhcpOff, Bridge: true}}}); err != nil {
		t.Fatalf("empty: %v", err)
	}
}

// D3: Namen aus festen Adressen und Vergaben (A, PTR, NODATA fuer AAAA), eigene Eintraege gehen vor, ein Name je MAC,
// abgelaufene Vergaben verschwinden, MAC/IP gehen an die Gruppen.
func TestDHCPNames(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	s, err := m.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150", Domain: "home.lan"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddDHCPReservation(ctx, DHCPReservation{ScopeID: s.ID, MAC: "02:00:00:00:00:01", IP: "192.168.50.20", Name: "NAS Keller"}); err != nil {
		t.Fatal(err)
	}
	st := dhcpStore{m}
	exp := time.Now().Add(time.Hour)
	for _, l := range []dhcp.Lease{
		{Scope: s.ID, MAC: "02:00:00:00:00:0a", IP: netip.MustParseAddr("192.168.50.100"), Hostname: "Laptop-Lea", Expires: exp, State: dhcp.StateBound},
		{Scope: s.ID, MAC: "02:00:00:00:00:0b", IP: netip.MustParseAddr("192.168.50.101"), Hostname: "laptop-lea", Expires: exp, State: dhcp.StateBound}, // gleicher Name
		{Scope: s.ID, MAC: "02:00:00:00:00:0c", IP: netip.MustParseAddr("192.168.50.102"), Hostname: "alt", Expires: time.Now().Add(-time.Minute), State: dhcp.StateBound},
		{Scope: s.ID, MAC: "02:00:00:00:00:0d", IP: netip.MustParseAddr("192.168.50.103"), Hostname: "drucker", Expires: exp, State: dhcp.StateBound},
	} {
		if err := st.SaveLease(l); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.AddRecord(ctx, Record{Name: "drucker.home.lan", Type: "A", Value: "192.168.50.9"}); err != nil {
		t.Fatal(err)
	}
	if err := m.dhcpNamesBuild(ctx); err != nil {
		t.Fatal(err)
	}
	a := func(name string) string {
		rrs, ok := m.Lookup(name, dns.TypeA)
		if !ok || len(rrs) != 1 {
			return ""
		}
		return rrs[0].(*dns.A).A.String()
	}
	if a("nas-keller.home.lan") != "192.168.50.20" || a("laptop-lea.home.lan") != "192.168.50.100" || a("alt.home.lan") != "" || a("drucker.home.lan") != "192.168.50.9" {
		t.Fatalf("names: nas=%q laptop=%q alt=%q drucker=%q", a("nas-keller.home.lan"), a("laptop-lea.home.lan"), a("alt.home.lan"), a("drucker.home.lan"))
	}
	if rrs, ok := m.Lookup("laptop-lea.home.lan", dns.TypeAAAA); !ok || len(rrs) != 0 {
		t.Fatalf("AAAA: %v %v", rrs, ok)
	}
	if rrs, ok := m.Lookup("100.50.168.192.in-addr.arpa", dns.TypePTR); !ok || rrs[0].(*dns.PTR).Ptr != "laptop-lea.home.lan." {
		t.Fatalf("PTR: %v %v", rrs, ok)
	}
	if n := m.ownClientName("192.168.50.101"); n != "laptop-lea" { // ohne DNS-Namen (belegt): Name vom Geraet
		t.Fatalf("client name %q", n)
	}
	if mac := m.grp.MAC(netip.MustParseAddr("192.168.50.103")); mac != "02:00:00:00:00:0d" {
		t.Fatalf("groups mac %q", mac)
	}
}

// D5/D6: Netze, feste Adressen und Vergaben gehen von Node A nach B; das Netz kommt dort ausgeschaltet an, die Namen
// gelten auch auf B, und die Uebernahme meldet nichts zurueck (kein Echo).
func TestDHCPCluster(t *testing.T) {
	a, _ := testModule(t)
	b, _ := testModule(t)
	ctx := context.Background()
	var echo []string
	b.SetCluster(func(_ context.Context, item, id string, _ bool) { echo = append(echo, item+" "+id) })
	s, err := a.AddDHCPScope(ctx, DHCPScope{Iface: "eth9", Subnet: "192.168.50.0/24", Start: "192.168.50.100", End: "192.168.50.150", Domain: "home.lan", BootUEFI: "x.efi"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddDHCPReservation(ctx, DHCPReservation{ScopeID: s.ID, MAC: "02:00:00:00:00:01", IP: "192.168.50.20", Name: "nas"}); err != nil {
		t.Fatal(err)
	}
	_ = dhcpStore{a}.SaveLease(dhcp.Lease{Scope: s.ID, MAC: "02:00:00:00:00:0a", IP: netip.MustParseAddr("192.168.50.100"), Hostname: "tv", Expires: time.Now().Add(time.Hour).Truncate(time.Second), State: dhcp.StateBound})
	sync := func(item string) {
		cur, err := a.clDHCPCurrent(ctx, item)
		if err != nil {
			t.Fatal(err)
		}
		for id, v := range cur {
			if err := b.ClusterApply(ctx, item, id, json.RawMessage(v), false); err != nil {
				t.Fatalf("%s %s: %v", item, id, err)
			}
		}
	}
	for _, it := range []string{ItemDHCPScopes, ItemDHCPRes, ItemDHCPLeases} {
		sync(it)
	}
	bs, _ := b.DHCPScopes(ctx)
	if len(bs) != 1 || bs[0].Enabled || bs[0].BootUEFI != "x.efi" || bs[0].Domain != "home.lan" {
		t.Fatalf("scope on b: %+v", bs)
	}
	for _, it := range []string{ItemDHCPScopes, ItemDHCPRes, ItemDHCPLeases} {
		b.clChanged(ctx, it)
	}
	if len(echo) != 0 {
		t.Fatalf("echo: %v", echo)
	}
	if err := b.dhcpNamesBuild(ctx); err != nil {
		t.Fatal(err)
	}
	if rrs, ok := b.Lookup("tv.home.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatalf("name on b: %v %v", rrs, ok)
	}
	if rrs, ok := b.Lookup("nas.home.lan", dns.TypeA); !ok || len(rrs) != 1 {
		t.Fatalf("fixed name on b: %v %v", rrs, ok)
	}
	// Vergabe geloescht -> auf B weg
	if err := b.ClusterApply(ctx, ItemDHCPLeases, "l:192.168.50.0/24|02:00:00:00:00:0a", nil, true); err != nil {
		t.Fatal(err)
	}
	if rows, _ := b.dhcpLeaseRows(ctx); len(rows) != 0 {
		t.Fatalf("lease left: %+v", rows)
	}
	// Netz geloescht -> mit festen Adressen weg
	if err := b.ClusterApply(ctx, ItemDHCPScopes, "s:192.168.50.0/24", nil, true); err != nil {
		t.Fatal(err)
	}
	if res, _ := b.DHCPReservations(ctx); len(res) != 0 {
		t.Fatalf("reservations left: %+v", res)
	}
}

// D6: Reserve bleibt still ohne Partner und solange einer erreichbar ist; DNS-Server im Netz aus dem Cluster.
func TestDHCPReserve(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	if !m.dhcpPrimaryAlive(ctx) {
		t.Fatal("reserve without peers must stay silent")
	}
	peers := []DHCPPeer{{Name: "a", Addr: netip.MustParseAddr("192.168.50.2"), Online: true}, {Name: "far", Addr: netip.MustParseAddr("10.0.0.2")}}
	m.SetDHCPPeers(func(context.Context, string) []DHCPPeer { return peers })
	if !m.dhcpPrimaryAlive(ctx) {
		t.Fatal("primary online")
	}
	peers[0].Online = false
	if m.dhcpPrimaryAlive(ctx) {
		t.Fatal("primary gone, reserve must answer")
	}
	if dns := m.dhcpPeerDNS(ctx, netip.MustParsePrefix("192.168.50.0/24")); len(dns) != 1 || dns[0] != peers[0].Addr {
		t.Fatalf("peer dns %v", dns)
	}
	if !m.dhcpIsPeer(netip.MustParseAddr("10.0.0.2")) || m.dhcpIsPeer(netip.MustParseAddr("10.0.0.3")) {
		t.Fatal("peer detection")
	}
	if err := m.SetDHCPRole(ctx, "boss"); err == nil {
		t.Fatal("bad role accepted")
	}
	if err := m.SetDHCPRole(ctx, dhcpReserve); err != nil || m.dhcpRole(ctx) != dhcpReserve {
		t.Fatalf("role: %v", err)
	}
}
