package dns64

import (
	"context"
	"encoding/json"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/ra"
	"github.com/ipv64net/node64/internal/metrics"
)

func TestRAPick(t *testing.T) {
	a := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, v := range s {
			out = append(out, netip.MustParseAddr(v))
		}
		return out
	}
	for _, c := range []struct {
		addrs []string
		bind  string
		want  string
	}{
		{[]string{"fe80::1", "2001:db8::2", "fd00::2"}, "", "fd00::2"}, // ULA vor global (bleibt beim Praefixwechsel)
		{[]string{"fe80::1", "2001:db8::2"}, "", "2001:db8::2"},
		{[]string{"fe80::1"}, "", ""}, // nur link-lokal: nichts
		{[]string{"fe80::1", "2001:db8::2", "fd00::2"}, "2001:db8::2", "2001:db8::2"},
		{[]string{"fe80::1", "fd00::2"}, "2001:db8::9", ""}, // Bind-Adresse nicht auf der Schnittstelle
	} {
		var bind netip.Addr
		if c.bind != "" {
			bind = netip.MustParseAddr(c.bind)
		}
		got := raPick(a(c.addrs...), bind)
		if (c.want == "" && got.IsValid()) || (c.want != "" && got != netip.MustParseAddr(c.want)) {
			t.Errorf("%v bind %q: got %v, want %q", c.addrs, c.bind, got, c.want)
		}
	}
}

func TestSetRAConfig(t *testing.T) {
	m, _ := testModule(t)
	old := dhcpBridge
	dhcpBridge = func() bool { return false }
	t.Cleanup(func() { dhcpBridge = old })
	ctx := context.Background()
	if c := m.raConfig(ctx); c.Enabled || len(c.Ifaces) != 0 {
		t.Fatalf("default %+v", c)
	}
	for _, bad := range []RAConfig{
		{Enabled: true},                                  // ohne Schnittstelle
		{Ifaces: []string{"eth0;rm"}},                    // ungueltige Schnittstelle
		{Ifaces: []string{"eth0"}, Domain: "bad domain"}, // Domain
		{Ifaces: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}},
	} {
		if _, err := m.SetRAConfig(ctx, bad); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
	c, err := m.SetRAConfig(ctx, RAConfig{Enabled: true, Ifaces: []string{" eth9 ", "eth9", "eth8"}, Domain: "Home.LAN."})
	if err != nil || len(c.Ifaces) != 2 || c.Domain != "home.lan" {
		t.Fatalf("save %+v %v", c, err)
	}
	if got := m.raConfig(ctx); !got.Enabled || strings.Join(got.Ifaces, ",") != "eth9,eth8" || got.Domain != "home.lan" {
		t.Fatalf("stored %+v", got)
	}
	if m.dh.ra.srv.Load() != nil {
		t.Fatal("sender started while the module is stopped")
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	s := m.dh.ra.srv.Load()
	if s == nil || strings.Join(s.Ifaces, ",") != "eth9,eth8" || len(s.Domains) != 1 {
		t.Fatalf("sender %+v", s)
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var sb strings.Builder
	_, _ = w.WriteTo(&sb)
	if !strings.Contains(sb.String(), `node64_dns64_ra_announcing{interface="eth9"} 0`) {
		t.Errorf("metrics:\n%s", sb.String())
	}
	if _, err := m.SetRAConfig(ctx, RAConfig{Ifaces: []string{"eth9"}}); err != nil || m.dh.ra.srv.Load() != nil {
		t.Fatalf("off: %v %v", err, m.dh.ra.srv.Load())
	}
	dhcpBridge = func() bool { return true }
	if _, err := m.SetRAConfig(ctx, RAConfig{Enabled: true, Ifaces: []string{"eth9"}}); err == nil {
		t.Fatal("enabled in a docker bridge network")
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
}

// Anzeige: Router mit fremdem DNS-Server -> Hinweis; kein Router vergibt Adressen -> Hinweis.
func TestRAView(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	other := ra.Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::1"), Lifetime: 1800, DNS: []netip.Addr{netip.MustParseAddr("fe80::1")}, LastSeen: time.Now()}
	m.dh.ra.probe.Store(&raProbe{At: time.Now(), Routers: []ra.Router{other}})
	v := m.raView(ctx, []DHCPScope{{Domain: "home.lan"}})
	if !v.Probed || len(v.Routers) != 1 || !v.Routers[0].OtherDNS || v.Routers[0].OwnDNS || !v.NoAddrs || v.DomainHint != "home.lan" {
		t.Fatalf("view %+v", v)
	}
	other.Prefixes = []ra.Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/64"), SLAAC: true, Valid: 7200}}
	m.dh.ra.probe.Store(&raProbe{At: time.Now(), Routers: []ra.Router{other}})
	if v := m.raView(ctx, nil); v.NoAddrs {
		t.Fatal("SLAAC prefix not recognised")
	}
	// API
	mux := dhcpMux(m)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/dns64/dhcp/ipv6", nil))
	var out struct {
		Config  RAConfig    `json:"config"`
		Running bool        `json:"running"`
		Status  []ra.Status `json:"status"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil || out.Running || out.Status == nil {
		t.Fatalf("api %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/dns64/dhcp/ipv6", strings.NewReader(`{"enabled":false,"interfaces":["eth9"],"domain":"x.lan"}`)))
	if rec.Code != http.StatusOK || m.raConfig(ctx).Domain != "x.lan" {
		t.Fatalf("put %d %s", rec.Code, rec.Body)
	}
}

func TestRAPageRenders(t *testing.T) {
	tpl, err := template.New("dhcp").Funcs(template.FuncMap{"join": strings.Join}).ParseFS(templateFS, "templates/pages/dhcp.html")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r := raRouterView{Router: ra.Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::1"), Lifetime: 1800, Managed: true, LastSeen: now,
		Prefixes: []ra.Prefix{{Prefix: netip.MustParsePrefix("2001:db8::/64"), SLAAC: true}}, DNS: []netip.Addr{netip.MustParseAddr("fe80::1")}, Domains: []string{"fritz.box"}}, OtherDNS: true}
	views := []raView{
		{},
		{Config: RAConfig{Enabled: true, Ifaces: []string{"eth0"}, Domain: "home.lan"}, Running: true, Err: "permission denied",
			Status:  []ra.Status{{Iface: "eth0", DNS: []netip.Addr{netip.MustParseAddr("fd00::2")}, LastSent: now}, {Iface: "eth1", Error: "x", ErrKind: "no_iface"}, {Iface: "eth2", ErrKind: "no_addr"}, {Iface: "eth3", ErrKind: "send"}},
			Ifaces:  []raIface{{Name: "eth0", Pick: netip.MustParseAddr("fd00::2"), Selected: true}, {Name: "eth5"}},
			Routers: []raRouterView{r, {Router: ra.Router{Iface: "eth0", Source: netip.MustParseAddr("fe80::9"), DNS: []netip.Addr{netip.MustParseAddr("fd00::2")}, LastSeen: now}, OwnDNS: true}}},
		{Probed: true, ProbeAt: now, ProbeErr: "no such interface", NoAddrs: true, DomainHint: "home.lan"},
	}
	for i, v := range views {
		var sb strings.Builder
		if err := tpl.ExecuteTemplate(&sb, "content", tview{CSRF: "c", Data: pageData{DHCP: dhcpPage{Mode: dhcpOff, RA: v}}}); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		if i == 1 && (!strings.Contains(sb.String(), "dns64.dhcp.ra.other_dns") || !strings.Contains(sb.String(), "dns64.dhcp.ra.err_no_iface")) {
			t.Fatalf("hints missing:\n%s", sb.String())
		}
	}
}
