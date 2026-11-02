package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

func TestServersView(t *testing.T) {
	if newServersView(nil) != nil {
		t.Fatal("nil portal: view")
	}
	// Supporter: fest 2, keine Auswahl
	v := newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Assigned: []string{"srv07", "srv08"}})
	if v.Options != nil || v.Names != "srv07, srv08" {
		t.Fatalf("fixed: %+v", v)
	}
	// Business: 1 bis 2
	v = newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}})
	if !slices.Equal(v.Options, []int{1, 2}) || v.Current != 2 {
		t.Fatalf("business: %+v", v)
	}
	// Company: 1 bis 3, dann "alle (auch kuenftige)" statt 4; alle zugeteilt = Option 0
	v = newServersView(&ipv64api.CDN64Servers{Count: 4, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08", "srv09", "srv10"}})
	if !slices.Equal(v.Options, []int{1, 2, 3, 0}) || v.Current != 0 {
		t.Fatalf("company: %+v", v)
	}
}

// Server je Tunnel: die Node nimmt die Server ihres Tunnels (nicht die Liste der Uebersicht), setzt die Anzahl fuer
// ihren Tunnel und zeigt den Knopf in der Spalte CDN64 nur, wenn die Klasse waehlen darf.
func TestOnlineServersPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	all := []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}, {Name: "srv08", Host: "127.0.0.1", Port: 2, IPs: []string{"127.0.0.1"}}}
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{}, edges: all,
		servers: &ipv64api.CDN64Servers{Count: 2, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"a.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.onlineEnable(ctx, h, 1); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tunEdges = all[1:] // Portal mit Server je Tunnel: der Tunnel hat nur srv08, die Uebersicht nennt beide
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	if c, _, _ := e.m.onlineConf(ctx); c == nil || len(c.Edges) != 1 || c.Edges[0].Name != "srv08" {
		t.Fatalf("own tunnel's servers expected: %+v", c)
	}
	tun := ""
	if c, _, _ := e.m.onlineConf(ctx); c != nil {
		tun = c.Tunnel
	}
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	e.m.g.Audit = func(*http.Request, string, string, string) {}
	post := func(count string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/cdn64/online/servers", strings.NewReader("count="+count))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.m.pageOnlineServers(rec, req)
		return rec
	}
	if rec := post("3"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(flash, "success") || !slices.Equal(f.setCount, []int{3}) || !slices.Equal(f.setTun, []string{tun}) {
		t.Fatalf("set 3: %d %q %v %v", rec.Code, flash, f.setCount, f.setTun)
	}
	if s := e.m.onlineServers(ctx, e.m.online.remote.Load().Data); s == nil || s.Count != 3 {
		t.Fatalf("remote not updated: %+v", s)
	}
	if post("x"); !strings.HasPrefix(flash, "danger") || len(f.setCount) != 1 {
		t.Fatalf("invalid: %q %v", flash, f.setCount)
	}
	f.servers.Selectable = false // Klasse fest: ipv64 lehnt ab
	if post("1"); !strings.HasPrefix(flash, "danger") {
		t.Fatalf("fixed plan: %q", flash)
	}

	// Spalte CDN64: Knopf mit der Anzahl, ein Dialog mit Auswahl; keine Kachel mehr
	f.servers.Selectable = true
	row := hostRow{Host: h, Online: &onlineRow{Mode: 1, Names: h.Names, Status: "active"}}
	d := listData{Kind: KindProxy, OnlineOn: true, Rows: []hostRow{row}, Servers: newServersView(f.servers)}
	body := renderHosts(t, d)
	for _, want := range []string{`data-bs-target="#cdn64-servers"`, `id="cdn64-servers"`, `action="/cdn64/online/servers"`, `<option value="3" selected>`, `<option value="0">`, "cdn64.online.servers_now"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	if strings.Contains(body, `id="cdn-servers"`) {
		t.Fatal("tile below the hosts must be gone")
	}
	d.Servers = newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Assigned: []string{"srv07", "srv08"}})
	if body = renderHosts(t, d); strings.Contains(body, "#cdn64-servers") || strings.Contains(body, `name="count"`) {
		t.Fatal("fixed plan: no button expected")
	}
}
