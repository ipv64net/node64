package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/tunnel"
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
	// Company: 1 bis alle Server (waechst mit), dazu "alle (auch kuenftige)" = 0; Verbindungen 1 bis 4
	v = newServersView(&ipv64api.CDN64Servers{Count: 4, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08", "srv09", "srv10"},
		Sessions: 2, SessionsMax: 4})
	if !slices.Equal(v.Options, []int{1, 2, 3, 4, 0}) || v.Current != 0 || !slices.Equal(v.SessionOptions, []int{1, 2, 3, 4}) || v.CurSessions != 2 {
		t.Fatalf("company: %+v", v)
	}
	v = newServersView(&ipv64api.CDN64Servers{Count: 4, Choice: 4, Max: 4, All: true, Total: 4, Selectable: true, Sessions: 1, SessionsMax: 4})
	if v.Current != 4 {
		t.Fatalf("company, 4 chosen (not all): %+v", v)
	}
	// Free: fest 1x1, keine Auswahl der Verbindungen
	if v = newServersView(&ipv64api.CDN64Servers{Count: 1, Max: 1, Total: 4, Sessions: 1, SessionsMax: 1}); v.SessionOptions != nil || v.CurSessions != 1 {
		t.Fatalf("free: %+v", v)
	}
}

// Server je Tunnel: die Node nimmt die Server ihres Tunnels (nicht die Liste der Uebersicht), setzt die Anzahl fuer
// ihren Tunnel und zeigt den Knopf in der Spalte CDN64 nur, wenn die Klasse waehlen darf.
func TestOnlineServersPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	all := []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}, {Name: "srv08", Host: "127.0.0.1", Port: 2, IPs: []string{"127.0.0.1"}}}
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{}, edges: all,
		servers: &ipv64api.CDN64Servers{Count: 2, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}, Sessions: 1, SessionsMax: 4}}
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
	// ipv64 meldet srv08 als ausgefallen (standby): gleiche Verbindung, nur die Markierung wechselt
	e.m.online.mu.Lock()
	cl0 := e.m.online.client
	e.m.online.mu.Unlock()
	f.mu.Lock()
	f.tunEdges = []ipv64api.CDN64Edge{{Name: "srv08", Host: "127.0.0.1", Port: 2, IPs: []string{"127.0.0.1"}, Standby: true}}
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	e.m.online.mu.Lock()
	cl1 := e.m.online.client
	e.m.online.mu.Unlock()
	if cl0 == nil || cl1 != cl0 || len(cl1.Status()) != 1 || !cl1.Status()[0].Standby {
		t.Fatalf("standby not taken over in place: same client %v", cl1 == cl0)
	}
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	e.m.g.Audit = func(*http.Request, string, string, string) {}
	post := func(count string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/cdn64/online/servers", strings.NewReader("count="+count+"&sessions=2"))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.m.pageOnlineServers(rec, req)
		return rec
	}
	if rec := post("3"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(flash, "success") || !slices.Equal(f.setCount, []int{3}) || !slices.Equal(f.setTun, []string{tun}) {
		t.Fatalf("set 3: %d %q %v %v", rec.Code, flash, f.setCount, f.setTun)
	}
	if s := e.m.onlineServers(ctx, e.m.online.remote.Load().Data); s == nil || s.Count != 3 || s.CurSessions != 2 {
		t.Fatalf("remote not updated: %+v", s)
	}
	// Verbindungen je Server: die Node uebernimmt sie beim Abgleich, ohne den Tunnel neu zu starten
	e.m.online.mu.Lock()
	cl := e.m.online.client
	e.m.online.mu.Unlock()
	e.m.onlineSync(ctx)
	e.m.online.mu.Lock()
	cl2 := e.m.online.client
	e.m.online.mu.Unlock()
	if cl == nil || cl2 != cl || cl.Status()[0].Wanted != 2 || e.m.core.SettingOr(ctx, setOnlineSessions, "") != "2" {
		t.Fatalf("sessions not applied in place: same client %v, %+v", cl2 == cl, cl.Status())
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
	for _, want := range []string{`data-bs-target="#cdn64-servers"`, `id="cdn64-servers"`, `action="/cdn64/online/servers"`, `<option value="3" selected>`, `<option value="0">`, "cdn64.online.servers_now",
		`name="sessions"`, "cdn64.online.servers_sessions_n", "3×2", `data-c64o-busy data-c64o-reload`} {
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

// Spinner in der Spalte CDN64: solange ein Server nicht alle eingestellten Verbindungen hat und sich an ihm in der
// letzten Minute etwas geaendert hat (Start, Speichern, Abbruch); ein laenger ausgefallener Server dreht nicht endlos.
func TestOnlinePending(t *testing.T) {
	now := time.Now()
	st := []tunnel.EdgeStatus{{Name: "srv07", Sessions: 4, Slots: 4, Changed: now}, {Name: "srv08", Sessions: 1, Slots: 4, Changed: now.Add(-10 * time.Second)}}
	if up, want, p := onlinePending(st, now); up != 5 || want != 8 || !p {
		t.Fatalf("building: %d/%d %v", up, want, p)
	}
	st[1].Standby, st[1].Sessions = true, 0 // laut ipv64 ausgefallen, keine Verbindung: zaehlt nicht mit, kein Spinner
	if up, want, p := onlinePending(st, now); up != 4 || want != 4 || p {
		t.Fatalf("standby server: %d/%d %v", up, want, p)
	}
	st[1].Sessions = 1 // schon zurueck, ipv64 weiss es noch nicht: zaehlt wieder
	if up, want, p := onlinePending(st, now); up != 5 || want != 8 || !p {
		t.Fatalf("standby but connected: %d/%d %v", up, want, p)
	}
	st[1].Standby = false
	st[1].Changed = now.Add(-2 * time.Minute) // seit zwei Minuten unvollstaendig: ausgefallen bzw. abgelehnt
	if _, _, p := onlinePending(st, now); p {
		t.Fatal("long-down server must not spin")
	}
	st[1].Sessions = 4
	if up, want, p := onlinePending(st, now); up != 8 || want != 8 || p {
		t.Fatalf("complete: %d/%d %v", up, want, p)
	}
	h := newHost()
	h.ID, h.Names = 9, []string{"p.test"}
	row := hostRow{Host: h, Online: &onlineRow{Mode: 1, Names: h.Names, Status: "active", Up: 1, Want: 4, Pending: true,
		Edges: []onlineBadge{{Name: "srv08", State: "direct", Sessions: 1}}}}
	sv := newServersView(&ipv64api.CDN64Servers{Count: 1, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv08"}, Sessions: 4, SessionsMax: 4})
	body := renderHosts(t, listData{Kind: KindProxy, OnlineOn: true, Rows: []hostRow{row}, Servers: sv})
	for _, want := range []string{"data-c64o-pending ", `data-c64o-pending-btn`, `data-c64o-edge="srv08"`, "1×4", `data-fmt="cdn64.online.conns_pending"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	row.Online.Pending = false
	if body = renderHosts(t, listData{Kind: KindProxy, OnlineOn: true, Rows: []hostRow{row}, Servers: sv}); strings.Contains(body, "data-c64o-pending") {
		t.Fatal("no spinner once all connections are up")
	}
}
