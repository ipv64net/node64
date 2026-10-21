package cdn64

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Pause (alle Modi) und Namen, die die Node nicht verwaltet (Modus 3 von ipv64.net, andere Nodes).
func TestOnlinePause(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}},
		extra: []ipv64api.CDN64Host{{ID: 50, FQDN: "web.test", Mode: 3, Status: "active", Wildcard: true,
			Target:   &ipv64api.CDN64Target{Source: "fixed", Target: "203.0.113.5", Port: 8443, Scheme: "https", Frontend: 2, CacheMB: 256, CacheMinutes: 10},
			ACL:      &ipv64api.CDN64ACL{Default: "deny", List: []string{"198.51.100.0/24"}},
			Mappings: []ipv64api.CDN64Mapping{{ID: 1, Name: "WireGuard", ListenPort: 51820, Transport: "udp", TargetPort: 51820}}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	other := newHost()
	other.Names, other.TargetHost, other.TargetPort = []string{"local.test"}, "93.184.216.34", 8081
	if err := e.m.saveHost(ctx, other); err != nil {
		t.Fatal(err)
	}
	if res, err := e.m.onlineEnable(ctx, h, 1); err != nil || len(res) != 1 || res[0].Result != "on" {
		t.Fatalf("enable: %v %+v", err, res)
	}
	call := func(path, body string) int {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader(body)))
		return rec.Code
	}
	hp := "/api/cdn64/hosts/" + strconv.FormatInt(h.ID, 10) + "/online/pause"

	// Host der Node: alle Namen pausieren, Stand sofort sichtbar
	if c := call(hp, `{"paused":true}`); c != http.StatusNoContent {
		t.Fatalf("pause: %d", c)
	}
	list, _ := e.m.onlineNames(ctx)
	if len(list) != 1 || !f.paused[list[0].RemoteID] {
		t.Fatalf("not paused at ipv64: %+v %v", list, f.paused)
	}
	hosts, _ := e.m.hosts(ctx)
	if r := e.m.onlineIndex(ctx, hosts)[h.ID]; r == nil || !r.Paused {
		t.Fatalf("row not paused: %+v", r)
	}
	if c := call(hp, `{"paused":false}`); c != http.StatusNoContent || f.paused[list[0].RemoteID] {
		t.Fatalf("resume: %d %v", c, f.paused)
	}
	if c := call(hp, `kaputt`); c != http.StatusBadRequest {
		t.Fatalf("bad json: %d", c)
	}
	if c := call("/api/cdn64/hosts/"+strconv.FormatInt(other.ID, 10)+"/online/pause", `{"paused":true}`); c != http.StatusConflict {
		t.Fatalf("host without CDN64: %d", c)
	}

	// Name, den die Node nicht verwaltet: in der Liste, Pause per ID bei ipv64
	others := e.m.onlineOthers(ctx, e.m.online.remote.Load().Data)
	if len(others) != 1 || others[0].FQDN != "web.test" || others[0].Target.CacheMB != 256 {
		t.Fatalf("others: %+v", others)
	}
	if c := call("/api/cdn64/online/names/50/pause", `{"paused":true}`); c != http.StatusNoContent || !f.paused[50] {
		t.Fatalf("remote pause: %d %v", c, f.paused)
	}
	if c := call("/api/cdn64/online/names/999/pause", `{"paused":true}`); c != http.StatusNotFound {
		t.Fatalf("unknown name: %d", c)
	}
	if c := call("/api/cdn64/online/names/x/pause", `{"paused":true}`); c != http.StatusBadRequest {
		t.Fatalf("bad id: %d", c)
	}

	// Liste rendern: Hostzeile mit Pause-Knopf, Karte mit Modus 3 (Ziel, Cache, Liste, Portmapper, pausiert)
	rows, err := e.m.rowsOf(ctx, KindProxy)
	if err != nil {
		t.Fatal(err)
	}
	d := listData{Kind: KindProxy, Rows: rows, OnlineOn: true, Others: e.m.onlineOthers(ctx, e.m.online.remote.Load().Data)}
	body := renderHosts(t, d)
	for _, want := range []string{`data-c64o-pause="` + strconv.FormatInt(h.ID, 10) + `"`, `data-c64o-rpause="50" data-paused="1"`,
		"https://203.0.113.5:8443", "cdn64.online.o_cache", "cdn64.online.o_acl_deny", "51820/udp → 51820 (WireGuard)",
		"https://ipv64.net/cdn64?edit=50", "cdn64.online.paused", `<tr class="table-warning">`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
}

// Ohne eigene Namen und ohne Tunnel holt der Abgleich den Stand nur selten - ausser die Liste wurde geoeffnet.
func TestOnlineIdleSync(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	for i := 0; i < 3; i++ {
		e.m.onlineSync(ctx)
	}
	if f.calls != 1 {
		t.Fatalf("idle: %d calls, want 1", f.calls)
	}
	e.m.online.want.Store(true)
	e.m.onlineSync(ctx)
	if f.calls != 2 {
		t.Fatalf("list opened: %d calls, want 2", f.calls)
	}
	f.extra = []ipv64api.CDN64Host{{ID: 7, FQDN: "web.test", Mode: 3, Status: "active"}}
	e.m.online.want.Store(true)
	e.m.onlineSync(ctx)
	e.m.onlineSync(ctx) // Namen da: jeder Abgleich holt den Stand
	if f.calls != 4 || len(e.m.online.remote.Load().Data.Hosts) != 1 {
		t.Fatalf("with names: %d calls", f.calls)
	}
}

// tplView spielt die View der Oberflaeche fuer die Vorlage (Texte = Schluessel).
type tplView struct {
	Data          listData
	CSRF, Version string
}

func (tplView) T(key string, _ ...any) string { return key }
func (tplView) Doc(string) template.HTML      { return "" }
func (tplView) DocURL(string) string          { return "#" }
func (tplView) Bytes(n int64) string          { return fmt.Sprintf("%d B", n) }
func (tplView) Int(n int64) string            { return strconv.FormatInt(n, 10) }
func (tplView) Time(t time.Time) string       { return t.Format(time.RFC3339) }
func (tplView) Date(t time.Time) string       { return t.Format(time.DateOnly) }
func (tplView) Ago(time.Time) string          { return "" }

func renderHosts(t *testing.T, d listData) string {
	t.Helper()
	tp, err := template.ParseFS(templateFS, "templates/pages/hosts.html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tp.ExecuteTemplate(&buf, "content", tplView{Data: d}); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}
