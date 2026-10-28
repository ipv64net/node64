package cdn64

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// CDN64 Statistik: Reiter nur mit CDN64-Namen, Seite mit Kacheln/Tabelle/Kasten, Fehler von ipv64, Schalter WAF/JA4.
func TestProtection(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	var data any
	var flash string
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, d any) { data = d; w.WriteHeader(st) }
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return "t:" + key + fmt.Sprint(args...) }

	// ohne CDN64-Namen kein Reiter
	e.m.online.remote.Store(&onlineRemote{At: time.Now(), Data: &ipv64api.CDN64Overview{}})
	if hasTab(e.m.tabs("/cdn64"), "/cdn64/protection") {
		t.Fatal("tab without CDN64 names")
	}

	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if res, err := e.m.onlineEnable(ctx, h, 2); err != nil || len(res) != 1 || res[0].Result != "on" {
		t.Fatalf("enable: %v %+v", err, res)
	}
	list, _ := e.m.onlineNames(ctx)
	rid := list[0].RemoteID
	f.mu.Lock()
	f.waf, f.ja4 = map[int64]bool{rid: true}, map[int64]string{rid: "block"}
	f.extra = []ipv64api.CDN64Host{{ID: 90, FQDN: "web.test", Mode: 3, Status: "active"}}
	c := ipv64api.CDN64ProtectionCounts{BlockedList: 100, BlockedACL: 5, BlockedFlood: 20, BlockedLimit: 7, BlockedWAF: 3, BlockedJA4: 2,
		JA4Hits: 9, BlockedIPs: 42, Conns: 1234, ConnsV4: 321}
	f.prot = &ipv64api.CDN64Protection{JA4Global: "count", Totals: c,
		Daily:  []ipv64api.CDN64ProtectionDay{{Day: time.Now().Format(time.DateOnly), CDN64ProtectionCounts: c}},
		Hosts:  []ipv64api.CDN64ProtectionHost{{ID: rid, FQDN: "app.test", Mode: 2, CDN64ProtectionCounts: c}, {ID: 90, FQDN: "web.test", Mode: 3}},
		JA4Top: []ipv64api.CDN64JA4Hit{{JA4: "t13d1516h2_8daaf6152771_e5627efa2ab1", Hits: 9}}}
	f.mu.Unlock()
	ov, err := f.Overview(ctx)
	e.m.onlineSetRemote(ov, err)
	if !hasTab(e.m.tabs("/cdn64"), "/cdn64/protection") {
		t.Fatal("tab missing with CDN64 names")
	}

	get := func(q string) (int, protectionData) {
		data = nil
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest("GET", "/cdn64/protection"+q, nil))
		d, _ := data.(protectionData)
		return rec.Code, d
	}
	code, d := get("?days=30")
	if code != http.StatusOK || d.Error != "" || d.Days != 30 || d.Blocked != 137 || d.Overload != 27 || !d.Counting || len(d.Rows) != 2 {
		t.Fatalf("page: %d %+v", code, d)
	}
	if r := d.Rows[0]; r.FQDN != "app.test" || r.Link != "/cdn64/hosts/"+strconv.FormatInt(h.ID, 10) || !r.WAF || r.JA4 != "block" || r.Blocked != 137 {
		t.Fatalf("row: %+v", r)
	}
	if r := d.Rows[1]; r.Link != "https://ipv64.net/cdn64?edit=90" || !r.Ext {
		t.Fatalf("mode 3 row: %+v", r)
	}
	if len(d.Modes) != 2 || d.Modes[0] != 2 || d.Modes[1] != 3 || !strings.Contains(d.Chart, `"data":[0,`) || !strings.Contains(d.Chart, "cdn64.protection.r_ja4") {
		t.Fatalf("modes/chart: %v %s", d.Modes, d.Chart)
	}
	// Zwischenspeicher je Zeitraum; unbekannter Zeitraum = 7 Tage
	get("?days=30")
	if _, d := get("?days=99"); d.Days != 7 {
		t.Fatalf("default range: %d", d.Days)
	}
	f.mu.Lock()
	days := fmt.Sprint(f.protDays)
	f.mu.Unlock()
	if days != "[30 7]" {
		t.Fatalf("ipv64 calls: %s", days)
	}

	// Vorlage: Kacheln, Tabelle, Werkzeuge, Startphase, Kasten "Ohne CDN64", Reiter
	d.Tabs = e.m.tabs("/cdn64/protection")
	body := renderPage(t, "protection.html", d)
	for _, want := range []string{`data-prot="blocked">137<`, `data-prot="ips">42<`, `data-prot="overload">27<`, `data-prot="conns">1234<`,
		"cdn64.protection.k_v4", "table-stack", `data-nolabel`, `href="/cdn64/hosts/` + strconv.FormatInt(h.ID, 10) + `"`, "https://ipv64.net/cdn64?edit=90",
		"t13d1516h2_8daaf6152771_e5627efa2ab1", "cdn64.protection.tools_hint", "cdn64.protection.tools_count", "data-prot-without",
		"cdn64.protection.without_ip", "cdn64.protection.without_v4", "cdn64.protection.mode_2", "cdn64.protection.mode_3", "cdn64.protection.honest",
		"cdn64.protection.ja4_block", "data-prot-chart", `href="/cdn64/protection?days=1"`, `nav-link active" href="/cdn64/protection"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	if strings.Contains(body, "cdn64.protection.mode_1") {
		t.Fatal("sentence for mode 1 without names in mode 1")
	}
	if strings.Contains(body, "data-prot-nodata") {
		t.Fatal("no-data hint although something was blocked")
	}
	// ohne Zahlen (z. B. Server noch ohne Schutz-Zaehler): Hinweis statt leerer Seite
	empty := d
	empty.P, empty.Blocked = &ipv64api.CDN64Protection{}, 0
	if eb := renderPage(t, "protection.html", empty); !strings.Contains(eb, "data-prot-nodata") || !strings.Contains(eb, "cdn64.protection.nodata") {
		t.Fatal("page without figures misses the no-data hint")
	}

	// Liste der Proxy-Hosts: Schalter mit dem Stand von ipv64
	rows, _ := e.m.rowsOf(ctx, KindProxy)
	hb := renderHosts(t, listData{Kind: KindProxy, Rows: rows, OnlineOn: true})
	for _, want := range []string{`action="/cdn64/hosts/` + strconv.FormatInt(h.ID, 10) + `/protection"`, `name="waf" value="1" id="c64o-waf-` + strconv.FormatInt(h.ID, 10) + `" checked`,
		`<option value="block" selected>`} {
		if !strings.Contains(hb, want) {
			t.Fatalf("hosts page misses %q", want)
		}
	}

	// Schalter: WAF aus, JA4 nur zaehlen
	post := func(id int64, form url.Values) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("POST", "/cdn64/hosts/"+strconv.FormatInt(id, 10)+"/protection", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		e.mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(h.ID, url.Values{"ja4": {"count"}}); rec.Code != http.StatusSeeOther || !strings.HasPrefix(flash, "success") {
		t.Fatalf("set: %d %s", rec.Code, flash)
	}
	f.mu.Lock()
	waf, ja4 := f.waf[rid], f.ja4[rid]
	f.mu.Unlock()
	if waf || ja4 != "count" {
		t.Fatalf("at ipv64: waf=%v ja4=%q", waf, ja4)
	}
	if r := e.m.onlineIndex(ctx, rowsHosts(rows))[h.ID]; r == nil || r.WAF || r.JA4 != "count" {
		t.Fatalf("row after set: %+v", r)
	}
	if rec := post(h.ID, url.Values{"waf": {"1"}, "ja4": {"block"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("set again: %d", rec.Code)
	}
	f.mu.Lock()
	waf, ja4 = f.waf[rid], f.ja4[rid]
	f.mu.Unlock()
	if !waf || ja4 != "block" {
		t.Fatalf("at ipv64 again: waf=%v ja4=%q", waf, ja4)
	}
	if rec := post(h.ID, url.Values{"ja4": {"kaputt"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad ja4: %d", rec.Code)
	}
	other := newHost()
	other.Names, other.TargetHost, other.TargetPort = []string{"local.test"}, "93.184.216.34", 8081
	if err := e.m.saveHost(ctx, other); err != nil {
		t.Fatal(err)
	}
	flash = ""
	if rec := post(other.ID, url.Values{"ja4": {"off"}}); rec.Code != http.StatusSeeOther || !strings.Contains(flash, "cdn64.online.e.not_online") {
		t.Fatalf("host without CDN64: %d %s", rec.Code, flash)
	}
	if rec := post(9999, url.Values{"ja4": {"off"}}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown host: %d", rec.Code)
	}

	// ipv64 antwortet nicht: freundliche Meldung statt 500
	f.mu.Lock()
	f.protErr = errors.New("ipv64 not reachable: timeout")
	f.mu.Unlock()
	code, d = get("?days=1")
	if code != http.StatusOK || d.Error != "t:cdn64.online.e.ipv64_unreachable" || d.P != nil {
		t.Fatalf("error page: %d %+v", code, d)
	}
	body = renderPage(t, "protection.html", d)
	if !strings.Contains(body, "cdn64.protection.unavailable") || strings.Contains(body, "data-prot=") {
		t.Fatal("error page shows figures")
	}
}

func hasTab(list []tab, path string) bool {
	for _, x := range list {
		if x.Path == path {
			return true
		}
	}
	return false
}
