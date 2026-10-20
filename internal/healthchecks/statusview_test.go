package healthchecks

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
)

// newStatusModule: Modul mit Store und Routen, ohne Scheduler (Laufzeitzustand kommt aus der DB, keine Verdichtung
// nebenher).
func newStatusModule(t *testing.T) (*Module, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	m := New(core, log, nil, nil, "test")
	if err := core.Migrate(context.Background(), Name, m.Migrations()); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	pass := func(h http.Handler) http.Handler { return h }
	m.Routes(mux, module.Guards{Enabled: pass, Auth: pass})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return m, srv
}

const statusSecretTarget = "http://geheim-ziel.example:8443/intern"

func statusAddCheck(t *testing.T, m *Module, name string, rt scheduler.Runtime) *Check {
	t.Helper()
	c := &Check{Token: NewToken(), Type: checks.TypeHTTP, Name: name, Target: statusSecretTarget, Params: json.RawMessage("{}"), Interval: time.Minute,
		RetryInterval: 20 * time.Second, ConnectTimeout: time.Second, TotalTimeout: 2 * time.Second, Stabilize: 1, IPMode: checks.IPAuto}
	ctx := context.Background()
	if err := m.st.Insert(ctx, c); err != nil {
		t.Fatal(err)
	}
	if rt.LastMessage == "" {
		rt.LastMessage = "dial tcp 10.1.2.3:8443: connection refused"
	}
	if err := m.st.SaveRuntime(ctx, c.Token, rt); err != nil {
		t.Fatal(err)
	}
	return c
}

func statusMeasure(t *testing.T, m *Module, token string, at time.Time, up bool, flags int) {
	t.Helper()
	if _, err := m.st.w.Exec(`INSERT INTO hc_measurements (token, time, status, latency_ms, message, flags) VALUES (?,?,?,?,?,?)`,
		token, ft(at), b2i(up), 12.5, "raw message 10.1.2.3", flags); err != nil {
		t.Fatal(err)
	}
}

func statusDaily(t *testing.T, m *Module, token, day string, count, up int) {
	t.Helper()
	if _, err := m.st.w.Exec(`INSERT INTO hc_daily (token, day, count, up_count, min_ms, avg_ms, max_ms) VALUES (?,?,?,?,1,2,3)`, token, day, count, up); err != nil {
		t.Fatal(err)
	}
}

func statusIncident(t *testing.T, m *Module, token string, from, to time.Time) {
	t.Helper()
	id, err := m.st.OpenIncident(context.Background(), token, from, checks.ReasonConnectFailed, "connect 10.1.2.3:8443 refused")
	if err != nil {
		t.Fatal(err)
	}
	if !to.IsZero() {
		if err := m.st.CloseIncident(context.Background(), id, to); err != nil {
			t.Fatal(err)
		}
	}
}

func statusSavePage(t *testing.T, m *Module, p *StatusPage, hash string) *StatusPage {
	t.Helper()
	if err := m.st.SaveStatusPage(context.Background(), p, hash); err != nil {
		t.Fatal(err)
	}
	got, err := m.st.StatusPage(context.Background(), p.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// statusFixNow stellt die Uhr der Berechnung fest (Europe/Berlin, 20.10.2026 10:00 = 08:00 UTC).
func statusFixNow(t *testing.T, m *Module) time.Time {
	t.Helper()
	if err := m.core.SetSetting(context.Background(), "node.timezone", "Europe/Berlin"); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	old := statusNow
	statusNow = func() time.Time { return now }
	t.Cleanup(func() { statusNow = old })
	return now
}

func TestStatusDayBars(t *testing.T) {
	m, _ := newStatusModule(t)
	now := statusFixNow(t, m)
	upRT := scheduler.Runtime{State: scheduler.StateUp, Since: now.Add(-time.Hour), LastCheck: now.Add(-30 * time.Second)}
	a := statusAddCheck(t, m, "A intern", upRT)
	b := statusAddCheck(t, m, "B intern", upRT)
	empty := statusAddCheck(t, m, "C leer", scheduler.Runtime{State: scheduler.StatePending})

	// aeltere Tage aus hc_daily
	statusDaily(t, m, a.Token, "2026-10-17", 100, 100)  // up
	statusDaily(t, m, a.Token, "2026-10-16", 100, 90)   // down (90 %)
	statusDaily(t, m, a.Token, "2026-10-15", 1000, 999) // partial
	statusDaily(t, m, a.Token, "2026-07-01", 100, 0)    // vor dem Zeitraum: zaehlt nicht
	// 18.10. 23:30 Ortszeit: gehoert zum 18. (aelter als gestern -> nur hc_daily, dort nichts) -> none
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 18, 21, 30, 0, 0, time.UTC), false, 0)
	// gestern (19.10. Ortszeit): 00:30 Ortszeit down, dazu 19 up -> 95 % -> partial
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 18, 22, 30, 0, 0, time.UTC), false, 0)
	for i := 0; i < 19; i++ {
		statusMeasure(t, m, a.Token, time.Date(2026, 10, 19, 12, i, 0, 0, time.UTC), true, 0)
	}
	// heute (20.10. Ortszeit, ab 19.10. 22:00 UTC): up; Messung in Wartung zaehlt nicht
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 19, 22, 30, 0, 0, time.UTC), true, 0)
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 20, 7, 0, 0, 0, time.UTC), true, 0)
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 20, 7, 1, 0, 0, time.UTC), false, FlagMaintenance)
	// B: Stoerung von 20 min am 17.10. ohne Messungen -> down; 5 min am 12.10. mit guten Messungen -> partial
	statusIncident(t, m, b.Token, time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 17, 10, 20, 0, 0, time.UTC))
	statusIncident(t, m, b.Token, time.Date(2026, 10, 12, 10, 0, 0, 0, time.UTC), time.Date(2026, 10, 12, 10, 5, 0, 0, time.UTC))
	statusDaily(t, m, b.Token, "2026-10-12", 100, 100)

	p := statusSavePage(t, m, &StatusPage{Slug: "bars", Title: "Bars", Enabled: true, Days: 90, ShowHistory: true, Groups: []StatusGroup{
		{Name: "G", Items: []StatusItem{{Token: a.Token, Label: "Web"}, {Token: b.Token}, {Token: empty.Token}}}}}, "")
	v, err := m.statusView(context.Background(), p, "de")
	if err != nil {
		t.Fatal(err)
	}
	items := v.Groups[0].Items
	if len(items) != 3 || items[0].Label != "Web" || items[1].Label != "B intern" {
		t.Fatalf("items: %+v", items)
	}
	bars := items[0].Bars
	if len(bars) != 90 {
		t.Fatalf("bars: %d", len(bars))
	}
	first := time.Date(2026, 10, 20-89, 0, 0, 0, 0, time.UTC).Format("2006-01-02")
	if bars[0].Day != first || bars[89].Day != "2026-10-20" {
		t.Fatalf("days: %s .. %s (want %s)", bars[0].Day, bars[89].Day, first)
	}
	want := map[int]string{89: "up", 88: "partial", 87: "none", 86: "up", 85: "down", 84: "partial", 0: "none"}
	for i, s := range want {
		if bars[i].State != s {
			t.Errorf("bar %d (%s): %s, want %s (%+v)", i, bars[i].Day, bars[i].State, s, bars[i])
		}
	}
	if bars[88].Uptime != 95 || bars[89].Uptime != 100 || bars[87].Uptime != -1 {
		t.Errorf("uptime: %v %v %v", bars[88].Uptime, bars[89].Uptime, bars[87].Uptime)
	}
	// 100+100+90+1000+999+... : 19+2+100+90+999 von 20+2+100+100+1000
	if got := items[0].Uptime; got != statusPct(statusAgg{count: 1222, up: 1210}) {
		t.Errorf("item uptime %v", got)
	}
	bb := items[1].Bars
	if bb[86].State != "down" || bb[86].DownMins != 20 || bb[81].State != "partial" || bb[81].DownMins != 5 {
		t.Errorf("incident bars: %+v %+v", bb[86], bb[81])
	}
	if items[2].State != "unknown" || items[2].Uptime != -1 || items[2].Bars[89].State != "none" {
		t.Errorf("empty item: %+v", items[2])
	}
	if v.Overall != "up" || v.Groups[0].Overall != "up" {
		t.Errorf("overall %s/%s", v.Overall, v.Groups[0].Overall)
	}
	if len(v.Incidents) != 2 || v.Incidents[0].Item != "B intern" || v.Incidents[0].Reason == "" || strings.Contains(v.Incidents[0].Reason, "10.1.2.3") {
		t.Errorf("incidents: %+v", v.Incidents)
	}
}

func TestStatusRules(t *testing.T) {
	for _, c := range []struct {
		states []string
		want   string
	}{
		{nil, "unknown"},
		{[]string{"paused", "unknown"}, "unknown"},
		{[]string{"up", "unknown", "paused"}, "up"},
		{[]string{"up", "maintenance"}, "maintenance"},
		{[]string{"up", "maintenance", "degraded"}, "degraded"},
		{[]string{"up", "partial"}, "degraded"},
		{[]string{"degraded", "down", "maintenance"}, "down"},
	} {
		if got := statusOverall(c.states); got != c.want {
			t.Errorf("overall %v: %s, want %s", c.states, got, c.want)
		}
	}
	for _, c := range []struct {
		a     statusAgg
		down  int
		maint bool
		want  string
	}{
		{statusAgg{}, 0, false, "none"},
		{statusAgg{}, 0, true, "maintenance"},
		{statusAgg{}, 3, false, "partial"},
		{statusAgg{}, 15, false, "down"},
		{statusAgg{100, 100}, 0, false, "up"},
		{statusAgg{100, 99}, 0, false, "partial"},
		{statusAgg{100, 94}, 0, false, "down"},
		{statusAgg{100, 99}, 0, true, "maintenance"},
		{statusAgg{100, 50}, 0, true, "down"},
	} {
		if got := statusBucket("d", c.a, c.down, c.maint).State; got != c.want {
			t.Errorf("bucket %+v %d %v: %s, want %s", c.a, c.down, c.maint, got, c.want)
		}
	}
	tr := func(k string, _ ...any) string {
		if k == "hc.reasons.timeout" {
			return "Zeitueberschreitung"
		}
		return k
	}
	if statusReason(tr, "timeout") != "Zeitueberschreitung" || statusReason(tr, "neu") != "hc.status.pub.reason_other" || statusReason(tr, "ok") != "" {
		t.Error("reason texts")
	}
	if statusPct(statusAgg{100000, 99999}) != 99.99 || statusPct(statusAgg{3, 2}) != 66.66 {
		t.Error("pct must round down")
	}

	m, _ := newStatusModule(t)
	now := time.Now()
	for _, c := range []struct {
		rt    scheduler.Runtime
		maint bool
		want  string
	}{
		{scheduler.Runtime{State: scheduler.StateUp, LastCheck: now}, false, "up"},
		{scheduler.Runtime{State: scheduler.StateUp, LastCheck: now.Add(-time.Hour)}, false, "unknown"}, // stale
		{scheduler.Runtime{State: scheduler.StateDown, LastCheck: now}, true, "maintenance"},
		{scheduler.Runtime{State: scheduler.StateDependent, LastCheck: now}, false, "down"},
		{scheduler.Runtime{State: scheduler.StateFlapping, LastCheck: now}, false, "degraded"},
		{scheduler.Runtime{State: scheduler.StateStabilizing, LastCheck: now}, false, "degraded"},
		{scheduler.Runtime{State: scheduler.StatePending}, false, "unknown"},
		{scheduler.Runtime{State: scheduler.StatePaused}, true, "paused"},
	} {
		c2 := &Check{Token: "x", Interval: time.Minute, Runtime: c.rt}
		if got, _ := m.statusItemState(c2, c.maint); got != c.want {
			t.Errorf("state %s maint=%v: %s, want %s", c.rt.State, c.maint, got, c.want)
		}
	}
}

func statusGet(t *testing.T, url string, cookies ...*http.Cookie) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(b)
}

func TestStatusPublicRoutes(t *testing.T) {
	m, srv := newStatusModule(t)
	now := time.Now()
	c := statusAddCheck(t, m, "Datenbank intern", scheduler.Runtime{State: scheduler.StateDown, Since: now.Add(-time.Minute), LastCheck: now,
		LastReason: checks.ReasonConnectFailed})
	statusIncident(t, m, c.Token, now.Add(-time.Minute), time.Time{})
	statusMeasure(t, m, c.Token, now.Add(-time.Minute), false, 0)
	p := statusSavePage(t, m, &StatusPage{Slug: "oeffentlich", Title: "Öffentlich", Enabled: false, ShowHistory: true,
		Groups: []StatusGroup{{Name: "Dienste", Items: []StatusItem{{Token: c.Token, Label: "Datenbank"}}}}}, "")
	other := statusSavePage(t, m, &StatusPage{Slug: "andere", Title: "Andere", Enabled: true, PublishNode: true,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: c.Token}}}}}, "")
	site := httptest.NewServer(m.StatusSite(p.ID))
	t.Cleanup(site.Close)
	base := srv.URL + "/status/oeffentlich"

	// aus: ueberall 404
	for _, u := range []string{base, base + "/status.json", base + "/badge.svg", site.URL + "/status.json", site.URL + "/"} {
		if code, _, _ := statusGet(t, u); code != 404 {
			t.Fatalf("disabled %s: %d", u, code)
		}
	}
	// eingeschaltet ohne publish_node: Node-Port 404, eigene Website 200
	p.Enabled = true
	p = statusSavePage(t, m, p, "")
	if code, _, _ := statusGet(t, base+"/status.json"); code != 404 {
		t.Fatalf("not published: %d", code)
	}
	if code, _, _ := statusGet(t, srv.URL+"/status/gibtsnicht/status.json"); code != 404 {
		t.Fatalf("unknown slug: %d", code)
	}
	code, h, body := statusGet(t, site.URL+"/status.json")
	if code != 200 || !strings.Contains(h.Get("Cache-Control"), "max-age=30") || h.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("site status.json: %d %v %s", code, h, body)
	}
	p.PublishNode = true
	p = statusSavePage(t, m, p, "")
	code, _, body = statusGet(t, base+"/status.json")
	if code != 200 {
		t.Fatalf("published: %d %s", code, body)
	}
	// Datenschutz: weder Token noch Ziel, IP, Port oder Rohmeldung
	for _, secret := range []string{c.Token, "geheim-ziel", "8443", "10.1.2.3", "refused", "raw message", "intern"} {
		if strings.Contains(body, secret) {
			t.Fatalf("status.json leaks %q: %s", secret, body)
		}
	}
	var v StatusView
	if err := json.Unmarshal([]byte(body), &v); err != nil || v.Overall != "down" || len(v.Groups) != 1 || v.Groups[0].Items[0].Label != "Datenbank" ||
		len(v.Incidents) != 1 || v.Incidents[0].Item != "Datenbank" {
		t.Fatalf("view: %v %+v", err, v)
	}
	itemID := v.Groups[0].Items[0].ID
	// Details: nur Eintraege dieser Seite
	code, _, body = statusGet(t, base+"/item/"+strconv.FormatInt(itemID, 10))
	var d StatusItemDetail
	if code != 200 || json.Unmarshal([]byte(body), &d) != nil || d.State != "down" || len(d.Hours) != 24 || len(d.Incidents) != 1 || d.Uptime24h != 0 {
		t.Fatalf("detail: %d %s", code, body)
	}
	if strings.Contains(body, c.Token) || strings.Contains(body, "10.1.2.3") {
		t.Fatalf("detail leaks: %s", body)
	}
	if code, _, _ := statusGet(t, base+"/item/"+strconv.FormatInt(other.Groups[0].Items[0].ID, 10)); code != 404 {
		t.Fatalf("foreign item: %d", code)
	}
	// Badges und Feed
	code, h, body = statusGet(t, base+"/badge.svg")
	if code != 200 || h.Get("Content-Type") != "image/svg+xml" || !strings.Contains(body, "<svg") {
		t.Fatalf("badge: %d %v %s", code, h, body)
	}
	if code, _, _ := statusGet(t, base+"/badge/"+strconv.FormatInt(itemID, 10)+"?type=uptime"); code != 200 {
		t.Fatalf("item badge: %d", code)
	}
	if code, _, _ := statusGet(t, base+"/badge/999999"); code != 404 {
		t.Fatalf("unknown badge: %d", code)
	}
	code, h, body = statusGet(t, base+"/feed.atom")
	if code != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/atom+xml") || !strings.Contains(body, "<feed") || strings.Contains(body, "10.1.2.3") {
		t.Fatalf("feed: %d %v %s", code, h, body)
	}
	// HTML mit strenger CSP; eigene Website ebenso
	code, h, body = statusGet(t, base)
	if code != 200 || !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'nonce-") || strings.Contains(body, c.Token) {
		t.Fatalf("html: %d %v", code, h)
	}
	if code, _, _ := statusGet(t, site.URL+"/"); code != 200 {
		t.Fatalf("site html: %d", code)
	}
	if code, _, _ := statusGet(t, base+"/gibtsnicht"); code != 404 {
		t.Fatalf("unknown path: %d", code)
	}
	// gzip, wenn der Client es annimmt (selbst gesetzt: der Transport entpackt dann nicht)
	for _, u := range []string{base, base + "/status.json"} {
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		zr, zerr := gzip.NewReader(resp.Body)
		var plain []byte
		if zerr == nil {
			plain, zerr = io.ReadAll(zr)
		}
		resp.Body.Close()
		if resp.Header.Get("Content-Encoding") != "gzip" || !strings.Contains(strings.Join(resp.Header.Values("Vary"), ","), "Accept-Encoding") || zerr != nil || len(plain) == 0 {
			t.Fatalf("gzip %s: %v %v", u, resp.Header, zerr)
		}
	}
	// nur GET/HEAD (und das Login-POST)
	req, _ := http.NewRequest("DELETE", base+"/status.json", nil)
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("delete: %v %v", err, resp)
	}
	// Seitenliste fuer PROXY64
	refs := m.StatusPageRefs(context.Background())
	if len(refs) != 2 {
		t.Fatalf("refs: %+v", refs)
	}
}

func TestStatusPassword(t *testing.T) {
	m, srv := newStatusModule(t)
	c := statusAddCheck(t, m, "A", scheduler.Runtime{State: scheduler.StateUp, LastCheck: time.Now()})
	hash, _ := bcrypt.GenerateFromPassword([]byte("geheim"), bcrypt.MinCost)
	p := statusSavePage(t, m, &StatusPage{Slug: "privat", Title: "Privat", Enabled: true, PublishNode: true,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: c.Token}}}}}, string(hash))
	base := srv.URL + "/status/privat"
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	login := func(pw string) *http.Response {
		resp, err := noRedirect.PostForm(base+"/login", url.Values{"password": {pw}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}

	for _, u := range []string{base + "/status.json", base + "/badge.svg", base + "/feed.atom", base + "/item/1"} {
		if code, _, _ := statusGet(t, u); code != 401 {
			t.Fatalf("locked %s: %d", u, code)
		}
	}
	code, _, body := statusGet(t, base)
	if code != 200 || strings.Contains(body, "\"groups\"") {
		t.Fatalf("password form: %d", code)
	}
	// falsches Passwort: PRG zurueck auf die Seite mit Hinweis, kein Cookie
	if resp := login("falsch"); resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/status/privat?pw=wrong" || len(resp.Cookies()) != 0 {
		t.Fatalf("wrong password: %d %v %v", resp.StatusCode, resp.Header, resp.Cookies())
	}
	if code, _, _ := statusGet(t, base+"?pw=wrong"); code != 200 {
		t.Fatalf("form after wrong password: %d", code)
	}
	resp := login("geheim")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/status/privat" || len(resp.Cookies()) != 1 {
		t.Fatalf("login: %d %v", resp.StatusCode, resp.Header)
	}
	ck := resp.Cookies()[0]
	if !ck.HttpOnly || ck.Path != "/status/privat" || ck.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie: %+v", ck)
	}
	if code, h, _ := statusGet(t, base+"/status.json", ck); code != 200 || !strings.HasPrefix(h.Get("Cache-Control"), "private") || h.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("with cookie: %d %v", code, h)
	}
	// neues Passwort: altes Cookie ungueltig
	hash2, _ := bcrypt.GenerateFromPassword([]byte("neu"), bcrypt.MinCost)
	statusSavePage(t, m, p, string(hash2))
	if code, _, _ := statusGet(t, base+"/status.json", ck); code != 401 {
		t.Fatalf("old cookie after password change: %d", code)
	}
	// Drosselung: nach 10 Fehlversuchen 429, auch mit richtigem Passwort
	for i := 0; i < 9; i++ {
		login("falsch")
	}
	if resp := login("neu"); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("throttle: %d", resp.StatusCode)
	}
}

func TestStatusCache(t *testing.T) {
	m, _ := newStatusModule(t)
	now := statusFixNow(t, m)
	c := statusAddCheck(t, m, "A", scheduler.Runtime{State: scheduler.StateUp, LastCheck: now})
	p := statusSavePage(t, m, &StatusPage{Slug: "cache", Title: "Cache", Enabled: true, ShowHistory: true,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: c.Token}}}}}, "")
	ctx := context.Background()
	v1, _ := m.statusView(ctx, p, "de")
	v2, _ := m.statusView(ctx, p, "de")
	ven, _ := m.statusView(ctx, p, "en")
	if v1 == nil || v1 != v2 || v1 == ven {
		t.Fatal("view must be cached per page and language")
	}
	// Ankuendigung leert den Zwischenspeicher
	if _, err := m.st.AddStatusNotice(ctx, p.ID, "Wartung Router", "warning", "heute Abend"); err != nil {
		t.Fatal(err)
	}
	v3, _ := m.statusView(ctx, p, "de")
	if v3 == v1 || len(v3.Notices) != 1 || v3.Notices[0].Title != "Wartung Router" {
		t.Fatalf("flush on notice: %+v", v3.Notices)
	}
	// nach 30 s neu gerechnet
	later := now.Add(31 * time.Second)
	statusNow = func() time.Time { return later }
	if v4, _ := m.statusView(ctx, p, "de"); v4 == v3 {
		t.Fatal("view must expire after 30 s")
	}
}

func TestStatusMaintenance(t *testing.T) {
	m, _ := newStatusModule(t)
	now := statusFixNow(t, m)
	a := statusAddCheck(t, m, "A", scheduler.Runtime{State: scheduler.StateDown, LastCheck: now})
	b := statusAddCheck(t, m, "B", scheduler.Runtime{State: scheduler.StateUp, LastCheck: now})
	ctx := context.Background()
	// laufend fuer A, taeglich 2 Tage lang 18 h (deckt die Tage ueberwiegend ab); kuenftig fuer B in 3 Tagen
	if err := m.st.MaintenanceInsert(ctx, &Maintenance{Name: "Umbau", StartAt: now.Add(-50 * time.Hour), EndAt: now.Add(-32 * time.Hour), Repeat: "daily",
		RepeatUntil: now.Add(time.Hour), Tokens: []string{a.Token}, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.st.MaintenanceInsert(ctx, &Maintenance{Name: "Update", StartAt: now.Add(72 * time.Hour), EndAt: now.Add(73 * time.Hour), Tokens: []string{b.Token}, Active: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.st.MaintenanceInsert(ctx, &Maintenance{Name: "Fremd", StartAt: now.Add(-time.Hour), EndAt: now.Add(time.Hour), Tokens: []string{"anderer"}, Active: true}); err != nil {
		t.Fatal(err)
	}
	p := statusSavePage(t, m, &StatusPage{Slug: "wartung", Title: "W", Enabled: true, Days: 30,
		Groups: []StatusGroup{{Items: []StatusItem{{Token: a.Token, Label: "Alpha"}, {Token: b.Token, Label: "Beta"}}}}}, "")
	v, err := m.statusView(ctx, p, "de")
	if err != nil {
		t.Fatal(err)
	}
	ia := v.Groups[0].Items[0]
	if ia.State != "maintenance" || v.Overall != "maintenance" {
		t.Fatalf("state %s overall %s", ia.State, v.Overall)
	}
	if ia.Bars[28].State != "maintenance" || v.Groups[0].Items[1].Bars[28].State != "none" {
		t.Fatalf("maintenance bar: %+v", ia.Bars[28])
	}
	if len(v.Maintenance) != 2 || !v.Maintenance[0].Active || v.Maintenance[0].Items[0] != "Alpha" || v.Maintenance[1].Title != "Update" ||
		v.Maintenance[1].Active || v.Maintenance[1].Items[0] != "Beta" {
		t.Fatalf("maintenance: %+v", v.Maintenance)
	}
}
