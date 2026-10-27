package honeypot

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/ports"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/web"
)

// Katalog: jeder Dienst des Sensors mit Standardport drin, keine Doppelten (auch nicht Protokoll+Port), alle
// Eintraege des Profils full, sortiert nach Gruppe.
func TestCatalogBuild(t *testing.T) {
	cat := Catalog()
	have := map[string]bool{}
	seen := map[Service]bool{}
	seenPort := map[string]bool{}
	last := -1
	for _, e := range cat {
		have[e.Service] = true
		k := Service{e.Service, e.Port, e.Page}
		if seen[k] {
			t.Errorf("duplicate entry %+v", k)
		}
		seen[k] = true
		pp := e.Proto + "/" + strconv.Itoa(e.Port)
		if seenPort[pp] {
			t.Errorf("port %s twice in the catalog", pp)
		}
		seenPort[pp] = true
		if e.Port < 1 || e.Port > 65535 {
			t.Errorf("%s: no default port (add it to catalogPorts)", e.Service)
		}
		g := slices.Index(CatalogGroups, e.Group)
		if g < 0 || g < last {
			t.Errorf("%s %d: group %q out of order", e.Service, e.Port, e.Group)
		}
		last = g
		if want := string(svcProto(e.Service)); e.Proto != want {
			t.Errorf("%s: proto %s, want %s", e.Service, e.Proto, want)
		}
	}
	for _, s := range KnownServices() {
		if !have[s] || !sensorValidService(s) {
			t.Errorf("service %s missing in the catalog", s)
		}
	}
	for s := range tcpProtos {
		if !slices.Contains(KnownServices(), s) {
			t.Errorf("registered tcp service %s not known", s)
		}
	}
	for s := range udpProtos {
		if !slices.Contains(KnownServices(), s) {
			t.Errorf("registered udp service %s not known", s)
		}
	}
	for _, s := range Profiles[ProfileFull] {
		if !seen[s] {
			t.Errorf("full profile entry %+v missing", s)
		}
	}
	if !reflectEqual(Catalog(), cat) {
		t.Fatal("catalog not stable")
	}
}

func reflectEqual(a, b []CatalogEntry) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Vorlagen: jedes Profil kommt ohne eigene Zeilen in die Tabelle und wird wieder als dieses Profil erkannt;
// "none" leert alles, "free" schaltet nur freie Ports ein.
func TestCatalogPresets(t *testing.T) {
	for _, p := range []string{ProfileMinimal, ProfileStandard, ProfileFull} {
		var f catForm
		if !f.preset(p, catStates{}) {
			t.Fatalf("%s: unknown preset", p)
		}
		if len(f.Extras) != 0 {
			t.Errorf("%s: extras %+v", p, f.Extras)
		}
		sel := f.services()
		if len(sel) != len(Profiles[p]) || MatchProfile(sel) != p {
			t.Errorf("%s: selection %v matches %q", p, sel, MatchProfile(sel))
		}
		c := ModuleConfig{Profile: ProfileCustom}
		selectionConfig(&c, sel)
		if c.Profile != p {
			t.Errorf("%s: saved as %s", p, c.Profile)
		}
	}
	// Standard hat http 8123 ohne Koeder, der Katalog (full) mit Koeder: dieselbe Zeile, Koeder leer
	f := catFormFrom(Profiles[ProfileStandard])
	for i, e := range Catalog() {
		if e.Service == SvcHTTP && e.Port == 8123 && (!f.Rows[i].On || f.Rows[i].Page != "") {
			t.Fatalf("http 8123 row: %+v", f.Rows[i])
		}
	}
	// eigene Auswahl mit doppeltem Dienst: ssh 22 in der Zeile, ssh 2200 ebenfalls (Zeile ssh 2222 ist aus)
	f = catFormFrom([]Service{{SvcSSH, 22, ""}, {SvcSSH, 2200, ""}, {SvcTCP, 3390, ""}})
	sel := f.services()
	if len(sel) != 3 || MatchProfile(sel) != "" || len(f.Extras) != 1 || f.Extras[0].Port != "3390" {
		t.Fatalf("custom: %v extras %+v", sel, f.Extras)
	}
	c := ModuleConfig{Profile: ProfileStandard}
	selectionConfig(&c, sel)
	if c.Profile != ProfileCustom || len(c.Services) != 3 {
		t.Fatalf("custom saved as %+v", c)
	}
	// alle aus
	f.preset("none", catStates{})
	if len(f.services()) != 0 {
		t.Fatalf("none: %v", f.services())
	}
	// alle freien: 80/tcp offen bei edge, 161/udp eingestellt bei einem anderen Teil, 22 offen im Sensor
	st := catStates{status: []ServiceStatus{{Service: SvcSSH, Port: 22, Listen: true}},
		others: []ports.Claim{{Owner: "edge", Proto: ports.TCP, Port: 80, Active: true}, {Owner: "x", Proto: ports.UDP, Port: 161}}}
	f.preset("free", st)
	on := map[string]bool{}
	for _, r := range f.Rows {
		if r.On {
			on[r.Service+" "+r.Port] = true
		}
	}
	if on["http 80"] || on["snmp 161"] || !on["ssh 22"] || !on["https 443"] || !on["tcp 445"] {
		t.Fatalf("free: %v", on)
	}
	if f.preset("bogus", st) {
		t.Fatal("unknown preset accepted")
	}
}

// Zustand: TCP und UDP getrennt, aktiv = belegt, eingestellt = reserviert, eigener Sensor offen/Fehler.
func TestCatalogStates(t *testing.T) {
	st := catStates{
		status: []ServiceStatus{{Service: SvcSSH, Port: 22, Listen: true, Conns: 3}, {Service: SvcTelnet, Port: 23, Error: "listen tcp :23: bind: permission denied"}},
		others: []ports.Claim{{Owner: "edge", Purpose: "HTTPS", Proto: ports.TCP, Port: 443, Active: true}, {Owner: "dns64", Purpose: "DNS", Proto: ports.UDP, Port: 53, Active: true},
			{Owner: "edge", Purpose: "HTTP", Proto: ports.TCP, Port: 80}},
	}
	cases := []struct {
		svc   string
		port  int
		state string
		owner string
	}{
		{SvcSSH, 22, "open", ""},
		{SvcTelnet, 23, "error", ""},
		{SvcTCP, 22, "used", Name}, // anderer eigener Dienst auf 22/tcp
		{SvcSNMP, 22, "free", ""},  // 22/udp ist frei
		{SvcHTTPS, 443, "used", "edge"},
		{SvcSIP, 443, "free", ""}, // 443/udp
		{SvcTCP, 53, "free", ""},  // 53/tcp
		{SvcSNMP, 53, "used", "dns64"},
		{SvcHTTP, 80, "reserved", "edge"},
		{SvcHTTP, 0, "", ""},
	}
	for _, c := range cases {
		got := st.state(c.svc, c.port)
		if got.State != c.state || got.Owner != c.owner {
			t.Errorf("%s %d: %+v, want %s %s", c.svc, c.port, got, c.state, c.owner)
		}
	}
	if st.state(SvcSSH, 22).Conns != 3 {
		t.Error("conns missing")
	}
}

// Doppelte Ports: TCP und UDP getrennt (udp 161 und tcp 161 sind kein Konflikt).
func TestValidateTCPUDPPorts(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	check := func(list []Service) string {
		c := ModuleConfig{Profile: ProfileCustom, Config: Config{Services: list}}
		return m.validate(ctx, &c)["services"]
	}
	if e := check([]Service{{SvcTCP, 161, ""}, {SvcSNMP, 161, ""}, {SvcSIP, 5060, ""}, {SvcTCP, 5060, ""}}); e != "" {
		t.Fatalf("tcp+udp on one port: %s", e)
	}
	if e := check([]Service{{SvcSNMP, 161, ""}, {SvcSIP, 161, ""}}); e != "honeypot.err.port_twice|161/udp" {
		t.Fatalf("udp twice: %q", e)
	}
	if e := check([]Service{{SvcTCP, 2000, ""}, {SvcSSH, 2000, ""}}); e != "honeypot.err.port_twice|2000" {
		t.Fatalf("tcp twice: %q", e)
	}
	if e := check([]Service{{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}}); e != "" {
		t.Fatalf("ssh twice on different ports: %s", e)
	}
}

// catRender haelt fest, was Render bekommen hat.
type catRender struct {
	status int
	data   settingsData
}

func catPost(t *testing.T, m *Module, form url.Values) catRender {
	t.Helper()
	var out catRender
	m.g.Render = func(w http.ResponseWriter, _ *http.Request, status int, _, _ string, data any) {
		out.status, out.data = status, data.(settingsData)
		w.WriteHeader(status)
	}
	req := httptest.NewRequest(http.MethodPost, "/honeypot/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = req.ParseForm()
	rec := httptest.NewRecorder()
	m.pageSettingsSave(rec, req)
	if out.status == 0 {
		out.status = rec.Code
	}
	return out
}

// catFormValues baut das Formular der Tabelle (ein = Zeilen "dienst port", die eingeschaltet sind).
func catFormValues(on map[string]bool, extras ...Service) url.Values {
	v := url.Values{"catalog": {"1"}, "retention_days": {"7"}, "max_events": {"200000"}, "xn": {strconv.Itoa(len(extras))}}
	for i, e := range Catalog() {
		n := strconv.Itoa(i)
		v.Set("port_"+n, strconv.Itoa(e.Port))
		v.Set("page_"+n, e.Page)
		if on[e.Service+" "+strconv.Itoa(e.Port)] {
			v.Set("on_"+n, "1")
		}
	}
	for j, x := range extras {
		n := strconv.Itoa(j)
		v.Set("xsvc_"+n, x.Service)
		v.Set("xport_"+n, strconv.Itoa(x.Port))
		v.Set("xpage_"+n, x.Page)
	}
	return v
}

// Speichern aus der Tabelle: eigene Auswahl als custom, genau ein Profil als Profil, Vorlage ohne Speichern,
// Textliste (Erweitert), belegter Port als Fehler mit Zustand.
func TestCatalogSave(t *testing.T) {
	web := modFreePort(t)
	m, _ := modTest(t, web)
	ctx := context.Background()

	// eigene Auswahl: ssh in der Zeile (Port geaendert) und ein zweiter ssh als eigene Zeile
	p1, p2 := modFreePort(t), modFreePort(t)
	v := catFormValues(map[string]bool{"ssh 22": true, "ssh 2222": true}, Service{SvcSSH, p2, ""})
	for i, e := range Catalog() {
		if e.Service == SvcSSH && e.Port == 22 {
			v.Set("port_"+strconv.Itoa(i), strconv.Itoa(p1))
		}
	}
	if r := catPost(t, m, v); r.status != http.StatusSeeOther {
		t.Fatalf("save custom: %d %v", r.status, r.data.Errors)
	}
	c := m.loadConfig(ctx)
	if c.Profile != ProfileCustom || len(c.Services) != 3 || c.Services[0] != (Service{SvcSSH, p1, ""}) || c.Services[2] != (Service{SvcSSH, p2, ""}) {
		t.Fatalf("custom: %+v", c)
	}
	// Tabelle aus der Einstellung: Zeilen ssh 22 (Port p1) und ssh 2222, p2 als eigene Zeile
	f := catFormFrom(effectiveServices(c))
	if len(f.Extras) != 1 || f.Extras[0].Port != strconv.Itoa(p2) {
		t.Fatalf("form from config: %+v", f.Extras)
	}

	// genau Minimal: als Profil gespeichert
	if r := catPost(t, m, catFormValues(map[string]bool{"ssh 22": true, "http 80": true})); r.status != http.StatusSeeOther {
		t.Fatalf("save minimal: %d %v", r.status, r.data.Errors)
	}
	if c = m.loadConfig(ctx); c.Profile != ProfileMinimal {
		t.Fatalf("minimal saved as %s", c.Profile)
	}

	// Vorlage: Tabelle gefuellt, nichts gespeichert
	v = catFormValues(nil)
	v.Set("preset", ProfileFull)
	r := catPost(t, m, v)
	if r.status != http.StatusOK || !r.data.CatUnsaved || m.loadConfig(ctx).Profile != ProfileMinimal {
		t.Fatalf("preset: %d unsaved=%v", r.status, r.data.CatUnsaved)
	}
	n := 0
	for _, row := range r.data.CatRows {
		if row.On {
			n++
		}
	}
	if n != len(Profiles[ProfileFull]) || !strings.Contains(r.data.Lines, "snmp 161") {
		t.Fatalf("preset full: %d rows on, lines %q", n, r.data.Lines)
	}
	// Zustand in der Tabelle: Port der Oberflaeche belegt, 80 bei edge eingestellt
	for _, row := range r.data.CatRows {
		if row.Service == SvcHTTP && row.Port == "80" && (row.State != "reserved" || row.OwnerName == "") {
			t.Fatalf("http 80 state: %+v", row)
		}
	}
	if r.data.UIPorts != strconv.Itoa(web) {
		t.Fatalf("ui ports: %q", r.data.UIPorts)
	}

	// eigene Auswahl auf dem Port der Oberflaeche: Fehler am Feld, Zeile zeigt "belegt"
	r = catPost(t, m, catFormValues(nil, Service{SvcTCP, web, ""}))
	if r.status != http.StatusUnprocessableEntity || !strings.Contains(r.data.Errors["services"], "honeypot.err.port_used") {
		t.Fatalf("conflict: %d %v", r.status, r.data.Errors)
	}
	if len(r.data.CatExtras) == 0 || r.data.CatExtras[0].State != "used" || r.data.CatExtras[0].Owner != "web" {
		t.Fatalf("conflict state: %+v", r.data.CatExtras)
	}

	// Textliste (Erweitert): gespeichert statt der Tabelle
	p3 := modFreePort(t)
	v = catFormValues(map[string]bool{"ssh 22": true})
	v.Set("use_text", "1")
	v.Set("services", "tcp "+strconv.Itoa(p3)+"\nsnmp 161\ntcp 161\n")
	if r = catPost(t, m, v); r.status != http.StatusSeeOther {
		t.Fatalf("text: %d %v", r.status, r.data.Errors)
	}
	if c = m.loadConfig(ctx); c.Profile != ProfileCustom || len(c.Services) != 3 {
		t.Fatalf("text saved: %+v", c)
	}

	// alles aus: Fehler (mindestens ein Dienst)
	if r = catPost(t, m, catFormValues(nil)); r.status != http.StatusUnprocessableEntity || r.data.Errors["services"] == "" {
		t.Fatalf("empty: %d", r.status)
	}

	// Vorlage "Nur ueber PROXY64": Tabelle leer, Hinweis mit Merker; gespeichert als Profil proxy (ohne Dienste)
	v = catFormValues(nil)
	v.Set("preset", ProfileProxy)
	if r = catPost(t, m, v); r.status != http.StatusOK || r.data.Cfg.Profile != ProfileProxy {
		t.Fatalf("preset proxy: %d %s", r.status, r.data.Cfg.Profile)
	}
	v = catFormValues(nil)
	v.Set("proxy_only", "1")
	if r = catPost(t, m, v); r.status != http.StatusSeeOther {
		t.Fatalf("save proxy: %d %v", r.status, r.data.Errors)
	}
	if c = m.loadConfig(ctx); c.Profile != ProfileProxy || len(effectiveServices(c)) != 0 {
		t.Fatalf("proxy saved: %+v", c)
	}
	// Dienst eingeschaltet: wird eigene Auswahl bzw. Profil, Merker zaehlt nicht
	v = catFormValues(map[string]bool{"ssh 22": true, "http 80": true})
	v.Set("proxy_only", "1")
	if r = catPost(t, m, v); r.status != http.StatusSeeOther || m.loadConfig(ctx).Profile != ProfileMinimal {
		t.Fatalf("services win over proxy: %d %s", r.status, m.loadConfig(ctx).Profile)
	}
}

// GET /api/honeypot/catalog: Katalog mit Auswahl und Zustand.
func TestCatalogAPI(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	if _, err := m.SaveConfig(ctx, ModuleConfig{Profile: ProfileCustom, Config: Config{Services: []Service{{SvcSSH, 22, ""}, {SvcSSH, 2222, ""}, {SvcSSH, 2200, ""}}}}); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	m.apiCatalog(rec, httptest.NewRequest(http.MethodGet, "/api/honeypot/catalog", nil))
	var info CatalogInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &info); err != nil || rec.Code != 200 {
		t.Fatalf("%d %v", rec.Code, err)
	}
	if info.Profile != ProfileCustom || len(info.Entries) != len(Catalog()) || len(info.Extra) != 1 || info.Extra[0].Port != 2200 || len(info.Presets) != 3 {
		t.Fatalf("info: %+v", info)
	}
	for _, e := range info.Entries {
		switch {
		case e.Service == SvcSSH && e.Port == 22 && !e.On:
			t.Fatal("ssh 22 not on")
		case e.Service == SvcHTTP && e.Port == 80 && (e.On || e.State != "reserved" || e.Owner != "edge"):
			t.Fatalf("http 80: %+v", e)
		case e.Description == "":
			t.Fatalf("no description: %+v", e)
		}
	}
}

// Seite im echten Layout: Tabelle, Vorlagen, Hinweis, Textliste; alle Schluessel (auch die dynamischen des
// Katalogs) in den Sprachdateien oder in docs/tmp-*i18n*.json.
func TestCatalogPageRender(t *testing.T) {
	st, dir := modCore(t)
	logger := logging.New("error", "text", io.Discard)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	m := New(st, logger.Slog(), dir, "test")
	m.newSensor = func(*slog.Logger, string) sensorAPI { return &modFakeSensor{lns: map[int]net.Listener{}} }
	reg := module.NewRegistry(st, logger.Slog())
	reg.Register(m)
	t.Cleanup(reg.StopAll)
	s, err := web.New(web.Deps{Cfg: &config.Config{DataDir: dir, HTTPPort: 8080, LogLevel: "error"}, Store: st, Log: logger, I18n: bundle, Modules: reg,
		Sync: nodesync.NoOp{}, Version: "test", StartedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(path string, form url.Values) (int, string) {
		var resp *http.Response
		var err error
		if form == nil {
			resp, err = client.Get(srv.URL + path)
		} else {
			resp, err = client.PostForm(srv.URL+path, form)
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	_, body := do("/setup", nil)
	csrf := csrfRe.FindStringSubmatch(body)
	if csrf == nil {
		t.Fatal("no csrf")
	}
	if code, _ := do("/setup", url.Values{"_csrf": {csrf[1]}, "lang": {"de"}, "username": {"admin"}, "password": {"sehr geheimes passwort"},
		"password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}}); code != http.StatusSeeOther {
		t.Fatalf("setup: %d", code)
	}
	p := modFreePort(t)
	if _, err := m.SaveConfig(context.Background(), ModuleConfig{Profile: ProfileCustom, Expert: true, Config: Config{Services: []Service{{Service: SvcSSH, Port: p}}}}); err != nil {
		t.Fatal(err)
	}
	if err := reg.Enable(context.Background(), Name); err != nil {
		t.Fatal(err)
	}
	code, body := do("/honeypot/settings", nil)
	if code != 200 {
		t.Fatalf("settings: %d", code)
	}
	// Texte stehen bis zur Uebernahme nur im Fragment: Seite zeigt dann den Schluessel
	for _, want := range []string{`name="catalog"`, `name="on_0"`, `name="preset" value="free"`, `name="xsvc_0"`, `name="use_text"`, `name="page_`,
		"mikrotik-api", `value="` + strconv.Itoa(p) + `"`, "NODE64_MODE|honeypot.cat.node_hint", "Fernzugriff|honeypot.cat.group.remote"} {
		a, b, _ := strings.Cut(want, "|")
		if !strings.Contains(body, a) && (b == "" || !strings.Contains(body, b)) {
			t.Fatalf("settings: %q missing", want)
		}
	}
	csrf = csrfRe.FindStringSubmatch(body)
	v := catFormValues(nil)
	v.Set("_csrf", csrf[1])
	v.Set("preset", ProfileFull)
	if code, body = do("/honeypot/settings", v); code != 200 || !strings.Contains(body, "snmp 161") || !strings.Contains(body, "UDP") {
		t.Fatalf("preset: %d", code)
	}
	v.Del("preset")
	if code, _ = do("/honeypot/settings", v); code != http.StatusUnprocessableEntity {
		t.Fatalf("empty selection: %d", code)
	}
	if code, body = do("/api/honeypot/catalog", nil); code != 200 || !strings.Contains(body, `"entries"`) || !strings.Contains(body, `"state":"open"`) {
		t.Fatalf("api: %d", code)
	}

	// einfacher Modus: umschalten, Vorlagen mit den Ports fuer den Router, Startseite; Meldung an ipv64 ohne Key unveraendert
	if code, _ = do("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "ui_mode": {"simple"}}); code != http.StatusSeeOther || m.loadConfig(context.Background()).Expert {
		t.Fatalf("mode simple: %d", code)
	}
	if code, body = do("/honeypot/settings", nil); code != 200 || !strings.Contains(body, "data-hp-simple") || strings.Contains(body, `name="catalog"`) ||
		!strings.Contains(body, `id="sp-custom" value="custom" checked`) || !strings.Contains(body, "22/tcp") || !strings.Contains(body, "161/udp") ||
		!strings.Contains(body, `<option value="gateway" selected>`) || !strings.Contains(body, `id="local_block" name="local_block" value="1" checked`) {
		t.Fatalf("simple view: %d %s", code, body)
	}
	if code, _ = do("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "simple": {"1"}, "profile": {ProfileMinimal}, "start_page": {"bunt"}}); code != http.StatusUnprocessableEntity {
		t.Fatalf("simple invalid start page: %d", code)
	}
	before := m.loadConfig(context.Background())
	if code, _ = do("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "simple": {"1"}, "profile": {ProfileMinimal}, "start_page": {StartNeutral}, "notify_new": {"1"}}); code != http.StatusSeeOther {
		t.Fatalf("simple save: %d", code)
	}
	if c := m.loadConfig(context.Background()); c.Profile != ProfileMinimal || c.StartPage != StartNeutral || !c.NotifyNew || c.Report != before.Report || c.Expert ||
		c.RetentionDays != before.RetentionDays || !c.NoLocalBlock {
		t.Fatalf("simple saved: %+v", c)
	}
	// Haken "Erkannte Angreifer in PROXY64 sperren" (Standard an, hier zuletzt ohne Haken gespeichert)
	if code, _ = do("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "simple": {"1"}, "profile": {ProfileMinimal}, "start_page": {StartNeutral}, "local_block": {"1"}}); code != http.StatusSeeOther || m.loadConfig(context.Background()).NoLocalBlock {
		t.Fatalf("simple local block: %d", code)
	}
	if code, _ = do("/honeypot/settings", url.Values{"_csrf": {csrf[1]}, "ui_mode": {"expert"}}); code != http.StatusSeeOther || !m.loadConfig(context.Background()).Expert {
		t.Fatalf("mode expert: %d", code)
	}
	if _, body = do("/honeypot/settings", nil); !strings.Contains(body, `name="catalog"`) || !strings.Contains(body, `<option value="neutral" selected>`) {
		t.Fatal("expert view after switch")
	}

	// dynamische Schluessel des Katalogs
	tmp := map[string]map[string]string{"de": {}, "en": {}}
	frags, _ := filepath.Glob(filepath.Join("..", "..", "docs", "tmp-*i18n*.json"))
	for _, name := range frags {
		b, err := os.ReadFile(name)
		if err != nil {
			continue
		}
		var x map[string]map[string]string
		if err := json.Unmarshal(b, &x); err != nil {
			t.Fatalf("tmp i18n %s: %v", name, err)
		}
		for lang, kv := range x {
			if tmp[lang] == nil {
				tmp[lang] = map[string]string{}
			}
			for k, val := range kv {
				tmp[lang][k] = val
			}
		}
	}
	keys := map[string]bool{"honeypot.owner." + Name: true}
	for _, g := range CatalogGroups {
		keys["honeypot.cat.group."+g] = true
	}
	for _, pr := range catPresets {
		keys["honeypot.cat.preset."+pr] = true
	}
	for _, e := range Catalog() {
		keys[e.DescKey] = true
	}
	for _, s := range KnownServices() {
		keys[catalogDesc(Service{Service: s})] = true
	}
	for _, pg := range Pages {
		keys[catalogDesc(Service{Service: SvcHTTP, Page: pg})] = true
	}
	for k := range keys {
		for _, lang := range []string{"de", "en"} {
			if bundle.T(lang, k) == k && tmp[lang][k] == "" {
				t.Errorf("%s: missing i18n key %s", lang, k)
			}
		}
	}
}
