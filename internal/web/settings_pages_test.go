package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/netstat"
	"github.com/ipv64net/node64/internal/ports"
)

// fakePorts: Port-Verwaltung mit Claims wie aus den Modulen (Oberflaeche, Eingang, DNS64, Honeypot, Streams, Tunnel).
func fakePorts() *ports.Registry {
	reg := ports.New()
	reg.Provide("web", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "HTTP", Proto: ports.TCP, Port: 8080, Active: true}}
	})
	reg.Provide("edge", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "HTTP", Proto: ports.TCP, Port: 80}, {Purpose: "HTTPS", Proto: ports.TCP, Port: 443, Active: true},
			{Purpose: "HTTP/3", Proto: ports.UDP, Port: 443, Active: true}}
	})
	reg.Provide("dns64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "DNS", Proto: ports.UDP, Port: 53, Active: true}, {Purpose: "DNS", Proto: ports.TCP, Port: 53, Active: true},
			{Purpose: "DoT", Proto: ports.TCP, Port: 853, Error: "listen tcp :853: bind: permission denied"}}
	})
	reg.Provide("honeypot", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "Honeypot SNMP", Proto: ports.UDP, Port: 161, Active: true},
			{Purpose: "Honeypot SSH", Proto: ports.TCP, Port: 2222},                                // nur eingestellt, aber von einem anderen Programm offen
			{Purpose: "Honeypot DNS", Proto: ports.UDP, Port: 53, Error: "address already in use"}} // will 53/udp wie DNS64
	})
	reg.ProvideOutbound("cdn64", func(context.Context) []ports.Claim {
		return []ports.Claim{{Purpose: "CDN64 online srv07", Proto: ports.UDP, Port: 7844, Bind: "srv07.cdn64.de", Active: true}}
	})
	return reg
}

func fakeListeners(t *testing.T, list []netstat.Listener, ok bool) {
	t.Helper()
	old, oldP := listenerSource, privilegeSource
	listenerSource = func() ([]netstat.Listener, bool) { return list, ok }
	privilegeSource = func() netstat.Privileges {
		return netstat.Privileges{Known: true, UnprivStart: 1024, Container: true} // weder root noch Faehigkeit
	}
	t.Cleanup(func() { listenerSource, privilegeSource = old, oldP })
}

func TestPortsPageData(t *testing.T) {
	a := newTestApp(t)
	a.s.Ports = fakePorts()
	any4 := netip.MustParseAddr("0.0.0.0")
	fakeListeners(t, []netstat.Listener{{Proto: "tcp", Addr: any4, Port: 8080}, {Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 443},
		{Proto: "udp", Addr: any4, Port: 53}, {Proto: "tcp", Addr: any4, Port: 2222}}, true)
	d := a.s.portsPageData(context.Background(), "", "")
	find := func(owner, purpose string, proto ports.Proto) portRow {
		for _, r := range d.Rows {
			if r.Owner == owner && r.Purpose == purpose && r.Proto == proto {
				return r
			}
		}
		t.Fatalf("row %s %s %s missing: %+v", owner, purpose, proto, d.Rows)
		return portRow{}
	}
	if r := find("web", "HTTP", ports.TCP); r.Open != "yes" || r.Mod.TitleKey != "ports.owner_web" {
		t.Fatalf("web: %+v", r)
	}
	if r := find("edge", "HTTP/3", ports.UDP); r.Open != "no" { // 443/udp lauscht nicht
		t.Fatalf("http3: %+v", r)
	}
	if r := find("dns64", "DoT", ports.TCP); r.Error == "" || !r.Low || !r.LowDenied || r.Open != "no" {
		t.Fatalf("dot: %+v", r)
	}
	if r := find("honeypot", "Honeypot DNS", ports.UDP); len(r.Conflicts) != 1 || r.Conflicts[0] != "dns64 (DNS)" {
		t.Fatalf("conflict: %+v", r)
	}
	if r := find("dns64", "DNS", ports.UDP); len(r.Conflicts) != 1 || r.Foreign {
		t.Fatalf("dns conflict: %+v", r)
	}
	if r := find("honeypot", "Honeypot SSH", ports.TCP); !r.Foreign {
		t.Fatalf("2222 open by another program: %+v", r)
	}
	if r := find("cdn64", "CDN64 online srv07", ports.UDP); r.Kind != "out" || r.Open != "" {
		t.Fatalf("outbound: %+v", r)
	}
	if r := find("metrics", "Prometheus /api/metrics", ports.TCP); r.Kind != "via" || r.Port != 8080 {
		t.Fatalf("metrics via web port: %+v", r)
	}
	if d.Conflicts != 2 || d.Errors != 2 || !d.LowDenied || !strings.Contains(d.DockerArgs, "-p 53:53/udp") || !strings.Contains(d.DockerArgs, "-p 443:443/udp") {
		t.Fatalf("summary: conflicts=%d errors=%d low=%v docker=%q", d.Conflicts, d.Errors, d.LowDenied, d.DockerArgs)
	}
	// Filter
	if f := a.s.portsPageData(context.Background(), "", "conflict"); len(f.Rows) != 2 {
		t.Fatalf("filter conflict: %+v", f.Rows)
	}
	if f := a.s.portsPageData(context.Background(), "honeypot", ""); len(f.Rows) != 3 {
		t.Fatalf("filter module: %+v", f.Rows)
	}
	if f := a.s.portsPageData(context.Background(), "", "out"); len(f.Rows) != 1 || f.Rows[0].Owner != "cdn64" {
		t.Fatalf("filter out: %+v", f.Rows)
	}
	// ohne /proc (Windows, macOS): unbekannt
	fakeListeners(t, nil, false)
	if r := a.s.portsPageData(context.Background(), "web", "").Rows[0]; r.Open != "unknown" {
		t.Fatalf("unknown: %+v", r)
	}
}

func TestSettingsPages(t *testing.T) {
	a := newTestApp(t)
	a.s.Ports = fakePorts()
	fakeListeners(t, []netstat.Listener{{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080}}, true)
	loginAs(t, a, "admin", "sehr geheimes passwort")

	resp, body := a.get(t, "/settings")
	if resp.StatusCode != 200 {
		t.Fatalf("settings: %d", resp.StatusCode)
	}
	for _, want := range []string{`id="reach"`, `action="/settings/reach"`, `id="logging"`, `id="about"`,
		`data-from="backup" data-to="/settings/data#backup"`, `data-from="ports" data-to="/settings/ports"`, `data-from="reset" data-to="/settings/data#reset"`,
		`data-from="modules" data-to="/settings/modules"`, `href="/settings/ports"`, `href="/settings/data"`, `href="/settings/modules"`} {
		if !strings.Contains(body, want) {
			t.Errorf("settings lacks %s", want)
		}
	}
	for _, gone := range []string{`action="/settings/backup"`, `action="/settings/reset"`, `action="/settings/edge"`, `action="/settings/data"`, `action="/settings/modules"`} {
		if strings.Contains(body, gone) {
			t.Errorf("settings still has %s", gone)
		}
	}
	csrf := csrfOf(t, body)

	// Module: eigene Seite mit Beschreibung, zwei Highlights, Schalter mit Rueckfrage beim Ausschalten
	resp, body = a.get(t, "/settings/modules")
	if resp.StatusCode != 200 {
		t.Fatalf("modules: %d", resp.StatusCode)
	}
	for _, want := range []string{`id="modules"`, `class="nav-link active" href="/settings/modules"`} {
		if !strings.Contains(body, want) {
			t.Errorf("modules page lacks %s", want)
		}
	}
	if strings.Contains(body, "modinfo.") || strings.Contains(body, "module-changelog") {
		t.Error("modules page: untranslated text or changelog")
	}

	resp, body = a.get(t, "/settings/data")
	if resp.StatusCode != 200 {
		t.Fatalf("data: %d", resp.StatusCode)
	}
	for _, want := range []string{`id="retention"`, `id="backup"`, `id="restore"`, `id="export"`, `id="import"`, `id="reset"`, `name="audit_days"`,
		`action="/settings/data"`, `action="/settings/backup"`, `action="/settings/restore"`, `action="/settings/export"`, `action="/settings/import"`, `action="/settings/reset"`} {
		if !strings.Contains(body, want) {
			t.Errorf("data page lacks %s", want)
		}
	}

	resp, body = a.get(t, "/settings/ports")
	if resp.StatusCode != 200 {
		t.Fatalf("ports: %d", resp.StatusCode)
	}
	for _, want := range []string{`id="ports"`, `data-owner="honeypot"`, `data-kind="out"`, `table-danger`, `address already in use`, `id="hints"`, `-p 53:53/udp`} {
		if !strings.Contains(body, want) {
			t.Errorf("ports page lacks %s", want)
		}
	}
	if _, body = a.get(t, "/settings/ports?state=conflict"); strings.Contains(body, `data-kind="out"`) || !strings.Contains(body, `data-owner="dns64"`) {
		t.Error("filter state=conflict")
	}

	// Formulare leiten auf die neuen Seiten zurueck
	resp, _ = a.post(t, "/settings/data", url.Values{"_csrf": {csrf}, "raw_days": {"30"}, "hourly_days": {"365"}, "chart_detail": {"standard"}, "audit_days": {"90"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/settings/data#retention" {
		t.Fatalf("data save: %d %s", resp.StatusCode, loc)
	}
	if got := AuditDays(a.store); got != 90 {
		t.Fatalf("audit days: %d", got)
	}
	resp, _ = a.post(t, "/settings/data", url.Values{"_csrf": {csrf}, "raw_days": {"30"}, "hourly_days": {"365"}, "chart_detail": {"standard"}, "audit_days": {"5"}})
	if AuditDays(a.store) != 90 || resp.Header.Get("Location") != "/settings/data#retention" {
		t.Fatal("invalid audit days must not be saved")
	}
	resp, _ = a.post(t, "/settings/reset", url.Values{"_csrf": {csrf}, "password": {"falsch"}})
	if loc := resp.Header.Get("Location"); loc != "/settings/data#reset" {
		t.Fatalf("reset denied: %s", loc)
	}
	resp, _ = a.post(t, "/settings/export", url.Values{"_csrf": {csrf}, "secrets": {"password"}, "password": {"kurz"}})
	if loc := resp.Header.Get("Location"); loc != "/settings/data#export" {
		t.Fatalf("export: %s", loc)
	}
	resp, _ = a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "ui_name": {"node.example.ipv64.de"}, "ui_cert": {"auto"}})
	if loc := resp.Header.Get("Location"); loc != "/settings#reach" || a.store.SettingOr(context.Background(), setUIName, "") != "node.example.ipv64.de" {
		t.Fatalf("reach: %s", loc)
	}
	resp, _ = a.post(t, "/settings/reach", url.Values{"_csrf": {csrf}, "ui_cert": {"self"}}) // ohne Namensfeld: Name bleibt
	if a.store.SettingOr(context.Background(), setUIName, "") != "node.example.ipv64.de" || a.store.SettingOr(context.Background(), setUICert, "") != "self" {
		t.Fatal("reach without name field must keep the name")
	}
}

func TestSettingsNav(t *testing.T) {
	a := newTestAppWith(t, module.Placeholder{I: module.Info{Name: "x", TitleKey: "nav.x", Path: "/x"}})
	active := func(path string) []string {
		r := httptest.NewRequest("GET", path, nil)
		var out []string
		for _, n := range a.s.nav(r) {
			if n.Active {
				out = append(out, n.Key)
			}
		}
		return out
	}
	for path, want := range map[string]string{"/settings": "nav.settings_general", "/settings/2fa": "nav.settings_general",
		"/settings/modules": "nav.settings_modules", "/settings/ports": "nav.settings_ports", "/settings/data": "nav.settings_data", "/healthchecks/status-pages": "", "/audit": "nav.audit"} {
		got := active(path)
		if want == "" {
			continue
		}
		if len(got) != 1 || got[0] != want {
			t.Errorf("%s: active %v, want %s", path, got, want)
		}
	}
	var subs []string
	for _, n := range a.s.nav(httptest.NewRequest("GET", "/", nil)) {
		if n.Sub && strings.HasPrefix(n.Path, "/settings") {
			subs = append(subs, n.Key)
		}
	}
	if strings.Join(subs, ",") != "nav.settings_general,nav.settings_modules,nav.settings_ports,nav.settings_data" {
		t.Fatalf("settings submenu: %v", subs)
	}
}

// Seite Module mit einem verfuegbaren Modul: Beschreibung, zwei Highlights, Schalter mit Rueckfrage, kein Changelog.
func TestSettingsModulesPage(t *testing.T) {
	a := newTestAppDeps(t, nil, hcModule{})
	loginAs(t, a, "admin", "sehr geheimes passwort")
	resp, body := a.get(t, "/settings/modules")
	if resp.StatusCode != 200 || !strings.Contains(body, `name="action" value="enable"`) {
		t.Fatalf("modules: %d", resp.StatusCode)
	}
	resp, _ = a.post(t, "/settings/modules", url.Values{"_csrf": {csrfOf(t, body)}, "module": {"healthchecks"}, "action": {"enable"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/modules" {
		t.Fatalf("enable: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = a.get(t, "/settings/modules")
	for _, want := range []string{`id="module-healthchecks"`, `action="/settings/modules"`, `href="/healthchecks"`, `data-confirm=`,
		"Statusseiten, Wartungsfenster"} {
		if !strings.Contains(body, want) {
			t.Errorf("modules page lacks %s", want)
		}
	}
	if strings.Contains(body, "modinfo.") || strings.Contains(body, "module-changelog") {
		t.Error("untranslated text or changelog")
	}
	csrf := csrfOf(t, body)
	resp, _ = a.post(t, "/settings/modules", url.Values{"_csrf": {csrf}, "module": {"healthchecks"}, "action": {"disable"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/modules" {
		t.Fatalf("disable: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}
