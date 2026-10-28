package cdn64

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Seite Docker: Einstellungen, Zustand und Container (uebernommen mit Link, sonst der Grund).
func TestDockerPageRender(t *testing.T) {
	d := dockerData{Tabs: (&Module{}).tabs("/cdn64/docker"), On: true, Traefik: true, DefaultHost: "unix:///var/run/docker.sock", CertsOn: true,
		Cert: "http", Errors: map[string]string{"docker_host": "bad host"},
		View: dockerView{Enabled: true, Connected: true, Host: "unix:///var/run/docker.sock", Synced: time.Now(), Containers: []dockerContainerView{
			{Name: "whoami", State: "running", Source: dockerSrcNode64, Names: []string{"app.example.de"}, Target: "http://172.18.0.5:80", HostID: 7, Ignored: []string{"hsts@file"}},
			{Name: "legacy", State: "exited", Source: dockerSrcTraefik, Router: "web", Names: []string{"old.example.de"}, Problem: dockerErrRule, ProblemName: "web"},
		}}}
	body := renderPage(t, "docker.html", d)
	for _, want := range []string{`action="/cdn64/docker"`, `name="docker" id="docker_on" checked`, `name="traefik" id="docker_traefik" checked`,
		`name="docker_host"`, `placeholder="unix:///var/run/docker.sock"`, `bad host`, `value="http" selected`, `name="accept_tos"`,
		`href="/cdn64/hosts/7"`, `data-docker-container="legacy"`, "data-docker-ignored", "cdn64.docker.ignored", dockerErrRule, `cdn64.docker.state_ok`, `href="/cdn64/docker"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("docker page misses %s", want)
		}
	}
	for _, no := range []string{`value="self"`, `value="ca:`} { // eigene CA und selbst signiert gibt es hier nicht
		if strings.Contains(body, no) {
			t.Fatalf("docker page shows %s", no)
		}
	}
	d.View = dockerView{Enabled: true, Error: "permission denied"}
	if body := renderPage(t, "docker.html", d); !strings.Contains(body, "data-docker-error") || !strings.Contains(body, "permission denied") {
		t.Fatal("docker page misses the connection error")
	}
}

// Reiter Docker vor der Standardseite, CDN64 Statistik (falls da) bleibt nach den Zugriffen.
func TestDockerTab(t *testing.T) {
	tabs := (&Module{}).tabs("/cdn64/docker")
	if n := len(tabs); tabs[n-2].Path != "/cdn64/docker" || !tabs[n-2].Active || tabs[n-1].Path != "/cdn64/default" || tabs[n-3].Path != "/cdn64/log" {
		t.Fatalf("tabs: %+v", tabs)
	}
}

// Docker-Host: Abzeichen in der Liste, Felder aus den Labels gesperrt, kein Loeschen; serverseitig bleiben Namen und Ziel
// beim Speichern, Loeschen wird abgelehnt, Ausschalten geht.
func TestDockerHostUI(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	if err := e.m.core.SetSetting(ctx, setDocker, "on"); err != nil { // Schalter aus: Docker-Hosts loeschbar
		t.Fatal(err)
	}
	h := newHostKind(KindProxy)
	h.Names, h.Scheme, h.TargetHost, h.TargetPort, h.Enabled, h.DockerContainer = []string{"whoami.test"}, "http", "172.18.0.5", 80, true, "whoami"
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if got, err := e.m.host(ctx, h.ID); err != nil || got.DockerContainer != "whoami" {
		t.Fatalf("docker host not stored: %v %+v", err, got)
	}
	rows, err := e.m.rowsOf(ctx, KindProxy)
	if err != nil || len(rows) != 1 || rows[0].Docker == "" {
		t.Fatalf("rows: %v %+v", err, rows)
	}
	body := renderHosts(t, listData{Kind: KindProxy, Rows: rows})
	if !strings.Contains(body, "data-docker-badge") || !strings.Contains(body, `title="`+rows[0].Docker+`"`) {
		t.Fatal("host list misses the Docker badge")
	}
	if strings.Contains(body, "/cdn64/hosts/"+strconv.FormatInt(h.ID, 10)+"/delete") {
		t.Fatal("host list offers delete for a Docker host")
	}
	form := aiRender(t, "host_form.html", e.m.form(ctx, h, false))
	for _, want := range []string{"data-docker-host", `name="names" rows="3" required placeholder="nas.example.ipv64.de" readonly`, `name="scheme" disabled`,
		`maxlength="253" readonly`, `required readonly`} {
		if !strings.Contains(form, want) {
			t.Fatalf("host form misses %s", want)
		}
	}
	if strings.Contains(form, "/delete") {
		t.Fatal("host form offers delete for a Docker host")
	}

	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, args ...any) string { return key + fmt.Sprint(args...) }
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, _ any) { w.WriteHeader(st) }
	post := func(path string, v url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", path, strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("id", strconv.FormatInt(h.ID, 10))
		rec := httptest.NewRecorder()
		if strings.HasSuffix(path, "/delete") {
			e.m.pageDelete(rec, req)
		} else {
			e.m.pageUpdate(rec, req)
		}
		return rec
	}
	// Formular mit anderen Namen/Ziel (und ohne Schema wie beim gesperrten Feld): zaehlt nicht, der Rest schon
	rec := post("/cdn64/hosts/x", url.Values{"names": {"evil.test"}, "target_host": {"10.0.0.1"}, "target_port": {"22"}, "websockets": {"on"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("update: %d %s", rec.Code, flash)
	}
	got, _ := e.m.host(ctx, h.ID)
	if got.Names[0] != "whoami.test" || got.TargetHost != "172.18.0.5" || got.TargetPort != 80 || got.Scheme != "http" || !got.WebSockets || got.Enabled {
		t.Fatalf("after update: %+v", got)
	}
	rec = post("/cdn64/hosts/x/delete", nil)
	if rec.Code != http.StatusSeeOther || !strings.Contains(flash, "cdn64.docker.err.delete") {
		t.Fatalf("delete: %d %q", rec.Code, flash)
	}
	if _, err := e.m.host(ctx, h.ID); err != nil {
		t.Fatalf("docker host deleted: %v", err)
	}
}

// Einstellungen speichern: ungueltige Docker-API bzw. ssh:// abgelehnt, Zertifikat nur mit Nutzungsbedingungen.
func TestDockerSettingsSave(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	var status int
	var data any
	e.m.g.Render = func(w http.ResponseWriter, _ *http.Request, st int, _, _ string, d any) {
		status, data = st, d
		w.WriteHeader(st)
	}
	e.m.g.Flash = func(http.ResponseWriter, *http.Request, string, string) {}
	e.m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	post := func(v url.Values) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/cdn64/docker", strings.NewReader(v.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.m.pageDockerSave(rec, req)
		return rec
	}
	for _, bad := range []string{"ssh://root@box", "/var/run/docker.sock", "ftp://x"} {
		status, data = 0, nil
		post(url.Values{"docker": {"on"}, "docker_host": {bad}})
		if d, _ := data.(dockerData); status != http.StatusUnprocessableEntity || d.Errors["docker_host"] == "" {
			t.Fatalf("%s accepted: %d", bad, status)
		}
	}
	status, data = 0, nil
	post(url.Values{"docker": {"on"}, "docker_cert": {"http"}})
	if d, _ := data.(dockerData); status != http.StatusUnprocessableEntity || d.Errors["docker_cert"] != "certs.err.tos" {
		t.Fatalf("certificate without terms: %d", status)
	}
	if e.m.core.SettingOr(ctx, setDocker, "") == "on" {
		t.Fatal("saved despite error")
	}
	rec := post(url.Values{"docker": {"on"}, "docker_host": {"tcp://socket-proxy:2375"}, "docker_cert": {"http"}, "accept_tos": {"on"}})
	if rec.Code != http.StatusSeeOther || !e.m.certs.Account(ctx).TOSAccepted {
		t.Fatalf("save: %d", rec.Code)
	}
	for k, want := range map[string]string{setDocker: "on", setDockerTraefik: "off", setDockerHost: "tcp://socket-proxy:2375", setDockerCert: "http"} {
		if v := e.m.core.SettingOr(ctx, k, "-"); v != want {
			t.Fatalf("%s = %q, want %q", k, v, want)
		}
	}
}
