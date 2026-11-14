package cdn64

import (
	"bytes"
	"context"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// #74: Zeile im nginx-Format "combined" mit dem Host vorn, wie es CrowdSec (nginx-logs) liest.
func TestAccessLine(t *testing.T) {
	tm := time.Date(2026, 11, 14, 10, 5, 7, 0, time.FixedZone("", 3600))
	h := hit{time: tm, client: netip.MustParseAddr("203.0.113.7"), method: "GET", host: "cloud.example.com", path: `/a b"c?x=1`,
		status: 403, bytes: 512, ua: "curl/8.0", ref: "", proto: "HTTP/2.0", reason: rejGeo}
	line, ok := accessLine(h, false)
	want := `cloud.example.com 203.0.113.7 - - [14/Nov/2026:10:05:07 +0100] "GET /a b\x22c?x=1 HTTP/2.0" 403 512 "-" "curl/8.0"` + "\n"
	if !ok || line != want {
		t.Fatalf("line\n%q\nwant\n%q", line, want)
	}
	// grok-Muster wie crowdsecurity/nginx-logs (vereinfacht): optionaler Host, IP, Zeit, Anfrage, Status, Bytes, Referer, UA
	re := regexp.MustCompile(`^(\S+ )?\S+ - \S+ \[[^\]]+\] "[A-Z]+ .* HTTP/[0-9.]+" \d+ \d+ "[^"]*" "[^"]*"\n$`)
	if !re.MatchString(line) {
		t.Fatalf("not combined: %q", line)
	}
	h.client = netip.MustParseAddr("2001:db8:1:2::5")
	if line, _ := accessLine(h, true); !strings.Contains(line, " 2001:db8:1:: - - ") { // gekuerzt (/48), als Adresse
		t.Fatalf("anon: %q", line)
	}
	if _, ok := accessLine(hit{conn: true, method: "-", client: h.client, time: tm}, false); ok {
		t.Fatal("connection without request")
	}
	if _, ok := accessLine(hit{method: "TCP", path: " → 10.0.0.1:22", status: 0, client: h.client, time: tm}, false); ok {
		t.Fatal("stream")
	}
	if logEsc("a\nb", true) != `a\x0Ab` || logEsc("a b", false) != `a\x20b` || logEsc("a b", true) != "a b" {
		t.Fatal("escape")
	}
}

// Datei wechselt bei der eingestellten Groesse zu access.log.1.
func TestAccessFileRotate(t *testing.T) {
	dir := t.TempDir()
	a := &accessFile{path: filepath.Join(dir, accessFileName), log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	line := strings.Repeat("x", 99) + "\n"
	for range 25 {
		a.write(line, 1000)
	}
	a.close()
	cur, _ := os.ReadFile(a.path)
	old, _ := os.ReadFile(a.path + ".1")
	if len(cur) != 500 || len(old) != 1000 {
		t.Fatalf("sizes: %d %d", len(cur), len(old))
	}
}

// #74 Ende zu Ende: eingeschaltet schreibt PROXY64 jede Anfrage aller Hosts in <data>/cdn64/access.log - auch ohne
// Einzel-Log des Hosts und auch abgewiesene; ausgeschaltet nichts.
func TestAccessFileEndToEnd(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	data := t.TempDir()
	e.m.SetDataDir(data)
	e.enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello") }))
	t.Cleanup(srv.Close)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"file.test"}, "127.0.0.1", srv.Listener.Addr().(*net.TCPAddr).Port, CertNone
	h.Advanced.AccessLog = false
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(data, Name, accessFileName)
	get := func(p string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, "http://file.test"+p, nil)
		req.Header.Set("Referer", "https://ref.example/")
		req.Header.Set("User-Agent", "crowdsec-test")
		resp, err := e.client(false).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	get("/off")
	if err := e.m.saveAccessFile(ctx, true, 5); err != nil {
		t.Fatal(err)
	}
	get("/on?x=1")
	var raw []byte
	for range 60 {
		raw, _ = os.ReadFile(path)
		if strings.Contains(string(raw), "/on?x=1") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	s := string(raw)
	if strings.Contains(s, "/off") || !strings.Contains(s, `file.test 127.0.0.1 - - [`) ||
		!strings.Contains(s, `"GET /on?x=1 HTTP/1.1" 200 5 "https://ref.example/" "crowdsec-test"`) {
		t.Fatalf("access.log:\n%s", s)
	}
	if on, mb := e.m.accessFileSettings(ctx); !on || mb != 5 {
		t.Fatalf("settings %v %d", on, mb)
	}
	if err := e.m.saveAccessFile(ctx, false, 0); err == nil {
		t.Fatal("0 MB accepted")
	}
}

// #101: Nextcloud - /.well-known/caldav und carddav mit 301 auf /remote.php/dav/, nur mit Haken; eine eigene Location
// fuer den Pfad geht vor; andere Pfade gehen ans Ziel.
func TestNextcloudDAV(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "target "+r.URL.Path) }))
	t.Cleanup(srv.Close)
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"cloud.test"}, "127.0.0.1", port, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	do := func(method, p string) (int, string, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "http://cloud.test"+p, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("Location"), string(b)
	}
	if code, _, body := do(http.MethodGet, "/.well-known/caldav"); code != 200 || body != "target /.well-known/caldav" { // ohne Haken: Ziel
		t.Fatalf("off: %d %q", code, body)
	}
	h.Advanced.NextcloudDAV = true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/.well-known/caldav", "/.well-known/carddav", "/.well-known/CardDAV/"} {
		if code, loc, _ := do("PROPFIND", p); code != http.StatusMovedPermanently || loc != "/remote.php/dav/" {
			t.Fatalf("%s: %d %q", p, code, loc)
		}
	}
	if code, _, body := do(http.MethodGet, "/.well-known/webfinger"); code != 200 || body != "target /.well-known/webfinger" {
		t.Fatalf("other: %d %q", code, body)
	}
	h.Locations = []Location{{Path: "/.well-known/caldav", Action: LocRespond, Status: 200, Body: "own"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if code, _, body := do(http.MethodGet, "/.well-known/caldav"); code != 200 || body != "own" {
		t.Fatalf("location first: %d %q", code, body)
	}
	if code, _, _ := do(http.MethodGet, "/.well-known/carddav"); code != http.StatusMovedPermanently {
		t.Fatalf("carddav with location: %d", code)
	}
	r := newHost()
	r.Kind, r.Names, r.RedirectTarget, r.Advanced.NextcloudDAV = KindRedirect, []string{"redir.test"}, "https://example.com", true
	r.CertID = CertNone
	if err := e.m.saveHost(ctx, r); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.m.host(ctx, r.ID); got.Advanced.NextcloudDAV { // nur Proxy-Hosts
		t.Fatal("redirect host keeps nextcloud_dav")
	}
}

// #78 und #54: Locations eingeklappt mit "+ Location hinzufuegen" (nur eine leere Vorlage), Laendersperre mit
// Laendernamen und Flaggen in der Auswahl.
func TestHostFormLocationsAndCountries(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"loc.test"}, "127.0.0.1", 8080, CertNone
	h.Locations = []Location{{Path: "/api", Scheme: "http", TargetHost: "10.0.0.2", TargetPort: 3000}, {Path: "/admin", Action: LocBlock, Status: 403}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	e.m.bl.mu.Lock()
	e.m.bl.countries = []geoCountry{{Code: "DE", Name: "Germany"}, {Code: "AT", Name: "Austria"}}
	e.m.bl.mu.Unlock()
	d := e.m.form(ctx, h, false)
	if len(d.Locs) != 3 {
		t.Fatalf("locs: %d", len(d.Locs))
	}
	tp, err := template.New("host_form.html").Funcs(template.FuncMap{"join": strings.Join, "split": strings.Fields, "dict": tplDict}).ParseFS(templateFS, "templates/partials/*.html", "templates/pages/host_form.html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tp.ExecuteTemplate(&buf, "content", tplView{Data: d, Lang: "de"}); err != nil {
		t.Fatal(err)
	}
	html := buf.String()
	for _, want := range []string{`<details class="border rounded mb-2" data-loc>`, `data-loc-new hidden open`, `data-loc-add`, `data-loc-del`,
		`name="loc_count" value="3"`, `http://10.0.0.2:3000`, `cdn64.f.loc_action_block (403)`,
		`<option value="DE" data-flag="🇩🇪" data-alt="Germany Germany">Deutschland</option>`, `name="adv_nextcloud_dav"`} {
		if !strings.Contains(html, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Count(html, "data-loc-new") != 1 {
		t.Error("exactly one empty location template")
	}
}
