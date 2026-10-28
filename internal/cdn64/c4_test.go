package cdn64

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echoBackend antwortet mit dem, was beim Ziel ankommt.
func echoBackend(t *testing.T, tag string) (int, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big.txt" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, strings.Repeat("node64 ", 400))
			return
		}
		if r.Method == http.MethodPost {
			_, _ = io.Copy(io.Discard, r.Body)
		}
		w.Header().Set("Server", "backend")
		w.Header().Set("X-Secret", "1")
		_ = json.NewEncoder(w).Encode(map[string]string{"tag": tag, "path": r.URL.Path, "host": r.Host, "auth": r.Header.Get("Authorization"),
			"real": r.Header.Get("X-Real-IP"), "xff": r.Header.Get("X-Forwarded-For"), "custom": r.Header.Get("X-Custom"), "cookie": r.Header.Get("Cookie")})
	}))
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	p, _ := strconv.Atoi(u.Port())
	return p, srv
}

func getJSON(t *testing.T, c *http.Client, u string, hdr ...string) (int, map[string]string, http.Header) {
	t.Helper()
	code, body, h := do(t, c, "GET", u, hdr...)
	var out map[string]string
	_ = json.Unmarshal([]byte(body), &out)
	return code, out, h
}

func basic(user, pass string) string {
	r, _ := http.NewRequest("GET", "/", nil)
	r.SetBasicAuth(user, pass)
	return r.Header.Get("Authorization")
}

func TestAccessLists(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := echoBackend(t, "a")
	a := &AccessList{Name: "Familie", SatisfyAny: true, Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "alice", Password: "geheim"}}); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.AccessListID = []string{"acl.test"}, "127.0.0.1", port, CertNone, a.ID
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	code, _, hdr := getJSON(t, c, "http://acl.test/")
	if code != 401 || !strings.Contains(hdr.Get("WWW-Authenticate"), `Basic realm="Familie"`) {
		t.Fatalf("no login: %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	if code, _, _ := getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "falsch")); code != 401 {
		t.Fatalf("wrong password: %d", code)
	}
	code, got, _ := getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "geheim"))
	if code != 200 || got["auth"] != "" {
		t.Fatalf("login ok, auth not passed on: %d %v", code, got)
	}
	// Anmeldung weiterreichen
	a.PassAuth = true
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	if _, got, _ := getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "geheim")); got["auth"] == "" {
		t.Fatal("auth must be passed on")
	}
	if strings.Contains(mustJSON(a.public()), "$2a$") {
		t.Fatal("public view must not contain hashes")
	}
	// IP erlaubt: ohne Anmeldung
	a.Rules = []AccessRule{{Action: "deny", CIDR: "127.0.0.2"}, {Action: "allow", CIDR: "127.0.0.0/8"}}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := getJSON(t, c, "http://acl.test/"); code != 200 {
		t.Fatalf("ip allowed: %d", code)
	}
	// beides noetig, IP nicht erlaubt: 403 auch mit richtiger Anmeldung
	a.SatisfyAny, a.Rules = false, []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "geheim")); code != 403 {
		t.Fatalf("all, wrong ip: %d", code)
	}
	// Fehlversuche: nach 10 gesperrt (429)
	a.SatisfyAny = true
	if err := e.m.saveAccessList(ctx, a, []UserInput{{Username: "alice"}}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < authFailMax; i++ {
		getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "x"+strconv.Itoa(i)))
	}
	if code, _, _ := getJSON(t, c, "http://acl.test/", "Authorization", basic("alice", "geheim")); code != 429 {
		t.Fatalf("blocked after failures: %d", code)
	}
	// benutzte Liste laesst sich nicht loeschen
	var fe *FieldError
	if err := e.m.deleteAccessList(ctx, a.ID); !errors.As(err, &fe) || fe.Name != "acl.test" {
		t.Fatalf("delete in use: %v", err)
	}
	if err := e.m.saveAccessList(ctx, &AccessList{Name: "leer"}, nil); !errors.As(err, &fe) || fe.Key != "cdn64.err.acl_empty" {
		t.Fatalf("empty list: %v", err)
	}
	if err := e.m.saveAccessList(ctx, &AccessList{Name: "neu"}, []UserInput{{Username: "bob"}}); !errors.As(err, &fe) || fe.Key != "cdn64.err.acl_password" {
		t.Fatalf("new user without password: %v", err)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestLocations(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	pa, _ := echoBackend(t, "a")
	pb, _ := echoBackend(t, "b")
	acl := &AccessList{Name: "nur lan", Rules: []AccessRule{{Action: "allow", CIDR: "10.0.0.0/8"}}}
	if err := e.m.saveAccessList(ctx, acl, nil); err != nil {
		t.Fatal(err)
	}
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"loc.test"}, "127.0.0.1", pa, CertNone
	h.Locations = []Location{{Path: "/api/", TargetHost: "127.0.0.1", TargetPort: pb, ForwardPath: "/v1"},
		{Path: "/admin", TargetHost: "127.0.0.1", TargetPort: pb, AccessListID: acl.ID}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	if _, got, _ := getJSON(t, c, "http://loc.test/x"); got["tag"] != "a" || got["path"] != "/x" {
		t.Fatalf("host target: %v", got)
	}
	if _, got, _ := getJSON(t, c, "http://loc.test/api/users/1"); got["tag"] != "b" || got["path"] != "/v1/users/1" {
		t.Fatalf("location with forward path: %v", got)
	}
	if _, got, _ := getJSON(t, c, "http://loc.test/api"); got["tag"] != "b" || got["path"] != "/v1" {
		t.Fatalf("exact location path: %v", got)
	}
	if _, got, _ := getJSON(t, c, "http://loc.test/api/"); got["path"] != "/v1/" {
		t.Fatalf("location path with slash: %v", got)
	}
	if _, got, _ := getJSON(t, c, "http://loc.test/apix"); got["tag"] != "a" {
		t.Fatalf("/apix is not /api: %v", got)
	}
	if code, _, _ := getJSON(t, c, "http://loc.test/admin/x"); code != 403 {
		t.Fatalf("location access list: %d", code)
	}
	// Route nach dem bereinigten Pfad: kein Weg an der Zugriffsliste der Location vorbei, keiner aus forward_path heraus
	for _, x := range []struct {
		path string
		code int
	}{{"//admin/x", 403}, {"/admin//x", 403}, {"//admin", 403}, {"/./admin/x", 400}, {"/x/../admin/x", 400}, {"/%2e/admin/x", 400},
		{"/x/%2E%2E/admin", 400}, {"/api/../admin", 400}, {"/api/..%2Fx", 400}} {
		if code, _, _ := getJSON(t, c, "http://loc.test"+x.path); code != x.code {
			t.Errorf("%s: %d, want %d", x.path, code, x.code)
		}
	}
	if _, got, _ := getJSON(t, c, "http://loc.test//api//users/1"); got["tag"] != "b" || got["path"] != "/v1/users/1" {
		t.Fatalf("double slashes with forward path: %v", got)
	}
	bad := newHost()
	bad.Names, bad.TargetHost, bad.TargetPort = []string{"bad.test"}, "127.0.0.1", pa
	bad.Locations = []Location{{Path: "/a", TargetHost: "127.0.0.1", TargetPort: pb}, {Path: "a/", TargetHost: "x", TargetPort: 1}}
	var fe *FieldError
	if err := e.m.saveHost(ctx, bad); !errors.As(err, &fe) || fe.Key != "cdn64.err.location_dup" {
		t.Fatalf("duplicate location: %v", err)
	}
}

func TestAdvancedOptions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.enable(t)
	port, _ := echoBackend(t, "a")
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"adv.test"}, "127.0.0.1", port, CertNone
	h.Advanced = Advanced{RequestHeaders: []Header{{Name: "X-Custom", Value: "hallo"}}, RequestRemove: []string{"Cookie"},
		ResponseHeaders: []Header{{Name: "X-Frame-Options", Value: "DENY"}}, ResponseRemove: []string{"Server", "X-Secret"},
		HostHeader: "intern.lan", MaxBodyMB: 1, Gzip: true, TrustedProxies: []string{"127.0.0.1"}}
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	code, got, hdr := getJSON(t, c, "http://adv.test/", "Cookie", "a=b", "X-Forwarded-For", "203.0.113.9")
	if code != 200 || got["custom"] != "hallo" || got["cookie"] != "" || got["host"] != "intern.lan" || got["real"] != "203.0.113.9" || got["xff"] != "203.0.113.9" {
		t.Fatalf("request side: %d %v", code, got)
	}
	if hdr.Get("X-Frame-Options") != "DENY" || hdr.Get("Server") != "" || hdr.Get("X-Secret") != "" {
		t.Fatalf("response side: %v", hdr)
	}
	// Upload-Grenze
	req, _ := http.NewRequest("POST", "http://adv.test/up", bytes.NewReader(make([]byte, 2<<20)))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("max body: %d", resp.StatusCode)
	}
	// gzip
	tr := c.Transport.(*http.Transport).Clone()
	tr.DisableCompression = true
	gc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	req, _ = http.NewRequest("GET", "http://adv.test/big.txt", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err = gc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("gzip: %v", resp.Header)
	}
	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := io.ReadAll(zr)
	if !strings.HasPrefix(string(plain), "node64 node64") {
		t.Fatalf("gzip body: %q", plain[:20])
	}
	// zstd und Brotli je nach Browser
	for _, c := range []struct{ ae, want string }{{"gzip, deflate, br, zstd", "zstd"}, {"gzip, br", "br"}} {
		req, _ = http.NewRequest("GET", "http://adv.test/big.txt", nil)
		req.Header.Set("Accept-Encoding", c.ae)
		r2, err := gc.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r2.Body.Close()
		if r2.Header.Get("Content-Encoding") != c.want {
			t.Fatalf("%s: %v", c.ae, r2.Header)
		}
	}
	// ohne vertrauenswuerdigen Proxy zaehlt die Gegenstelle
	h.Advanced.TrustedProxies = nil
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, got, _ := getJSON(t, c, "http://adv.test/", "CF-Connecting-IP", "203.0.113.9", "X-Forwarded-For", "203.0.113.9"); got["real"] != "127.0.0.1" || got["xff"] != "127.0.0.1" {
		t.Fatalf("untrusted: %v", got)
	}
	var fe *FieldError
	for _, adv := range []Advanced{{RequestHeaders: []Header{{Name: "Connection", Value: "x"}}}, {TrustedProxies: []string{"0.0.0.0/0"}},
		{ResponseHeaders: []Header{{Name: "X-A", Value: "a\r\nb"}}}, {TimeoutSeconds: -1}} {
		h.Advanced = adv
		if err := e.m.saveHost(ctx, h); !errors.As(err, &fe) || fe.Field != "advanced" {
			t.Errorf("%+v must be refused: %v", adv, err)
		}
	}
}

func TestStatsAndAccessLog(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.m.SetDataDir(t.TempDir())
	e.enable(t)
	port, _ := echoBackend(t, "a")
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID, h.Advanced.AccessLog = []string{"log.test"}, "127.0.0.1", port, CertNone, true
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	c := e.client(false)
	do(t, c, "GET", "http://log.test/eins?x=1", "User-Agent", "Testlauf")
	do(t, c, "GET", "http://log.test/.env") // gilt nicht als Exploit, Block Common Exploits ist aus
	sdb := e.m.stats2.Load()
	if sdb == nil {
		t.Fatal("stats db not open")
	}
	var list []LogEntry
	for i := 0; i < 50; i++ {
		list, _ = sdb.entries(ctx, LogFilter{HostID: h.ID})
		if len(list) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(list) != 2 || list[1].Path != "/eins?x=1" || list[1].UA != "Testlauf" || list[1].Client != "127.0.0.1" || list[1].Status != 200 || list[1].Bytes == 0 {
		t.Fatalf("log: %+v", list)
	}
	sums, err := sdb.sums(ctx, time.Now().Add(-2*time.Hour)) // 2 Eimer: auch kurz nach einem Stundenwechsel
	if err != nil || sums[h.ID].Requests != 2 || sums[h.ID].S2 != 2 {
		t.Fatalf("sums: %+v %v", sums, err)
	}
	if found, _ := sdb.entries(ctx, LogFilter{Query: "eins"}); len(found) != 1 {
		t.Fatalf("search: %d", len(found))
	}
	if err := e.m.saveLogSettings(ctx, 91, false); err == nil {
		t.Fatal("retention > 90 must be refused")
	}
	if maskIP(netipMust("203.0.113.77")) != "203.0.113.0/24" {
		t.Fatal("mask")
	}
	// Modul aus: Datei geschlossen
	if err := e.reg.Disable(ctx, Name); err != nil {
		t.Fatal(err)
	}
	if e.m.stats2.Load() != nil {
		t.Fatal("stats must close with the module")
	}
}

// "N Stunden" sind genau N Stunden-Eimer inkl. der laufenden; Summen und Verlauf zaehlen dieselben Eimer.
func TestStatsWindowSumsEqualTimeline(t *testing.T) {
	ctx := context.Background()
	s, err := openStats(t.TempDir(), slog.New(slog.NewTextHandler(io.Discard, nil)), func() int { return 7 }, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	now := time.Now()
	cur := now.UTC().Truncate(time.Hour)
	for k := 0; k <= 25; k++ {
		if _, err := s.db.Exec(`INSERT INTO hourly (host_id, hour, requests) VALUES (1, ?, 1)`, cur.Add(-time.Duration(k)*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	since := now.Add(-24 * time.Hour)
	sums, err := s.sums(ctx, since)
	if err != nil {
		t.Fatal(err)
	}
	pts, err := s.hours(ctx, 0, since)
	if err != nil {
		t.Fatal(err)
	}
	var tl int64
	for _, p := range pts {
		tl += p.Requests
	}
	if len(pts) != 24 || !pts[0].Hour.Equal(cur.Add(-23*time.Hour)) || sums[1].Requests != 24 || tl != sums[1].Requests {
		t.Fatalf("window: %d buckets %+v, sums %d, timeline %d", len(pts), pts, sums[1].Requests, tl)
	}
}

func TestHealthcheckForTarget(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var bodies []map[string]any
	e.m.SetCheckCreator(func(r *http.Request, body []byte) (string, error) {
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		bodies = append(bodies, m)
		return "tok" + strconv.Itoa(len(bodies)), nil
	})
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort, h.CertID = []string{"hc.test"}, "192.168.1.20", 8123, CertNone
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	p := newHostKind(KindPass)
	p.Names, p.TargetHost, p.TargetPort = []string{"pass.test"}, "192.168.1.30", 443
	if err := e.m.saveHost(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{h.ID, p.ID} {
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/cdn64/hosts/"+strconv.FormatInt(id, 10)+"/healthcheck", nil))
		if rec.Code != 201 {
			t.Fatalf("create check: %d %s", rec.Code, rec.Body)
		}
	}
	if bodies[0]["type"] != "http" || bodies[0]["target"] != "http://192.168.1.20:8123/" || bodies[0]["name"] != "PROXY64: hc.test" {
		t.Fatalf("http check: %v", bodies[0])
	}
	if bodies[1]["type"] != "tcp" || bodies[1]["target"] != "192.168.1.30" {
		t.Fatalf("tcp check: %v", bodies[1])
	}
}

func netipMust(s string) netip.Addr { return netip.MustParseAddr(s) }

// Neue Proxy-Hosts komprimieren standardmaessig, andere Arten nicht.
func TestCompressionDefault(t *testing.T) {
	if !newHost().Advanced.Gzip || newHostKind(KindRedirect).Advanced.Gzip {
		t.Fatal("compression on for new proxy hosts only")
	}
}

// Zaehlung: Statusklassen nur fuer Antworten des Ziels; abgewiesen und an den Honeypot getrennt; "Fehler" = 5xx.
func TestStatsSplitDecoyAndErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	s, err := openStats(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func() int { return 7 }, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ip := netip.MustParseAddr("203.0.113.9")
	for _, h := range []hit{
		{time: now, hostID: 1, client: ip, method: "GET", path: "/", status: 200},
		{time: now, hostID: 1, client: ip, method: "GET", path: "/icons/x.png", status: 404},
		{time: now, hostID: 1, client: ip, method: "GET", path: "/api", status: 502},
		{time: now, hostID: 1, client: ip, method: "GET", path: "/.env", status: 403, reason: rejBlocklist},
		{time: now, hostID: 1, client: ip, method: "GET", path: "/.git/config", status: 200, reason: rejExploit, decoy: true},
		{time: now, hostID: 0, client: ip, method: "GET", host: "fremd.example", path: "/", status: 200, reason: "unknown", decoy: true},
	} {
		s.add(h)
	}
	s.close() // schreibt den Rest
	s, err = openStats(dir, slog.New(slog.NewTextHandler(io.Discard, nil)), func() int { return 7 }, func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	sums, err := s.sums(ctx, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := sums[1]
	if h.Requests != 5 || h.S2 != 1 || h.S4 != 1 || h.S5 != 1 || h.Blocked != 1 || h.Decoy != 1 || h.Errors() != 1 {
		t.Fatalf("host 1: %+v", h)
	}
	if sums[0].Decoy != 1 || sums[0].Blocked != 0 {
		t.Fatalf("host 0: %+v", sums[0])
	}
	all, _ := s.entries(ctx, LogFilter{Limit: 50})
	rej, _ := s.entries(ctx, LogFilter{Rejected: true, Limit: 50})
	dec, _ := s.entries(ctx, LogFilter{Decoy: true, Limit: 50})
	if len(rej) != 1 || rej[0].Reason != rejBlocklist || rej[0].Decoy || len(dec) != 2 || !dec[0].Decoy || len(all) != 3 {
		t.Fatalf("log: all %d, rejected %+v, decoy %+v", len(all), rej, dec)
	}
}

// Formular: "anna:neu" fuer einen bestehenden Benutzer setzt das neue Passwort (an seiner Stelle).
func TestUsersFromFormNewPassword(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader(url.Values{"new_users": {"anna:neu\r\nbob:pw\nclara"}, "remove_user": {"dora"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	got := usersFromForm(r, &AccessList{Users: []AccessUser{{Username: "anna"}, {Username: "dora"}, {Username: "emil"}}})
	want := []UserInput{{Username: "anna", Password: "neu"}, {Username: "emil"}, {Username: "bob", Password: "pw"}, {Username: "clara"}}
	if !slices.Equal(got, want) {
		t.Fatalf("users: %+v", got)
	}
}

// Fehlversuche: IPv6 je /64, Abgelaufenes faellt beim Aufraeumen heraus.
func TestFailLimiterGrouped(t *testing.T) {
	l := newFailLimiter()
	for i := 0; i < authFailMax-1; i++ {
		if l.failed(netip.MustParseAddr("2001:db8:1:2::" + strconv.Itoa(i+1))) {
			t.Fatal("blocked too early")
		}
	}
	if !l.failed(netip.MustParseAddr("2001:db8:1:2:ffff::1")) || !l.blocked(netip.MustParseAddr("2001:db8:1:2::abcd")) {
		t.Fatal("same /64 must be blocked")
	}
	if l.blocked(netip.MustParseAddr("2001:db8:1:3::1")) {
		t.Fatal("other /64 must stay open")
	}
	l.failed(netip.MustParseAddr("192.0.2.1"))
	l.mu.Lock()
	l.fail[limKey(netip.MustParseAddr("192.0.2.1"))] = []time.Time{time.Now().Add(-authFailWindow - time.Second)}
	for k := range l.ban {
		l.ban[k] = time.Now().Add(-time.Second)
	}
	l.mu.Unlock()
	l.sweep()
	if len(l.fail) != 0 || len(l.ban) != 0 {
		t.Fatalf("sweep: %d fail, %d ban", len(l.fail), len(l.ban))
	}
}

// Route nach dem bereinigten Pfad; Platz beim Ziel sparen nur echte WebSockets, wo sie erlaubt sind.
func TestReqPathAndWebSocket(t *testing.T) {
	for in, want := range map[string]string{"/": "/", "//admin": "/admin", "/a//b/": "/a/b/", "///": "/", "*": "*", "/a/b": "/a/b"} {
		if got, ok := reqPath(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"/.", "/..", "/a/./b", "/a/../b", "/a/..", "/a\\..\\b"} {
		if _, ok := reqPath(in); ok {
			t.Errorf("%q must be refused", in)
		}
	}
	h := newHost()
	h.WebSockets = false
	h.Locations = []Location{{Path: "/ws", WebSockets: true}, {Path: "/ws/plain"}}
	for p, want := range map[string]bool{"/": false, "/ws": true, "//ws/x": true, "/ws/plain/x": false, "/wsx": false} {
		if wsAt(h, p) != want {
			t.Errorf("wsAt %q: want %v", p, want)
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Upgrade", "foo")
	r.Header.Set("Connection", "Upgrade")
	if wsUpgrade(r) {
		t.Error("other upgrade is no websocket")
	}
	r.Header.Set("Upgrade", "WebSocket")
	r.Header.Set("Connection", "keep-alive, Upgrade")
	if !wsUpgrade(r) {
		t.Error("websocket not detected")
	}
}
