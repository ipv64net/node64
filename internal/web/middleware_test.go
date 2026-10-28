package web

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/config"
)

// X-Forwarded-For nur vom Proxy im eigenen Netz und nur die rechte Adresse (die haengt der Proxy an).
func TestClientIPForwardedFor(t *testing.T) {
	s := &Server{Deps: Deps{Cfg: &config.Config{TrustProxyHeaders: true}}}
	ip := func(remote string, xff ...string) string {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		for _, x := range xff {
			r.Header.Add("X-Forwarded-For", x)
		}
		return s.clientIP(r)
	}
	if got := ip("172.17.0.1:5000", "1.2.3.4, 203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("rightmost expected: %s", got)
	}
	if got := ip("172.17.0.1:5000", "1.2.3.4", "203.0.113.9"); got != "203.0.113.9" {
		t.Fatalf("rightmost header expected: %s", got)
	}
	if got := ip("198.51.100.7:5000", "1.2.3.4"); got != "198.51.100.7" {
		t.Fatalf("header from a public peer must be ignored: %s", got)
	}
	if got := ip("127.0.0.1:5000", "kaputt"); got != "127.0.0.1" {
		t.Fatalf("invalid entry: %s", got)
	}
	s.Cfg.TrustProxyHeaders = false
	if got := ip("172.17.0.1:5000", "203.0.113.9"); got != "172.17.0.1" {
		t.Fatalf("without NODE64_TRUST_PROXY: %s", got)
	}
}

// Ein Abbruch per http.ErrAbortHandler bleibt ein Abbruch (keine Fehlerseite hinter einem halben Download).
func TestRecovererAbort(t *testing.T) {
	s := &Server{}
	h := s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic(http.ErrAbortHandler) }))
	defer func() {
		if rec := recover(); rec != http.ErrAbortHandler {
			t.Fatalf("abort swallowed: %v", rec)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
}

type countReader struct {
	n int64
	r io.Reader
}

func (c *countReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.n += int64(n)
	return n, err
}

// Ohne Anmeldung liest die CSRF-Pruefung den Body der Upload-Pfade nicht (sonst bis 1 GB in den Speicher).
func TestCSRFUploadNotParsedWithoutLogin(t *testing.T) {
	a := newTestApp(t)
	tok := strings.Repeat("a", 40)
	for _, path := range []string{"/settings/restore", "/api/backup/restore"} {
		body := &countReader{r: io.MultiReader(strings.NewReader("_csrf="+tok+"&x="), strings.NewReader(strings.Repeat("b", 8<<20)))}
		req := httptest.NewRequest("POST", path, body)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.AddCookie(&http.Cookie{Name: csrfCookie + "_h", Value: tok})
		rec := httptest.NewRecorder()
		a.s.Handler().ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden || body.n > 1<<20 {
			t.Fatalf("%s: status %d, %d bytes read", path, rec.Code, body.n)
		}
	}
}

// Forward-Auth (ohne Sitzung): Passwort aendern beendet alle Sitzungen statt abzustuerzen; ein Basic-Kopf vom Proxy
// ersetzt auf /api/ nicht den CSRF-Token.
func TestForwardAuthNoSession(t *testing.T) {
	a := newTestApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings/login")
	if resp, _ := a.post(t, "/settings/login/forward", url.Values{"_csrf": {csrfOf(t, body)}, "enabled": {"1"}, "trusted": {"127.0.0.1"}, "header": {"Remote-User"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("forward auth: %d", resp.StatusCode)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	do := func(method, path, ctype string, body io.Reader, hdr map[string]string) (int, string) {
		req, _ := http.NewRequest(method, a.srv.URL+path, body)
		req.Header.Set("Remote-User", "admin")
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	code, page := do("GET", "/settings", "", nil, nil)
	if code != http.StatusOK {
		t.Fatalf("forward user: %d", code)
	}
	csrf := csrfOf(t, page)
	if code, _ := do("POST", "/api/backup", "application/json", strings.NewReader(`{"password":"backup-passwort"}`), map[string]string{"Authorization": "Basic YWRtaW46eA=="}); code != http.StatusForbidden {
		t.Fatalf("basic header must not skip csrf: %d", code)
	}
	form := url.Values{"_csrf": {csrf}, "current": {"sehr geheimes passwort"}, "password": {"neues langes passwort"}, "password2": {"neues langes passwort"}}
	if code, _ := do("POST", "/settings/password", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), nil); code != http.StatusSeeOther {
		t.Fatalf("password change: %d", code)
	}
	if resp, _ := a.get(t, "/settings"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("other sessions must end: %d", resp.StatusCode)
	}
}

// Login: gleichzeitige Fehlversuche kommen nicht ueber das Limit (5 je IP und Benutzer).
func TestLoginRateLimitParallel(t *testing.T) {
	a := newTestApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	resp, err := c.Get(a.srv.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := csrfOf(t, string(b))
	var mu sync.Mutex
	verified := 0
	var wg sync.WaitGroup
	for range 15 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.PostForm(a.srv.URL+"/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"falsch"}})
			if err != nil {
				return
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusUnauthorized {
				mu.Lock()
				verified++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if verified > 5 {
		t.Fatalf("%d password checks, limit is 5", verified)
	}
}

func TestLoginLimiterTakeRefund(t *testing.T) {
	l := newLoginLimiter()
	for i := range 5 {
		if l.take("ip:1") != 0 {
			t.Fatalf("attempt %d should be allowed", i)
		}
	}
	if l.take("ip:1") == 0 {
		t.Fatal("6th attempt must wait")
	}
	l.refund("ip:1")
	if l.take("ip:1") != 0 {
		t.Fatal("refunded attempt must be usable")
	}
}

// longTransfer hebt die Zeitlimits des Servers fuer eine Anfrage auf (Backup-Download, Wiederherstellung).
func TestLongTransfer(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/long" {
			longTransfer(w)
		}
		time.Sleep(300 * time.Millisecond)
		_, _ = io.WriteString(w, "ok")
	}))
	srv.Config.WriteTimeout = 100 * time.Millisecond
	srv.Start()
	defer srv.Close()
	get := func(path string) string {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			return "error"
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	if got := get("/long"); got != "ok" {
		t.Fatalf("long transfer: %q", got)
	}
	if got := get("/short"); got == "ok" {
		t.Fatal("default write timeout must still apply")
	}
}

// Ein voruebergehender Fehler beim Annehmen (z. B. EMFILE) beendet die Annahme nicht.
type flakyListener struct {
	net.Listener
	fails int
}

func (f *flakyListener) Accept() (net.Conn, error) {
	if f.fails > 0 {
		f.fails--
		return nil, errors.New("accept: too many open files")
	}
	return f.Listener.Accept()
}

func TestDualListenerTemporaryError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dl := newDualListener(&flakyListener{Listener: ln, fails: 3}, nil)
	defer dl.Close()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			_, _ = c.Write([]byte("G"))
			defer c.Close()
			time.Sleep(2 * time.Second)
		}
	}()
	done := make(chan error, 1)
	go func() {
		c, err := dl.Accept()
		if c != nil {
			c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("accept loop stopped")
	}
	dl.Close()
	if _, err := dl.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed: %v", err)
	}
}
