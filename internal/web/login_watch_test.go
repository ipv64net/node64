package web

import (
	"context"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

type loginWatchRec struct {
	mu    sync.Mutex
	calls []loginWatchCall
}

type loginWatchCall struct {
	src  netip.Addr
	port int
	tls  bool
}

func (r *loginWatchRec) LoginFailed(src netip.Addr, port int, tls bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, loginWatchCall{src, port, tls})
}

func (r *loginWatchRec) got() []loginWatchCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]loginWatchCall(nil), r.calls...)
}

// Fehlversuche (Passwort, API-Key) gehen mit IP und lokalem Port an den Beobachter; erfolgreiche Anmeldungen nicht.
func TestLoginWatcher(t *testing.T) {
	a := newTestApp(t)
	hash, _ := HashPassword("sehr geheimes passwort")
	if _, err := a.store.CreateUser(context.Background(), "admin", hash, "en", "UTC"); err != nil {
		t.Fatal(err)
	}
	// ohne Beobachter: nichts passiert
	_, body := a.get(t, "/login")
	csrf := csrfOf(t, body)
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"falsch"}})

	rec := &loginWatchRec{}
	a.s.SetLoginWatcher(rec)
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"falsch"}})
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"niemand"}, "password": {"x"}})
	u, _ := url.Parse(a.srv.URL)
	port, _ := strconv.Atoi(u.Port())
	calls := rec.got()
	if len(calls) != 2 || calls[0].src != netip.MustParseAddr("127.0.0.1") || calls[0].port != port || calls[0].tls {
		t.Fatalf("calls: %+v (port %d)", calls, port)
	}
	// ungueltiger API-Key zaehlt auch
	req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer node64_falsch")
	if resp, err := a.client.Do(req); err == nil {
		resp.Body.Close()
	}
	if n := len(rec.got()); n != 3 {
		t.Fatalf("api key: %d calls", n)
	}
	// erfolgreiche Anmeldung: kein Aufruf
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"sehr geheimes passwort"}})
	if n := len(rec.got()); n != 3 {
		t.Fatalf("success counted: %d calls", n)
	}
	a.s.SetLoginWatcher(nil)
	a.post(t, "/login", url.Values{"_csrf": {csrf}, "username": {"admin"}, "password": {"falsch"}})
	if n := len(rec.got()); n != 3 {
		t.Fatalf("after removal: %d calls", n)
	}
}
