package cdnedge

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Modus 1, Port 80: Anfragen an den gerouteten Namen gehen unveraendert weiter (auch Bodys, die wie Anfragen
// aussehen, und nach einem Upgrade roh); ein anderer Name - Host-Kopf, absolute URL, doppelter Host - trennt.
func TestHostGate(t *testing.T) {
	chunked := "POST /up HTTP/1.1\r\nHost: a.test\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"20\r\nGET / HTTP/1.1\r\nHost: b.test\r\n\r\n\r\n0\r\n\r\n"
	ok := []string{
		"GET / HTTP/1.1\r\nHost: a.test\r\n\r\nGET /2 HTTP/1.1\r\nHost: A.TEST:80\r\n\r\n",
		"POST /p HTTP/1.1\r\nHost: a.test\r\nContent-Length: 39\r\n\r\nGET / HTTP/1.1\r\nHost: b.test\r\n\r\nxxxxxxx" +
			"GET /3 HTTP/1.1\r\nHost: a.test\r\n\r\n",
		chunked + "GET /after HTTP/1.1\r\nHost: a.test\r\n\r\n",
		"GET http://a.test/abs HTTP/1.1\r\nHost: a.test\r\n\r\n",
		"GET /ws HTTP/1.1\r\nHost: a.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nraw bytes GET / HTTP/1.1\r\nHost: b.test\r\n\r\n",
	}
	for i, in := range ok {
		var out bytes.Buffer
		if err := gateHTTP(strings.NewReader(in), &out, "a.test"); !errors.Is(err, io.EOF) && err != nil {
			t.Fatalf("ok %d: %v", i, err)
		}
		if out.String() != in {
			t.Fatalf("ok %d: forwarded %q", i, out.String())
		}
	}
	first := "GET / HTTP/1.1\r\nHost: a.test\r\n\r\n"
	for i, bad := range []string{
		"GET /x HTTP/1.1\r\nHost: b.test\r\n\r\n",
		"GET http://b.test/x HTTP/1.1\r\nHost: a.test\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
		"GET /x HTTP/1.0\r\n\r\n",
		"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: a.test\r\nX: " + strings.Repeat("a", 2*hgHeaderMax) + "\r\n\r\n",
	} {
		var out bytes.Buffer
		if err := gateHTTP(strings.NewReader(first+bad), &out, "a.test"); err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("bad %d: no error", i)
		}
		if out.String() != first {
			t.Fatalf("bad %d: forwarded %q", i, out.String())
		}
	}
	// als Verbindung: anderer Name trennt den Besucher
	a, b := net.Pipe()
	g := newHostGate(a, []byte(first), "a.test")
	go func() { _, _ = io.WriteString(b, "GET / HTTP/1.1\r\nHost: b.test\r\n\r\n") }()
	got, err := io.ReadAll(g)
	if string(got) != first || err == nil {
		t.Fatalf("gate conn: %q %v", got, err)
	}
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("visitor not disconnected: %v", err)
	}
	_ = g.Close()
}

// Port 80 mit Keep-Alive (Modus 3): die zweite Anfrage an einen Namen mit "nur HTTPS" bzw. ohne Webseite wird nicht
// ueber die Verbindung des ersten Namens bedient.
func TestPlainKeepAliveFrontend(t *testing.T) {
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), Shield: ShieldConfig{ReqRate: -1}}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	tgt := plainTarget(t)
	https, off := *tgt, *tgt
	https.Frontend, off.Frontend = 3, 0
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "a.test", Mode: 3, Target: tgt}, {ID: 2, Name: "b.test", Mode: 3, Target: &https},
		{ID: 3, Name: "c.test", Mode: 3, Target: &off}}})
	for host, want := range map[string]int{"a.test": 200, "b.test": 403, "c.test": 421} {
		c, err := net.DialTimeout("tcp", cfg.ListenHTTP, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: a.test\r\n\r\nGET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
		br := bufio.NewReader(c)
		for i, w := range []int{200, want} {
			resp, err := http.ReadResponse(br, nil)
			if err != nil {
				t.Fatalf("%s %d: %v", host, i, err)
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != w {
				t.Fatalf("%s %d: %d, want %d", host, i, resp.StatusCode, w)
			}
		}
		c.Close()
	}
	if n := s.stats.of("b.test").Requests.Load() + s.stats.of("c.test").Requests.Load(); n != 0 {
		t.Fatalf("refused names served %d requests", n)
	}
}

// Abbruch mitten in der Antwort (panic(http.ErrAbortHandler) im ReverseProxy): keine Zwischendatei bleibt liegen.
func TestCacheAbortRemovesTemp(t *testing.T) {
	s := New(&Config{DataDir: t.TempDir()}, slog.New(slog.DiscardHandler), "test")
	re := &route{Name: "c.test", HostID: 1, Mode: 3,
		Target: newTarget(&apiTarget{Addrs: []string{"127.0.0.1"}, Port: 1, Scheme: "http", CacheMB: 10, CacheMinutes: 5})}
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "partial")
		panic(http.ErrAbortHandler)
	})
	func() {
		defer func() {
			if p := recover(); p != http.ErrAbortHandler {
				t.Fatalf("panic not passed on: %v", p)
			}
		}()
		s.serveCached(httptest.NewRecorder(), httptest.NewRequest("GET", "http://c.test/x.css", nil), re, next)
	}()
	if files, _ := filepath.Glob(filepath.Join(s.cache.dir, "tmp-*")); len(files) != 0 {
		t.Fatalf("temp files left: %v", files)
	}
}

// Zertifikat nur fuer den Namen (HTTP-01-Ausweg) bei einem Wildcard-Namen: Unternamen werden nicht damit beendet.
func TestCertCovers(t *testing.T) {
	s := New(&Config{DataDir: t.TempDir()}, slog.New(slog.DiscardHandler), "test")
	s.routes.Store(newRoutes(nil, &apiConfig{Hosts: []apiHost{{ID: 1, Name: "w.test", Mode: 2, Wildcard: true, Tunnels: []string{"t1"}}}}))
	cf, kf, _, _ := testCA(t, "w.test")
	cp, _ := os.ReadFile(cf)
	kp, _ := os.ReadFile(kf)
	if err := s.certs.put("w.test", cp, kp); err != nil {
		t.Fatal(err)
	}
	if !s.certs.covers("w.test", "W.test") || s.certs.covers("w.test", "a.w.test") || s.certs.hasWildcard("w.test") {
		t.Fatal("covers without wildcard")
	}
	if _, err := s.termCert(&tls.ClientHelloInfo{ServerName: "a.w.test"}); err == nil {
		t.Fatal("subname terminated with a certificate that does not cover it")
	}
	if c, err := s.termCert(&tls.ClientHelloInfo{ServerName: "w.test"}); err != nil || c == nil {
		t.Fatalf("name: %v", err)
	}
	cf, kf, _, _ = testCA(t, "w.test", "*.w.test")
	cp, _ = os.ReadFile(cf)
	kp, _ = os.ReadFile(kf)
	_ = s.certs.put("w.test", cp, kp)
	if !s.certs.covers("w.test", "a.w.test") || !s.certs.hasWildcard("w.test") {
		t.Fatal("wildcard certificate")
	}
}

// Umleitung auf HTTPS nur fuer eigene Namen: eine Anfrage in absoluter Form an einen anderen Namen bekommt 421 statt
// einer Weiterleitung dorthin (offene Weiterleitung, Test 2026-10-29).
func TestTermRedirectOwnNames(t *testing.T) {
	s := New(&Config{DataDir: t.TempDir()}, slog.New(slog.DiscardHandler), "test")
	s.routes.Store(newRoutes(nil, &apiConfig{Hosts: []apiHost{{ID: 1, Name: "m2.test", Mode: 2, Tunnels: []string{"t1"}}}}))
	w := httptest.NewRecorder()
	s.termRedirect(w, httptest.NewRequest("GET", "http://m2.test/a?b=1", nil))
	if w.Code != http.StatusMovedPermanently || w.Header().Get("Location") != "https://m2.test/a?b=1" {
		t.Fatalf("own name: %d %q", w.Code, w.Header().Get("Location"))
	}
	w = httptest.NewRecorder()
	s.termRedirect(w, httptest.NewRequest("GET", "http://evil.example/x", nil)) // r.Host = Name aus der URL
	if w.Code != http.StatusMisdirectedRequest || w.Header().Get("Location") != "" {
		t.Fatalf("absolute form to another name must not redirect: %d %q", w.Code, w.Header().Get("Location"))
	}
}
