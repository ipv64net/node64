package cdnedge

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ipv64net/node64/internal/httpcompress"
)

// edgeCache: Modus 3 wie in serveTerm (Proxy zum Ziel, Komprimierung, Cache), ohne Ports.
func edgeCache(t *testing.T, port int) http.Handler {
	t.Helper()
	s := New(&Config{DataDir: t.TempDir()}, slog.New(slog.NewTextHandler(io.Discard, nil)), "test")
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	re := &route{Name: "c.test", HostID: 1, UserID: 1, Mode: 3,
		Target: newTarget(&apiTarget{Addrs: []string{"127.0.0.1"}, Port: port, Scheme: "http", CacheMB: 10, CacheMinutes: 5})}
	next := httpcompress.Handler(s.directInit(), httpcompress.Options{Static: staticCached})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), termCtxKey{}, &termReq{re: re, host: "c.test", client: "127.0.0.1:1234"})
		s.serveCached(w, r.WithContext(ctx), re, next)
	})
}

func portOf(u string) int { p, _ := strconv.Atoi(u[strings.LastIndex(u, ":")+1:]); return p }

// Ziel kuendigt 5000 Byte an und schliesst nach 2000: komprimiert (ohne Content-Length) und ohne
// http.ServerContextKey (HTTP/3: der Proxy kehrt still zurueck) darf das nicht in den Cache.
func TestEdgeCacheTruncated(t *testing.T) {
	var hits atomic.Int64
	var full atomic.Bool
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = http.ReadRequest(bufio.NewReader(c))
				hits.Add(1)
				n := 2000
				if full.Load() {
					n = 5000
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nCache-Control: max-age=60\r\nContent-Length: 5000\r\n"+
					"Connection: close\r\n\r\n"+strings.Repeat("a", n))
			}()
		}
	}()
	h := edgeCache(t, ln.Addr().(*net.TCPAddr).Port)
	get := func() http.Header {
		req := httptest.NewRequest("GET", "https://c.test/app.css", nil)
		req.Header.Set("Accept-Encoding", "br, gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header()
	}
	for i := 0; i < 2; i++ {
		if hd := get(); hd.Get("X-Proxy-Cache") != "MISS" || hd.Get("Content-Encoding") != "br" {
			t.Fatalf("truncated %d: %v", i, hd)
		}
	}
	full.Store(true)
	get()
	if hd := get(); hd.Get("X-Proxy-Cache") != "HIT" || hits.Load() != 3 {
		t.Fatalf("complete response must be cached: %v hits %d", hd, hits.Load())
	}
}

// Cache-Schluessel: Ziel komprimiert selbst (deflate) - nicht an Browser ohne deflate; gzip;q=0 ist keine gzip-Fassung.
// 103 vor der Antwort: die 200 kommt in den Cache.
func TestEdgeCacheEncodings(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		w.Header().Set("Content-Type", "text/css")
		if r.URL.Path == "/hints.css" {
			w.WriteHeader(http.StatusEarlyHints)
		}
		if strings.Contains(r.Header.Get("Accept-Encoding"), "deflate") {
			w.Header().Set("Content-Encoding", "deflate")
		}
		_, _ = io.WriteString(w, strings.Repeat("body{}", 200))
	}))
	defer up.Close()
	h := edgeCache(t, portOf(up.URL))
	get := func(p, ae string) http.Header {
		req := httptest.NewRequest("GET", "https://c.test"+p, nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header()
	}
	if hd := get("/x.css", "deflate"); hd.Get("Content-Encoding") != "deflate" || hd.Get("X-Proxy-Cache") != "MISS" {
		t.Fatalf("deflate: %v", hd)
	}
	if hd := get("/x.css", ""); hd.Get("Content-Encoding") != "" || hd.Get("X-Proxy-Cache") != "MISS" {
		t.Fatalf("no accept-encoding got the deflate entry: %v", hd)
	}
	if hd := get("/x.css", "gzip;q=0"); hd.Get("Content-Encoding") != "" || hd.Get("X-Proxy-Cache") != "HIT" {
		t.Fatalf("gzip;q=0 is the same variant as none: %v", hd)
	}
	if hits.Load() != 2 {
		t.Fatalf("target hits %d", hits.Load())
	}
	// 103: ResponseRecorder haelt den ersten Status fest - ueber einen echten Server
	front := httptest.NewServer(h)
	defer front.Close()
	c := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	for i, want := range []string{"MISS", "HIT"} {
		req, _ := http.NewRequest("GET", front.URL+"/hints.css", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("X-Proxy-Cache") != want {
			t.Fatalf("103 %d: %d %v", i, resp.StatusCode, resp.Header)
		}
	}
}
