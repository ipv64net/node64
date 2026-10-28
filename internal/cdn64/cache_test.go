package cdn64

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

// Hinter einer Zugriffsliste: nie "public" (geteilte Caches davor); reicht die Liste Benutzer an das Ziel, legt
// PROXY64 nichts ab und liefert nichts aus dem Cache.
func TestCacheProtected(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/css")
		_, _ = io.WriteString(w, "body{}")
	}))
	defer up.Close()
	port, _ := strconv.Atoi(up.URL[strings.LastIndex(up.URL, ":")+1:])
	_, h := cacheModule(t, port)
	get := func(prot any) http.Header {
		req := httptest.NewRequest("GET", "http://app.test/x.css", nil)
		if prot != nil {
			req = req.WithContext(context.WithValue(req.Context(), ctxProtectedKey{}, prot))
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header()
	}
	for i, x := range []struct {
		prot      any
		cc, cache string
		hits      int64
	}{{true, "private", "MISS", 1}, {false, "private", "MISS", 2}, {false, "private", "HIT", 2}, {nil, "public", "HIT", 2}, {true, "private", "MISS", 3}} {
		hd := get(x.prot)
		if !strings.HasPrefix(hd.Get("Cache-Control"), x.cc+",") || hd.Get("X-Cache-Status") != x.cache || hits.Load() != x.hits {
			t.Fatalf("%d: %v hits %d", i, hd, hits.Load())
		}
	}
}

// cacheModule: nur was proxyHandler fuer Proxy, Komprimierung und Cache braucht.
func cacheModule(t *testing.T, port int) (*Module, http.Handler) {
	t.Helper()
	m := &Module{log: slog.New(slog.NewTextHandler(io.Discard, nil)), trInsecure: http.DefaultTransport.(*http.Transport).Clone(),
		cache: newAssetCache(8 << 20)}
	h := newHost()
	h.ID, h.Names, h.TargetHost, h.TargetPort, h.CacheAssets, h.Advanced.Gzip = 1, []string{"app.test"}, "127.0.0.1", port, true, true
	return m, m.proxyHandler(h, &hostStats{})
}

// Ziel kuendigt 5000 Byte an und schliesst nach 2000: komprimiert (ohne Content-Length) und ohne
// http.ServerContextKey (HTTP/3, Tunnel - der Proxy kehrt still zurueck) darf das nicht in den Cache.
func TestCacheTruncatedCompressed(t *testing.T) {
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
	_, h := cacheModule(t, ln.Addr().(*net.TCPAddr).Port)
	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "http://app.test/app.css", nil)
		req.Header.Set("Accept-Encoding", "br, gzip")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 2; i++ {
		if rec := get(); rec.Header().Get("X-Cache-Status") != "MISS" || rec.Header().Get("Content-Encoding") != "br" {
			t.Fatalf("truncated %d: %v", i, rec.Header())
		}
	}
	full.Store(true)
	get()
	if rec := get(); rec.Header().Get("X-Cache-Status") != "HIT" || hits.Load() != 3 {
		t.Fatalf("complete response must be cached: %v hits %d", rec.Header(), hits.Load())
	}
}

// 103 Early Hints vor der Antwort: Cache und Komprimierung nehmen die endgueltige 200.
func TestCacheEarlyHints(t *testing.T) {
	var hits atomic.Int64
	page := strings.Repeat("body { color: #333; }\n", 100)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Link", "</app.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/css")
		_, _ = io.WriteString(w, page)
	}))
	defer up.Close()
	port, _ := strconv.Atoi(up.URL[strings.LastIndex(up.URL, ":")+1:])
	_, h := cacheModule(t, port)
	front := httptest.NewServer(h)
	defer front.Close()
	c := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	for i, want := range []string{"MISS", "HIT"} {
		req, _ := http.NewRequest("GET", front.URL+"/app.css", nil)
		req.Header.Set("Accept-Encoding", "gzip")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("X-Cache-Status") != want {
			t.Fatalf("%d: %d %v", i, resp.StatusCode, resp.Header)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("target hits %d", hits.Load())
	}
}

// Ziel komprimiert selbst (deflate): der Eintrag geht nicht an Browser ohne deflate; gzip;q=0 zaehlt nicht als gzip.
func TestCacheKeyEncodings(t *testing.T) {
	var hits atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/css")
		if strings.Contains(r.Header.Get("Accept-Encoding"), "deflate") {
			w.Header().Set("Content-Encoding", "deflate")
		}
		_, _ = io.WriteString(w, "body{}")
	}))
	defer up.Close()
	port, _ := strconv.Atoi(up.URL[strings.LastIndex(up.URL, ":")+1:])
	_, h := cacheModule(t, port)
	get := func(ae string) http.Header {
		req := httptest.NewRequest("GET", "http://app.test/x.css", nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Header()
	}
	if hd := get("deflate"); hd.Get("Content-Encoding") != "deflate" {
		t.Fatalf("deflate: %v", hd)
	}
	if hd := get(""); hd.Get("Content-Encoding") != "" || hd.Get("X-Cache-Status") != "MISS" {
		t.Fatalf("no accept-encoding got the deflate entry: %v", hd)
	}
	if hd := get("gzip;q=0"); hd.Get("Content-Encoding") != "" || hd.Get("X-Cache-Status") != "HIT" {
		t.Fatalf("gzip;q=0 is the same variant as none: %v", hd)
	}
	if hits.Load() != 2 {
		t.Fatalf("target hits %d", hits.Load())
	}
}
