package httpcompress

import (
	"bufio"
	"bytes"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

func TestNegotiate(t *testing.T) {
	cases := []struct {
		ae     string
		static bool
		want   string
	}{
		{"gzip, deflate, br, zstd", false, Zstd},
		{"gzip, deflate, br, zstd", true, Brotli},
		{"gzip, deflate, br", false, Brotli},
		{"gzip", false, Gzip},
		{"br;q=0, gzip;q=0.5", false, Gzip},
		{"zstd;q=0", false, ""},
		{"", false, ""},
		{"identity", false, ""},
		{"gzip;q=0", false, ""},
		{"*", true, Brotli},
		{"x-gzip", false, Gzip},
		{"br;q=0, *", false, Zstd},
	}
	for _, c := range cases {
		if got := Negotiate(c.ae, c.static); got != c.want {
			t.Errorf("%q static=%v: %q, want %q", c.ae, c.static, got, c.want)
		}
	}
}

func decode(t *testing.T, enc string, b []byte) string {
	t.Helper()
	var r io.Reader
	switch enc {
	case Zstd:
		d, err := zstd.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		defer d.Close()
		r = d
	case Brotli:
		r = brotli.NewReader(bytes.NewReader(b))
	case Gzip:
		g, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		r = g
	default:
		return string(b)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func TestHandler(t *testing.T) {
	page := strings.Repeat("<p>Hallo Node64</p>\n", 200)
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/img":
			w.Header().Set("Content-Type", "image/png")
		case "/small":
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "5")
			_, _ = io.WriteString(w, "kurz!")
			return
		case "/already":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Encoding", "gzip")
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("ETag", `"abc"`)
			w.Header().Set("Accept-Ranges", "bytes")
		}
		_, _ = io.WriteString(w, page)
	})
	h := Handler(app, Options{Static: func(r *http.Request, _ http.Header) bool { return strings.HasSuffix(r.URL.Path, ".css") }})
	get := func(path, ae string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if ae != "" {
			req.Header.Set("Accept-Encoding", ae)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	for _, ae := range []string{"zstd, br, gzip", "br, gzip", "gzip"} {
		rec := get("/", ae)
		enc := rec.Header().Get("Content-Encoding")
		if enc == "" || rec.Body.Len() >= len(page)/4 || decode(t, enc, rec.Body.Bytes()) != page {
			t.Fatalf("%s: enc %q, %d bytes", ae, enc, rec.Body.Len())
		}
		if rec.Header().Get("ETag") != `W/"abc"` || !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") || rec.Header().Get("Accept-Ranges") != "" {
			t.Fatalf("headers: %v", rec.Header())
		}
	}
	if rec := get("/app.css", "zstd, br, gzip"); rec.Header().Get("Content-Encoding") != Brotli {
		t.Fatalf("static: %q", rec.Header().Get("Content-Encoding"))
	}
	for _, p := range []string{"/img", "/small", "/already"} {
		rec := get(p, "zstd, br, gzip")
		if p != "/already" && rec.Header().Get("Content-Encoding") != "" {
			t.Fatalf("%s must not be compressed", p)
		}
		if p == "/already" && rec.Header().Get("Content-Encoding") != "gzip" {
			t.Fatal("already compressed must pass through")
		}
	}
	if rec := get("/", ""); rec.Header().Get("Content-Encoding") != "" || rec.Body.String() != page {
		t.Fatal("no accept-encoding: plain")
	}
	// mehrfach (Pool): die Encoder sind nach Close sauber wieder verwendbar
	for i := 0; i < 5; i++ {
		rec := get("/", "zstd")
		if decode(t, Zstd, rec.Body.Bytes()) != page {
			t.Fatal("pooled encoder")
		}
	}
}

// Cache-Schluessel: q=0 zaehlt nicht, was das Ziel selbst komprimiert, geht nur an Browser, die es koennen.
func TestCacheVariant(t *testing.T) {
	for ae, want := range map[string]string{
		"":                        "|identity,",
		"gzip;q=0":                "|identity,",
		"deflate":                 "|deflate,identity,",
		"gzip, deflate, br":       "br|br,deflate,gzip,identity,",
		"gzip, deflate, br, zstd": "br|br,deflate,gzip,identity,zstd,",
		"zstd, identity;q=0":      "zstd|zstd,",
	} {
		if got := CacheVariant(ae); got != want {
			t.Errorf("%q: %q, want %q", ae, got, want)
		}
	}
	for _, c := range []struct {
		ae, ce string
		want   bool
	}{{"", "", true}, {"", "deflate", false}, {"gzip, deflate", "deflate", true}, {"gzip;q=0", "gzip", false}, {"*", "br", true}, {"gzip", "br", false}} {
		if got := Acceptable(c.ae, c.ce); got != c.want {
			t.Errorf("Acceptable(%q, %q) = %v", c.ae, c.ce, got)
		}
	}
}

// 103 Early Hints vor der Antwort: die endgueltige 200 wird trotzdem komprimiert (mit Vary).
func TestEarlyHints(t *testing.T) {
	page := strings.Repeat("body { color: #333; }\n", 100)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "</app.css>; rel=preload")
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Content-Type", "text/css")
		_, _ = io.WriteString(w, page)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	front := httptest.NewServer(Handler(httputil.NewSingleHostReverseProxy(u), Options{}))
	defer front.Close()
	req, _ := http.NewRequest("GET", front.URL+"/app.css", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := (&http.Client{Transport: &http.Transport{DisableCompression: true}}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != Gzip || !strings.Contains(resp.Header.Get("Vary"), "Accept-Encoding") || decode(t, Gzip, b) != page {
		t.Fatalf("after 103: %d %v", resp.StatusCode, resp.Header)
	}
}

// truncUpstream kuendigt 5000 Byte an und schliesst nach 2000 (bzw. liefert alles, full).
func truncUpstream(t *testing.T, full bool) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = http.ReadRequest(bufio.NewReader(c))
				n := 2000
				if full {
					n = 5000
				}
				_, _ = io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Type: text/css\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n"+strings.Repeat("a", n))
			}()
		}
	}()
	return &url.URL{Scheme: "http", Host: ln.Addr().String()}
}

// Ziel bricht ab (ohne http.ServerContextKey wie bei HTTP/3: der Proxy kehrt still zurueck): nicht vollstaendig,
// obwohl die Komprimierung einen gueltigen Strom erzeugt.
func TestTruncatedBody(t *testing.T) {
	for _, full := range []bool{false, true} {
		rp := httputil.NewSingleHostReverseProxy(truncUpstream(t, full))
		rp.ErrorLog = log.New(io.Discard, "", 0)
		rp.ModifyResponse = func(resp *http.Response) error { TrackBody(resp); return nil }
		req, b := Track(httptest.NewRequest("GET", "/app.css", nil))
		req.Header.Set("Accept-Encoding", "br")
		rec := httptest.NewRecorder()
		Handler(rp, Options{}).ServeHTTP(rec, req)
		if rec.Header().Get("Content-Encoding") != Brotli || b.Complete() != full {
			t.Fatalf("full=%v: enc %q complete %v", full, rec.Header().Get("Content-Encoding"), b.Complete())
		}
	}
	// ohne TrackBody: die Laenge allein (angekuendigt 5000, geschrieben 2000) markiert den Fehler
	req, b := Track(httptest.NewRequest("GET", "/", nil))
	req.Header.Set("Accept-Encoding", "gzip")
	Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", "5000")
		_, _ = io.WriteString(w, strings.Repeat("a", 2000))
	}), Options{}).ServeHTTP(httptest.NewRecorder(), req)
	if !b.failed.Load() {
		t.Fatal("length mismatch must mark the body as failed")
	}
}

// Static sieht die Antwort; die staerkere Stufe ist begrenzt (danach dynamisch statt warten).
func TestStaticSlots(t *testing.T) {
	var seen http.Header
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = io.WriteString(w, strings.Repeat("a{b:c}", 200))
	}), Options{Static: func(_ *http.Request, h http.Header) bool { seen = h.Clone(); return true }})
	for i := 0; i < cap(staticSlots); i++ {
		staticSlots <- struct{}{}
	}
	req := httptest.NewRequest("GET", "/x.css", nil)
	req.Header.Set("Accept-Encoding", "zstd, br")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for i := 0; i < cap(staticSlots); i++ {
		<-staticSlots
	}
	if seen.Get("Cache-Control") != "max-age=60" || rec.Header().Get("Content-Encoding") != Brotli || decode(t, Brotli, rec.Body.Bytes()) != strings.Repeat("a{b:c}", 200) {
		t.Fatalf("static: seen %v, enc %q", seen, rec.Header().Get("Content-Encoding"))
	}
	if len(staticSlots) != 0 {
		t.Fatal("slot leaked")
	}
}
