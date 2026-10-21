package httpcompress

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
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
		}
		_, _ = io.WriteString(w, page)
	})
	h := Handler(app, Options{Static: func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, ".css") }})
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
		if rec.Header().Get("ETag") != `W/"abc"` || !strings.Contains(rec.Header().Get("Vary"), "Accept-Encoding") {
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
