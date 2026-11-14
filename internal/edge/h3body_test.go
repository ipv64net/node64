package edge

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

// #157: GET ueber HTTP/3 (ohne content-length) kam beim Ziel als Anfrage mit Inhalt unbekannter Laenge an (HTTP/2 ohne
// END_STREAM); lighttpd (OPNsense) antwortet darauf mit 400. Das Ziel hier lehnt solche Anfragen ebenso ab.
func TestHTTP3GetWithoutBody(t *testing.T) {
	up := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.ContentLength != 0 {
			http.Error(w, "GET/HEAD with content-length", http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%s %s %d %q", r.Proto, r.Method, r.ContentLength, b)
	}))
	up.EnableHTTP2 = true
	up.StartTLS()
	defer up.Close()
	u, _ := url.Parse(up.URL)
	tr := up.Client().Transport.(*http.Transport).Clone()
	tr.ForceAttemptHTTP2 = true
	proxy := httputil.NewSingleHostReverseProxy(u)
	proxy.Transport = tr

	e, cfg := newEdge(t, nil)
	if err := e.Set("cdn64", []Route{{Names: []string{"app.test"}, Handler: proxy, HTTP3: true}}); err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "app.test"}} //nolint:gosec // Test
	defer h3.Close()
	do := func(method string, body io.Reader) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(method, "https://127.0.0.1:"+strconv.Itoa(cfg.HTTPSPort)+"/", body)
		req.Host = "app.test"
		if body != nil {
			req.ContentLength = -1 // Laenge unbekannt: ohne content-length
		}
		resp, err := h3.RoundTrip(req)
		if err != nil {
			t.Fatalf("%s: %v", method, err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	if code, b := do(http.MethodGet, nil); code != 200 || !strings.HasPrefix(b, "HTTP/2.0 GET 0") {
		t.Fatalf("GET: %d %q", code, b)
	}
	// POST ohne Laenge bleibt, wie er ist
	if code, b := do(http.MethodPost, io.MultiReader(strings.NewReader("abc"))); code != 200 || !strings.HasSuffix(b, ` "abc"`) {
		t.Fatalf("POST: %d %q", code, b)
	}
	// DELETE mit Inhalt (selten, aber erlaubt): Inhalt kommt vollstaendig an
	if code, b := do(http.MethodDelete, io.MultiReader(strings.NewReader("xyz"))); code != 200 || !strings.HasSuffix(b, ` "xyz"`) {
		t.Fatalf("DELETE: %d %q", code, b)
	}
}

// h3Body ohne Netz: leerer Inhalt, Inhalt, Fehler, Ende zu spaet.
func TestH3BodyProbe(t *testing.T) {
	req := func(m string, body io.ReadCloser) *http.Request {
		r := httptest.NewRequest(m, "/", nil)
		r.Body, r.ContentLength = body, -1
		return r
	}
	r := req(http.MethodGet, io.NopCloser(strings.NewReader("")))
	H3Body(r)
	if r.Body != http.NoBody || r.ContentLength != 0 {
		t.Fatalf("leer: %v %d", r.Body, r.ContentLength)
	}
	r = req(http.MethodGet, io.NopCloser(strings.NewReader("hallo")))
	H3Body(r)
	if b, _ := io.ReadAll(r.Body); string(b) != "hallo" || r.ContentLength != -1 {
		t.Fatalf("Inhalt: %q %d", b, r.ContentLength)
	}
	boom := errors.New("boom")
	r = req(http.MethodGet, io.NopCloser(iotestErr{boom}))
	H3Body(r)
	if _, err := io.ReadAll(r.Body); !errors.Is(err, boom) {
		t.Fatalf("Fehler: %v", err)
	}
	r = req(http.MethodPost, io.NopCloser(strings.NewReader("")))
	H3Body(r)
	if r.Body == http.NoBody || r.ContentLength != -1 {
		t.Fatal("POST bleibt unveraendert")
	}
	// Ende kommt erst nach der Wartezeit: Inhalt bleibt unbekannt lang, Lesen liefert trotzdem alles
	old := h3ProbeWait
	h3ProbeWait = 10 * time.Millisecond
	defer func() { h3ProbeWait = old }()
	pr, pw := io.Pipe()
	r = req(http.MethodGet, pr)
	H3Body(r)
	if r.Body == http.NoBody {
		t.Fatal("zu frueh als leer erkannt")
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		_, _ = pw.Write([]byte("spaet"))
		pw.Close()
	}()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r.Body); err != nil || buf.String() != "spaet" {
		t.Fatalf("spaet: %q %v", buf.String(), err)
	}
}

type iotestErr struct{ err error }

func (e iotestErr) Read([]byte) (int, error) { return 0, e.err }
