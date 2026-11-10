package apis

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// testCert erzeugt ein selbstsigniertes Zertifikat fuer 127.0.0.1 und liefert es mit Fingerabdruck.
func testCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "upsd-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, proxmox.CertFingerprint(der)
}

// treeAPI liefert JSON-Dateien aus testdata/<dir> je Pfad (Pfad ohne fuehrenden Schraegstrich, "/" -> "_", ".json")
// bzw. feste Antworten; zaehlt Anfragen und merkt Kopfzeilen.
type treeAPI struct {
	t      *testing.T
	dir    string
	mu     sync.Mutex
	fixed  map[string]fakeResp // Pfad (mit Methode, z. B. "GET /x") -> Antwort
	hits   map[string]int
	hdrs   []http.Header
	before func(w http.ResponseWriter, r *http.Request) bool // true = beantwortet
}

func newTreeAPI(t *testing.T, dir string) *treeAPI {
	return &treeAPI{t: t, dir: dir, fixed: map[string]fakeResp{}, hits: map[string]int{}}
}

func (a *treeAPI) set(methodPath string, status int, body string) {
	a.mu.Lock()
	a.fixed[methodPath] = fakeResp{status: status, body: body}
	a.mu.Unlock()
}

func (a *treeAPI) count(methodPath string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.hits[methodPath]
}

func (a *treeAPI) headers() []http.Header {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]http.Header(nil), a.hdrs...)
}

func (a *treeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	a.mu.Lock()
	a.hits[key]++
	a.hdrs = append(a.hdrs, r.Header.Clone())
	fx, ok := a.fixed[key]
	before := a.before
	a.mu.Unlock()
	if before != nil && before(w, r) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if ok {
		w.WriteHeader(fx.status)
		_, _ = w.Write([]byte(fx.body))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	name := strings.Trim(r.URL.Path, "/")
	name = strings.ReplaceAll(name, "/", "_") + ".json"
	b, err := os.ReadFile(filepath.Join("testdata", a.dir, name))
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"Base.1.0.ResourceMissingAtURI","message":"not found"}}`))
		return
	}
	_, _ = w.Write(b)
}

func TestParseWebAddr(t *testing.T) {
	for _, c := range []struct {
		in, def   string
		http      bool
		want, err string
	}{
		{"truenas", "https", false, "https://truenas:443", ""},
		{"https://NAS.lan:8443/", "https", false, "https://nas.lan:8443", ""},
		{"fd00::10", "https", false, "https://[fd00::10]:443", ""},
		{"http://tower", "http", true, "http://tower:80", ""},
		{"tower", "http", true, "http://tower:80", ""},
		{"http://tower", "https", false, "", "nur https"},
		{"https://user:pw@host", "https", false, "", "ungültige"},
		{"https://host/api/v2.0", "https", false, "", "ohne Pfad"},
		{"https://host:99999", "https", false, "", "Port"},
		{"ftp://host", "https", true, "", "http:// oder https://"},
		{"", "https", false, "", "keine Adresse"},
	} {
		got, err := parseWebAddr(c.in, c.def, "", c.http)
		if c.err != "" {
			if err == nil || !strings.Contains(deErr(err), c.err) {
				t.Errorf("%q: Fehler %v, erwartet %q", c.in, err, c.err)
			}
			continue
		}
		if err != nil || got.base != c.want {
			t.Errorf("%q = %q, %v; erwartet %q", c.in, got.base, err, c.want)
		}
	}
}

func TestWebClientLimits(t *testing.T) {
	big := strings.Repeat("x", webMaxBody+10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(`"` + big + `"`))
		case "/redir":
			http.Redirect(w, r, "https://elsewhere/", http.StatusFound)
		case "/err":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"kaputt\nzweite Zeile"}`))
		case "/gql":
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"errors":[{"message":"Cannot query field \"x\" on type \"Query\"."}]}`))
		case "/auth":
			w.WriteHeader(http.StatusUnauthorized)
		case "/notjson":
			_, _ = w.Write([]byte(`<html>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	tg, err := parseWebAddr(srv.URL, "http", "", true)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newWebClient(tg, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var s string
	if err := c.get(context.Background(), "/big", &s); err == nil || !strings.Contains(deErr(err), "zu groß") {
		t.Errorf("big: %v", err)
	}
	if err := c.get(context.Background(), "/redir", &s); err == nil || !strings.Contains(deErr(err), "Weiterleitung nach https://elsewhere/") {
		t.Errorf("redir: %v", err)
	}
	err = c.get(context.Background(), "/err", &s)
	if err == nil || !strings.Contains(deErr(err), "HTTP 500 (kaputt zweite Zeile) bei GET /err") {
		t.Errorf("err: %v", err)
	}
	if err := c.get(context.Background(), "/gql", &s); !gqlSchema(err) {
		t.Errorf("gql: %v", err)
	}
	if err := c.get(context.Background(), "/auth", &s); !webAuthErr(err) || !strings.Contains(deErr(err), "401") {
		t.Errorf("auth: %v", err)
	}
	if err := c.get(context.Background(), "/notjson", &s); err == nil || !strings.Contains(deErr(err), "kein passendes JSON") {
		t.Errorf("notjson: %v", err)
	}
	if err := c.get(context.Background(), "/missing", &s); !webAbsent(err) {
		t.Errorf("missing: %v", err)
	}
	if _, err := newWebClient(tg, "ab", nil); err == nil {
		t.Error("ungültiger Pin angenommen")
	}
	pin := strings.Repeat("a", 64)
	if _, err := newWebClient(tg, pin, nil); err == nil {
		t.Error("Pin mit http:// angenommen")
	}
}

func TestWebClientPin(t *testing.T) {
	addr, pin := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	tg, _ := parseWebAddr(addr, "https", "", false)
	var out struct{ OK bool }
	// ohne Pin: selbstsigniert, nicht vertrauenswuerdig
	c, _ := newWebClient(tg, "", nil)
	if err := c.get(context.Background(), "/", &out); !errors.Is(err, errWebTrust) {
		t.Errorf("ohne Pin: %v", err)
	}
	// falscher Pin
	c, _ = newWebClient(tg, strings.Repeat("0", 64), nil)
	if err := c.get(context.Background(), "/", &out); !errors.Is(err, errWebCert) {
		t.Errorf("falscher Pin: %v", err)
	}
	c, _ = newWebClient(tg, strings.ToUpper(pin[:2])+":"+pin[2:], nil)
	if err := c.get(context.Background(), "/", &out); err != nil || !out.OK {
		t.Errorf("Pin: %v %+v", err, out)
	}
	// probeCert: ohne Pin NeedConfirm, mit falschem Pin Fehler, mit Pin weiter
	res, ok := probeCert(context.Background(), tg, "", nil)
	if ok || !res.NeedConfirm || res.Fingerprint != pin || res.Trusted {
		t.Errorf("probe ohne Pin: %+v %v", res, ok)
	}
	res, ok = probeCert(context.Background(), tg, strings.Repeat("1", 64), nil)
	if ok || res.Error == "" {
		t.Errorf("probe falscher Pin: %+v", res)
	}
	if _, ok = probeCert(context.Background(), tg, pin, nil); !ok {
		t.Error("probe mit Pin abgelehnt")
	}
}

func TestStripTagsAndShort(t *testing.T) {
	in := `Pool <b>tank</b> state is DEGRADED: One or more devices<br>has been removed. <a href="/ui/storage">Storage</a> &amp; more`
	if got := stripTags(in); got != "Pool tank state is DEGRADED: One or more devices has been removed. Storage & more" {
		t.Errorf("stripTags = %q", got)
	}
	if got := shortText(strings.Repeat("ä", 300)); len([]rune(got)) != 201 {
		t.Errorf("shortText %d Zeichen", len([]rune(got)))
	}
}

func TestOptFAndTime(t *testing.T) {
	var v struct {
		A, B, C, D, E optF
		T1, T2, T3    tnTime
	}
	if err := json.Unmarshal([]byte(`{"A":1.5,"B":"42","C":null,"D":"NaN","E":"Infinity","T1":{"$date":1731150000000},"T2":1731150000,"T3":"2024-11-09T11:00:00Z"}`), &v); err != nil {
		t.Fatal(err)
	}
	if !v.A.Set || v.A.V != 1.5 || !v.B.Set || v.B.V != 42 || v.C.Set || v.D.Set || v.E.Set {
		t.Errorf("optF = %+v", v)
	}
	want := time.Unix(1731150000, 0)
	if !v.T1.T.Equal(want) || !v.T2.T.Equal(want) || !v.T3.T.Equal(time.Date(2024, 11, 9, 11, 0, 0, 0, time.UTC)) {
		t.Errorf("tnTime = %v %v %v", v.T1.T, v.T2.T, v.T3.T)
	}
}
