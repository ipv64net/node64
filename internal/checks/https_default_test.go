package checks

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #234: Web-Adressen ohne Schema gelten bei der Eingabe als https://; gespeicherte ohne Schema bleiben http://.
func TestWithHTTPS(t *testing.T) {
	for in, want := range map[string]string{
		"example.com/status":   "https://example.com/status",
		" http://example.com ": "http://example.com",
		"https://example.com":  "https://example.com",
		"2001:db8::1/x":        "https://[2001:db8::1]/x",
		"":                     "",
	} {
		if got := WithHTTPS(in); got != want {
			t.Errorf("WithHTTPS(%q) = %q, want %q", in, got, want)
		}
	}
	if u, _ := parseURL("example.com"); u.Scheme != "http" {
		t.Fatalf("stored target without scheme: %s", u)
	}
}

// #234: HTTPS mit Zertifikatswarnung verlangt, aber auf unverschluesseltes HTTP umgeleitet: gestoert.
func TestHTTPSDowngradeRedirect(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("plain")) }))
	defer plain.Close()
	target := strings.Replace(plain.URL, "127.0.0.1", "localhost", 1)
	tsrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target+"/", http.StatusFound) }))
	defer tsrv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(tsrv.Certificate()) // httptest-Zertifikat gilt fuer example.com
	SetTrustPool(func() *x509.CertPool { return pool })
	t.Cleanup(func() { SetTrustPool(nil) })
	base := strings.Replace(tsrv.URL, "127.0.0.1", "localhost", 1) + "/"
	viaName := func(days int) HTTPParams {
		return HTTPParams{Headers: map[string]string{"Host": "example.com"}, CertMinDays: days}
	}
	r := testRunner()
	if res := one(t, r, def(TypeHTTP, base, viaName(14))); res.Reason != ReasonTLSFailed || !strings.Contains(res.Message, "unencrypted") {
		t.Fatalf("downgrade with cert threshold must fail: %+v", res)
	}
	if res := one(t, r, def(TypeHTTP, base, viaName(0))); res.Status != Up {
		t.Fatalf("without cert threshold the redirect is fine: %+v", res)
	}
}
