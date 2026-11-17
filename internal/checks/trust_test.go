package checks

import (
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// #190: Ein Dienst mit Zertifikat einer eigenen CA der Node gilt bei HTTPS- und Zertifikats-Checks als vertrauenswuerdig.
func TestOwnCATrust(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tls ok")) }))
	defer srv.Close()
	r := testRunner()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/"
	host := strings.TrimPrefix(strings.TrimSuffix(base, "/"), "https://")
	viaName := HTTPParams{Headers: map[string]string{"Host": "example.com"}} // httptest-Zertifikat gilt fuer example.com
	certP := CertParams{ServerName: "example.com"}
	if res := one(t, r, def(TypeHTTP, base, viaName)); res.Reason != ReasonTLSFailed {
		t.Fatalf("unknown CA must fail: %+v", res)
	}
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate()) // steht hier fuer die eigene CA
	SetTrustPool(func() *x509.CertPool { return pool })
	t.Cleanup(func() { SetTrustPool(nil) })
	if res := one(t, r, def(TypeHTTP, base, viaName)); res.Status != Up {
		t.Fatalf("own CA: %+v", res)
	}
	if res := one(t, r, def(TypeCert, host, certP)); res.Status != Up {
		t.Fatalf("cert check with own CA: %+v", res)
	}
	// Quelle ohne eigene CA (nil) = System-CAs
	SetTrustPool(func() *x509.CertPool { return nil })
	if res := one(t, r, def(TypeCert, host, certP)); res.Reason != ReasonCertInvalid {
		t.Fatalf("without own CA: %+v", res)
	}
}
