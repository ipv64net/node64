package checks

import (
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	SetTrustPool(func() (*x509.CertPool, error) { return pool, nil })
	t.Cleanup(func() { SetTrustPool(nil) })
	if res := one(t, r, def(TypeHTTP, base, viaName)); res.Status != Up {
		t.Fatalf("own CA: %+v", res)
	}
	if res := one(t, r, def(TypeCert, host, certP)); res.Status != Up {
		t.Fatalf("cert check with own CA: %+v", res)
	}
	// Lesefehler der Quelle: der bisherige Pool gilt weiter, gemerkt wird der Fehler nicht
	broken := func() (*x509.CertPool, error) { return nil, errors.New("database is locked") }
	trustSource.Store(&broken)
	trustCache.Lock()
	trustCache.at = time.Time{}
	trustCache.Unlock()
	if res := one(t, r, def(TypeCert, host, certP)); res.Status != Up || !trustCache.at.IsZero() {
		t.Fatalf("read error keeps pool: %+v", res)
	}
	SetTrustPool(broken) // neue Quelle ohne bisherigen Pool: System-CAs, naechster Check fragt erneut
	if res := one(t, r, def(TypeCert, host, certP)); res.Reason != ReasonCertInvalid || !trustCache.at.IsZero() {
		t.Fatalf("read error without pool: %+v", res)
	}
	// Quelle ohne eigene CA (nil) = System-CAs
	SetTrustPool(func() (*x509.CertPool, error) { return nil, nil })
	if res := one(t, r, def(TypeCert, host, certP)); res.Reason != ReasonCertInvalid {
		t.Fatalf("without own CA: %+v", res)
	}
}
