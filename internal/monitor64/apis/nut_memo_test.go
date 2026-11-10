package apis

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
)

// "upsd hat schon TLS gesprochen" gilt ueber Neustarts: der Kern merkt sich Remembered() und gibt es dem neuen Sammler
// per Remember() zurueck - lehnt upsd STARTTLS danach ab, ist das ein Fehler statt Klartext (wie ohne Neustart).
func TestNUTRememberTLS(t *testing.T) {
	f := nutFake(t)
	cert, pin := testCert(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	newNUT := func() *NUT {
		n, err := NewNUT(NUTConfig{Address: f.addr(), Pin: pin})
		if err != nil {
			t.Fatal(err)
		}
		n.cfg.Pin, n.pin = "", "" // Modus auto ohne Pflicht, Zertifikat vertraut
		n.roots = x509.NewCertPool()
		n.roots.AddCert(leaf)
		return n
	}
	f.mu.Lock()
	f.cert = &cert
	f.mu.Unlock()
	n := newNUT()
	if n.Remembered() != nil {
		t.Fatalf("fresh collector: %v", n.Remembered())
	}
	if _, err := n.Collect(context.Background()); err != nil && !IsPartial(err) {
		t.Fatalf("with TLS: %v", err)
	}
	mem := n.Remembered()
	if len(mem) != 1 || !strings.HasPrefix(mem[0], "tls:") {
		t.Fatalf("remembered: %v", mem)
	}
	// upsd bietet kein TLS mehr an; "Neustart": neuer Sammler
	f.mu.Lock()
	f.cert = nil
	f.mu.Unlock()
	fresh := newNUT() // ohne gemerkten Stand: Klartext (lesen ohne Anmeldung) - der Fall, den das Merken verhindert
	if _, err := fresh.Collect(context.Background()); err != nil && !IsPartial(err) {
		t.Fatalf("without remembered state: %v", err)
	}
	other := newNUT()
	other.Remember([]string{"tls:192.0.2.1:3493"}) // Stand einer anderen Adresse gilt nicht
	if _, err := other.Collect(context.Background()); err != nil && !IsPartial(err) {
		t.Fatalf("state of another address: %v", err)
	}
	restarted := newNUT()
	restarted.Remember(mem)
	_, err = restarted.Collect(context.Background())
	// Text des Fehlers: Klartext bzw. uebersetzbarer Schluessel (monitor64.txt.nut_tls_gone)
	if err == nil || IsPartial(err) || !strings.Contains(deErr(err), "bisher TLS") && !strings.Contains(deErr(err), "nut_tls_gone") {
		t.Fatalf("rejected STARTTLS after restart: %v", err)
	}
}
