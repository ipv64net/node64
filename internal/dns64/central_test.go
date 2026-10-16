package dns64

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/secrets"
)

// centralMgr: Zertifikatsverwaltung auf der Datenbank des Test-Moduls.
func centralMgr(t *testing.T, m *Module) *certs.Manager {
	t.Helper()
	ctx := context.Background()
	ms, err := certs.Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.core.Migrate(ctx, "certs", ms); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	mgr, err := certs.New(ctx, certs.Deps{Store: m.core, Box: box, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mgr.Close)
	return mgr
}

// dotLeaf: das Zertifikat, das DoT ausliefert.
func dotLeaf(t *testing.T, port int) *x509.Certificate {
	t.Helper()
	c, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"dot"}}) //nolint:gosec // nur auslesen
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0]
}

// Umzug: Let's-Encrypt-Zertifikat und Heimnetz-CA gehen einmal in die Verwaltung, DNS64 nutzt danach das
// Zertifikat von dort (gleicher Schluessel), die Zustimmung zu den Nutzungsbedingungen wird uebernommen.
func TestCentralMigrationACME(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	if _, _, err := m.loadOrCreateCA(); err != nil { // vorhandene Heimnetz-CA
		t.Fatal(err)
	}
	// vorhandenes "Let's-Encrypt"-Zertifikat fuer dns.home.ipv64.de
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "dns.home.ipv64.de"}, DNSNames: []string{"dns.home.ipv64.de"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	_ = os.MkdirAll(m.acmeDir(), 0o700)
	_ = os.WriteFile(filepath.Join(m.acmeDir(), "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	_ = os.WriteFile(filepath.Join(m.acmeDir(), "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	c := m.loadConfig(ctx)
	c.DoT, c.DoTPort = true, freePort(t)
	c.CertMode, c.ACMEDomain, c.ACMEPrefix, c.ACMEEmail = certACME, "home.ipv64.de", "dns", "admin@example.org"
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	_ = m.core.SetSetting(ctx, setACMETOS, time.Now().UTC().Format(time.RFC3339))

	mgr := centralMgr(t, m)
	m.SetCerts(mgr)
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	c = m.loadConfig(ctx)
	if c.CertMode != certCentral || c.CertID == 0 || m.core.SettingOr(ctx, setCentralDone, "") == "" {
		t.Fatalf("not moved: mode=%s id=%d", c.CertMode, c.CertID)
	}
	if !mgr.Account(ctx).TOSAccepted || mgr.Account(ctx).Email != "admin@example.org" {
		t.Fatalf("account = %+v", mgr.Account(ctx))
	}
	if leaf := dotLeaf(t, c.DoTPort); leaf.SerialNumber.Int64() != 42 {
		t.Fatalf("served serial %v, want the imported certificate", leaf.SerialNumber)
	}
	if m.certInUse.Load() != c.CertID {
		t.Fatalf("in use %d, want %d", m.certInUse.Load(), c.CertID)
	}
	// CA mit gleichem Fingerabdruck in der Verwaltung
	cas, err := mgr.CAs(ctx)
	if err != nil || len(cas) != 1 {
		t.Fatalf("cas = %v %v", cas, err)
	}
	b, _ := pem.Decode(mustRead(t, m.caFile()))
	if sum := sha256.Sum256(b.Bytes); cas[0].Fingerprint != hexColon(sum[:]) && cas[0].Fingerprint != hexPlain(sum[:]) {
		t.Fatalf("ca fingerprint %s", cas[0].Fingerprint)
	}
	// zweiter Start: kein zweiter Umzug, gleiches Zertifikat
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = m.Stop(sctx)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := mgr.List(ctx); len(list) != 1 {
		t.Fatalf("certificates after restart: %d", len(list))
	}
}

// Heimnetz-CA in der Verwaltung: das Server-Zertifikat stellt die Verwaltung aus (von der bisherigen CA), ein
// Neustart stellt nicht neu aus; ein neu ausgestelltes gilt sofort (OnChange).
func TestCentralSelf(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.DoT, c.DoTPort, c.Names = true, freePort(t), []string{"dns.home.lan"}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	mgr := centralMgr(t, m)
	m.SetCerts(mgr)
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	own, err := mgr.Owned(ctx, certOwner)
	if err != nil || m.certInUse.Load() != own.ID {
		t.Fatalf("owned %v %v, in use %d", own, err, m.certInUse.Load())
	}
	ca, _, err := m.loadOrCreateCA()
	if err != nil {
		t.Fatal(err)
	}
	leaf := dotLeaf(t, c.DoTPort)
	if leaf.CheckSignatureFrom(ca) != nil {
		t.Fatal("served certificate not from the home CA")
	}
	serial := leaf.SerialNumber.String()
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	_ = m.Stop(sctx)
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dotLeaf(t, c.DoTPort).SerialNumber.String(); got != serial {
		t.Fatal("restart issued a new certificate")
	}
	// Verwaltung stellt neu aus (weiterer Name): DNS64 uebernimmt es ohne Zutun
	caID, _ := strconv.ParseInt(m.core.SettingOr(ctx, setCAID, ""), 10, 64)
	dnsNames, ips := wantedNames(c.Names)
	names := append(dnsNames, "extra.home.lan")
	for _, ip := range ips {
		names = append(names, ip.String())
	}
	if _, err := mgr.EnsureIssued(ctx, certOwner, caID, names, leafDays); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if l := m.cur.Load(); l != nil && l.Leaf != nil && l.Leaf.SerialNumber.String() != serial {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("new certificate not picked up")
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hexPlain(b []byte) string {
	const h = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, x := range b {
		out = append(out, h[x>>4], h[x&15])
	}
	return string(out)
}

func hexColon(b []byte) string {
	const h = "0123456789ABCDEF"
	out := make([]byte, 0, 3*len(b))
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, h[x>>4], h[x&15])
	}
	return string(out)
}
