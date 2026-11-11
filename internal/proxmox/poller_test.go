package proxmox

import (
	"context"
	"crypto/x509"
	"strings"
	"testing"
	"time"
)

func TestClampInterval(t *testing.T) {
	for in, want := range map[int]time.Duration{0: 30 * time.Second, 5: 15 * time.Second, 60: time.Minute, 999: 300 * time.Second} {
		if got := ClampInterval(in); got != want {
			t.Errorf("%d: %v", in, got)
		}
	}
}

func TestProbe(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	ctx := context.Background()
	// selbstsigniert, ohne Pin: nur Fingerabdruck zeigen, das Token geht nicht an das unbestaetigte Zertifikat
	r := probe(ctx, testSys("", srv.URL), x509.NewCertPool(), time.Second, 2*time.Second)
	if r.OK || !r.NeedConfirm || r.Error != "" || r.CertTrusted || r.CertSHA256 != pinOf(srv) || !strings.Contains(r.CertSubject, "Acme") || r.Version != "" {
		t.Fatalf("untrusted: %+v", r)
	}
	f.mu.Lock()
	sent := len(f.auths)
	f.mu.Unlock()
	if sent != 0 {
		t.Fatalf("token sent to an unconfirmed certificate (%d requests)", sent)
	}
	// bestaetigt: Test mit diesem Fingerabdruck als Pin
	r = probe(ctx, testSys(r.CertSHA256, srv.URL), x509.NewCertPool(), time.Second, 2*time.Second)
	if !r.OK || r.NeedConfirm || r.CertTrusted {
		t.Fatalf("confirmed: %+v", r)
	}
	if r.Version != "8.2.4" || r.Cluster != "lab" || strings.Join(r.Nodes, ",") != "pve1,pve2,pve3" || r.Guests != 10 || r.PermWarning != "" {
		t.Fatalf("data: %+v", r)
	}
	// CA bestaetigt
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	if r := probe(ctx, testSys("", srv.URL), roots, time.Second, 2*time.Second); !r.OK || !r.CertTrusted {
		t.Fatalf("trusted: %+v", r)
	}
	// falscher Pin: Fehler, aber Zertifikat sichtbar
	r = probe(ctx, testSys(strings.Repeat("0", 64), srv.URL), nil, time.Second, 2*time.Second)
	if r.OK || r.CertSHA256 != pinOf(srv) || !strings.Contains(r.Error, "certificate mismatch") {
		t.Fatalf("wrong pin: %+v", r)
	}
	// falsches Secret
	bad := testSys(pinOf(srv), srv.URL)
	bad.Secret = "x"
	if r := probe(ctx, bad, nil, time.Second, 2*time.Second); r.OK || !strings.Contains(r.Error, "401") {
		t.Fatalf("bad token: %+v", r)
	}
	// Token mit Privilege Separation ohne eigene Rechte: erreichbar, aber Hinweis
	f.set(func(f *fakePVE) { f.noRights = true })
	r = probe(ctx, testSys(pinOf(srv), srv.URL), nil, time.Second, 2*time.Second)
	if !r.OK || r.Guests != 0 || !strings.Contains(r.PermWarning, "PVEAuditor") || !strings.Contains(r.PermWarning, testTokenID) {
		t.Fatalf("no rights: %+v", r)
	}
	// nicht erreichbar, zweite Adresse geht
	r = probe(ctx, testSys(pinOf(srv), deadAddr(t), srv.URL), nil, time.Second, 2*time.Second)
	if !r.OK || r.CertSHA256 == "" {
		t.Fatalf("second address: %+v", r)
	}
	if r := probe(ctx, testSys("", deadAddr(t)), nil, time.Second, time.Second); r.OK || !strings.Contains(r.Error, "not reachable") {
		t.Fatalf("dead: %+v", r)
	}
}
