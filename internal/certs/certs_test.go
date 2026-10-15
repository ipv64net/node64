package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

func (f *fakeDNS) Ready(context.Context) bool { return true }

func (f *fakeDNS) Domains(context.Context) ([]string, error) { return f.domains, nil }

func (f *fakeDNS) AddTXT(_ context.Context, domain, prefix, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fq := prefix + "." + domain
	f.txt[fq] = append(f.txt[fq], value)
	f.added++
	return nil
}

func (f *fakeDNS) DeleteTXT(_ context.Context, domain, prefix, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	fq := prefix + "." + domain
	var keep []string
	for _, v := range f.txt[fq] {
		if v != value {
			keep = append(keep, v)
		}
	}
	if len(keep) == 0 {
		delete(f.txt, fq)
	} else {
		f.txt[fq] = keep
	}
	return nil
}

type env struct {
	m      *Manager
	ca     *fakeCA
	dns    *fakeDNS
	st     *store.Store
	box    *secrets.Box
	mu     sync.Mutex
	alerts []notify.Alert
}

func (e *env) kinds() []notify.Kind {
	e.mu.Lock()
	defer e.mu.Unlock()
	var out []notify.Kind
	for _, a := range e.alerts {
		out = append(out, a.Kind)
	}
	return out
}

func newEnv(t *testing.T, http Presenter) *env {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	cm, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx, "certs", ms); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	box, _ := secrets.New(key)
	e := &env{ca: newFakeCA(t), dns: newFakeDNS("home.ipv64.de", "other.ipv64.net"), st: st, box: box}
	e.ca.txt = e.dns.lookup
	e.m = e.manager(t, http)
	return e
}

func (e *env) manager(t *testing.T, http Presenter) *Manager {
	t.Helper()
	m, err := New(context.Background(), Deps{Store: e.st, Box: e.box, DNS: e.dns, HTTP: http, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "test",
		Directory: e.ca.url("/dir"), StagingDirectory: e.ca.url("/dir"),
		Notify: func(a notify.Alert) { e.mu.Lock(); e.alerts = append(e.alerts, a); e.mu.Unlock() }})
	if err != nil {
		t.Fatal(err)
	}
	m.txtVisible = func(context.Context, string, string, string) error { return nil } // die Test-Stelle sieht die Records sofort
	m.cnameOf = func(_ context.Context, name string) (string, error) {
		e.dns.mu.Lock()
		defer e.dns.mu.Unlock()
		return e.dns.cname[name], nil
	}
	t.Cleanup(m.Close)
	return m
}

// wait wartet, bis der Abruf fertig ist, und liefert den Stand.
func wait(t *testing.T, m *Manager, id int64) *Cert {
	t.Helper()
	for i := 0; i < 200; i++ {
		c, err := m.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if c.Step == "" && c.Status != StatusPending {
			return c
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("issue did not finish")
	return nil
}

func TestIssueIPv64WithWildcard(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	if _, err := e.m.Create(ctx, Request{Names: []string{"nas.home.ipv64.de"}, Source: SourceIPv64}); !errors.Is(err, ErrTOS) {
		t.Fatalf("without accepted terms: %v", err)
	}
	if err := e.m.SetAccount(ctx, "admin@example.test", true); err != nil {
		t.Fatal(err)
	}
	c, err := e.m.Create(ctx, Request{Names: []string{"NAS.home.ipv64.de", "*.home.ipv64.de"}, Source: SourceIPv64})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || c.LastError != "" || c.Issuer != "Fake ACME CA" || c.DaysLeft() < 88 {
		t.Fatalf("issued: %+v", c)
	}
	if e.dns.added != 2 || e.dns.records() != 0 {
		t.Fatalf("TXT records: added %d, left %d", e.dns.added, e.dns.records())
	}
	for _, n := range []string{"nas.home.ipv64.de", "x.home.ipv64.de"} {
		if e.m.ForName(n) == nil {
			t.Errorf("no certificate for %s", n)
		}
	}
	if e.m.ForName("a.b.home.ipv64.de") != nil || e.m.ForName("other.ipv64.net") != nil {
		t.Error("certificate must not match other names")
	}
	chain, err := e.m.Chain(ctx, c.ID)
	if err != nil || strings.Count(chain, "BEGIN CERTIFICATE") != 2 || strings.Contains(chain, "PRIVATE") {
		t.Fatalf("chain: %v %q", err, chain)
	}
	var keyCol string
	_ = e.st.Reader().QueryRowContext(ctx, `SELECT key_pem FROM certs WHERE id = ?`, c.ID).Scan(&keyCol)
	if !secrets.IsEncrypted(keyCol) {
		t.Fatal("private key must be stored encrypted")
	}
	// nach einem Neustart wieder da
	m2 := e.manager(t, nil)
	if m2.ForName("nas.home.ipv64.de") == nil || m2.ByID(c.ID) == nil {
		t.Fatal("certificate must survive a restart")
	}
	if len(e.kinds()) != 0 {
		t.Fatalf("no alerts expected: %v", e.kinds())
	}
}

func TestCreateValidation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_ = e.m.SetAccount(ctx, "", true)
	var ve *ValidationError
	cases := []Request{
		{Names: []string{"nas.example.com"}, Source: SourceIPv64},                        // nicht im Account
		{Names: []string{"*.example.com"}, Source: SourceHTTP},                           // HTTP-01 ohne Eingang
		{Names: []string{"a.example.com"}, Source: SourceAlias, AliasZone: "foreign.de"}, // Ziel nicht im Account
		{Names: []string{"a.example.com"}, Source: SourceAlias, AliasZone: ""},           // Ziel fehlt
		{Names: []string{"bad name"}, Source: SourceIPv64},                               // ungueltig
		{Names: []string{"a.home.ipv64.de"}, Source: "dns:cloudflare"},                   // unbekannter Weg
		{Names: nil, Source: SourceIPv64},                                                // keine Namen
		{Names: []string{"a.example.com"}, Source: SourceAlias, AliasZone: "home.ipv64.de", AliasPrefix: "a b"},
	}
	for i, req := range cases {
		if _, err := e.m.Create(ctx, req); !errors.As(err, &ve) {
			t.Errorf("case %d: want validation error, got %v", i, err)
		}
	}
	if err := e.m.SetAccount(ctx, "not-an-address", true); err == nil {
		t.Error("invalid email must be refused")
	}
}

func TestAliasNeedsCNAME(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_ = e.m.SetAccount(ctx, "", true)
	c, err := e.m.Create(ctx, Request{Names: []string{"www.example.com", "example.com"}, Source: SourceAlias, AliasZone: "home.ipv64.de", AliasPrefix: "le"})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusError || !strings.Contains(c.LastError, "CNAME _acme-challenge.www.example.com -> _acme-challenge.le.home.ipv64.de missing") {
		t.Fatalf("missing CNAME: %+v", c)
	}
	if k := e.kinds(); len(k) != 1 || k[0] != notify.KindCertFail {
		t.Fatalf("one failure alert expected: %v", k)
	}
	// noch einmal ohne CNAME: keine zweite Meldung
	if err := e.m.Renew(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	wait(t, e.m, c.ID)
	if len(e.kinds()) != 1 {
		t.Fatalf("failure must be reported once: %v", e.kinds())
	}
	from1, to := AliasCNAME("www.example.com", "home.ipv64.de", "le")
	from2, _ := AliasCNAME("example.com", "home.ipv64.de", "le")
	e.dns.mu.Lock()
	e.dns.cname[from1], e.dns.cname[from2] = to+".", to
	e.dns.mu.Unlock()
	if err := e.m.Renew(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || e.m.ForName("www.example.com") == nil {
		t.Fatalf("alias issue: %+v", c)
	}
	if k := e.kinds(); len(k) != 2 || k[1] != notify.KindCertOK {
		t.Fatalf("ok alert expected: %v", k)
	}
	if e.dns.records() != 0 {
		t.Fatal("TXT records must be removed")
	}
}

func TestHTTP01ThroughEdge(t *testing.T) {
	ctx := context.Background()
	port := 0
	for port == 0 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port = ln.Addr().(*net.TCPAddr).Port
		ln.Close()
	}
	eg, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPPort: port, HTTPSPort: 0, Default: edge.DefaultNotFound}, nil, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer eg.Close(ctx)
	e := newEnv(t, eg)
	e.ca.httpGet = func(name, token string) (string, error) {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(port)+"/.well-known/acme-challenge/"+token, nil)
		req.Host = name
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b), nil
	}
	_ = e.m.SetAccount(ctx, "", true)
	c, err := e.m.Create(ctx, Request{Names: []string{"app.example.com"}, Source: SourceHTTP, Staging: true})
	if err != nil {
		t.Fatal(err)
	}
	c = wait(t, e.m, c.ID)
	if c.Status != StatusValid || !c.Staging {
		t.Fatalf("http-01: %+v", c)
	}
	for _, l := range eg.Status().Listeners {
		if l.Running {
			t.Fatalf("port 80 must be closed after the challenge: %+v", l)
		}
	}
}

func selfSignedPEM(t *testing.T, days int, names ...string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, Issuer: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Duration(days) * 24 * time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	kd, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
}

func TestUploadInUseAndExpiryWarning(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	certPEM, keyPEM := selfSignedPEM(t, 10, "files.example.org")
	_, otherKey := selfSignedPEM(t, 10, "x.example.org")
	var ve *ValidationError
	if _, err := e.m.Upload(ctx, certPEM, otherKey); !errors.As(err, &ve) {
		t.Fatalf("key mismatch: %v", err)
	}
	oldCert, oldKey := selfSignedPEM(t, -1, "old.example.org")
	if _, err := e.m.Upload(ctx, oldCert, oldKey); !errors.As(err, &ve) {
		t.Fatalf("expired: %v", err)
	}
	c, err := e.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != SourceUpload || c.AutoRenew || c.Status != StatusValid || e.m.ForName("files.example.org") == nil {
		t.Fatalf("upload: %+v", c)
	}
	if err := e.m.Renew(ctx, c.ID); !errors.Is(err, ErrUpload) {
		t.Fatalf("renew upload: %v", err)
	}
	e.m.SetUsers("cdn64", func(context.Context) map[int64][]string { return map[int64][]string{c.ID: {"files.example.org"}} })
	if err := e.m.Delete(ctx, c.ID, false); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete in use: %v", err)
	}
	// Erneuerung/Warnung laeuft nur, solange ein Abnehmer die Verwaltung haelt
	e.m.loopFirst, e.m.loopEvery = 10*time.Millisecond, 20*time.Millisecond
	e.m.Acquire("cdn64")
	time.Sleep(150 * time.Millisecond)
	e.m.Release("cdn64")
	if k := e.kinds(); len(k) != 1 || k[0] != notify.KindCertExpiry {
		t.Fatalf("one expiry warning expected: %v", k)
	}
	if err := e.m.Delete(ctx, c.ID, true); err != nil {
		t.Fatal(err)
	}
	if e.m.ForName("files.example.org") != nil {
		t.Fatal("deleted certificate must be gone")
	}
}

func TestRenewalDue(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	_ = e.m.SetAccount(ctx, "", true)
	e.ca.validity = 20 * 24 * time.Hour // unter 30 Tagen: faellig
	c, err := e.m.Create(ctx, Request{Names: []string{"a.home.ipv64.de"}, Source: SourceIPv64})
	if err != nil {
		t.Fatal(err)
	}
	wait(t, e.m, c.ID)
	e.ca.mu.Lock()
	e.ca.validity = 90 * 24 * time.Hour
	e.ca.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // ohne Abnehmer: keine Erneuerung
	e.ca.mu.Lock()
	issued := e.ca.issued
	e.ca.mu.Unlock()
	if issued != 1 {
		t.Fatalf("no renewal without consumer: %d", issued)
	}
	e.m.loopFirst, e.m.loopEvery = 10*time.Millisecond, 20*time.Millisecond
	e.m.Acquire("cdn64")
	defer e.m.Release("cdn64")
	for i := 0; i < 100; i++ {
		if c, _ := e.m.Get(ctx, c.ID); c.DaysLeft() > 80 {
			e.ca.mu.Lock()
			issued = e.ca.issued
			e.ca.mu.Unlock()
			if issued != 2 {
				t.Fatalf("renewed once expected: %d", issued)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("certificate was not renewed")
}

func TestNeedsRenewalBackoff(t *testing.T) {
	c := &Cert{Status: StatusError, LastAttempt: time.Now().Add(-time.Hour)}
	if needsRenewal(c) {
		t.Fatal("retry only after 6 hours")
	}
	c.LastAttempt = time.Now().Add(-7 * time.Hour)
	if !needsRenewal(c) {
		t.Fatal("retry after 6 hours")
	}
	c = &Cert{Status: StatusValid, hasCert: true, NotAfter: time.Now().Add(60 * 24 * time.Hour)}
	if needsRenewal(c) {
		t.Fatal("not due yet")
	}
}
