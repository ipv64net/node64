package proxmox

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
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Nachgebauter Proxmox: version, cluster/status, cluster/resources, nodes/{n}/qemu/{id}/status/current.

const testTokenID, testSecret = "monitor@pve!node64", "11111111-2222-3333-4444-555555555555"

type fakePVE struct {
	mu        sync.Mutex
	resources []map[string]any
	status    []map[string]any
	qmp       map[string]string // "node/vmid" -> qmpstatus
	hits      map[string]int    // Pfad -> Anzahl
	auths     []string          // gesehene Authorization-Header
	methods   []string
	code      int                         // != 0: jede Anfrage mit diesem Status beantworten
	noRights  bool                        // Token mit Privilege Separation ohne eigene Rechte
	delay     time.Duration               // Antwort verzoegern
	certs     map[string][]map[string]any // Node -> certificates/info
	noCerts   bool                        // certificates/info: 403
	version   string
	ifaces    map[string]any // "node/qemu/vmid" bzw. "node/lxc/vmid" -> Antwort von agent/network-get-interfaces bzw. interfaces
}

func (f *fakePVE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.hits[r.URL.Path]++
	f.auths = append(f.auths, r.Header.Get("Authorization"))
	f.methods = append(f.methods, r.Method)
	code, delay, noRights := f.code, f.delay, f.noRights
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	if code != 0 {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"data":null}`))
		return
	}
	if r.Header.Get("Authorization") != "PVEAPIToken="+testTokenID+"="+testSecret {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := strings.TrimPrefix(r.URL.Path, "/api2/json")
	f.mu.Lock()
	defer f.mu.Unlock()
	var data any
	switch {
	case p == "/version":
		data = map[string]any{"version": f.version, "release": "8.2", "repoid": "abc"}
	case p == "/cluster/status":
		if noRights {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"data":null}`))
			return
		}
		data = f.status
	case p == "/cluster/resources":
		if noRights {
			data = []any{}
		} else {
			data = f.resources
		}
	case strings.HasPrefix(p, "/nodes/") && strings.HasSuffix(p, "/certificates/info"):
		if f.noCerts {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		c, ok := f.certs[strings.Split(p, "/")[2]]
		if !ok {
			w.WriteHeader(595)
			return
		}
		data = c
	case strings.HasPrefix(p, "/nodes/") && strings.HasSuffix(p, "/status/current"):
		parts := strings.Split(p, "/") // "", nodes, n, qemu, id, status, current
		q, ok := f.qmp[parts[2]+"/"+parts[4]]
		if !ok {
			w.WriteHeader(595)
			return
		}
		data = map[string]any{"status": "running", "qmpstatus": q}
	case strings.HasPrefix(p, "/nodes/") && (strings.HasSuffix(p, "/agent/network-get-interfaces") || strings.HasSuffix(p, "/interfaces")):
		parts := strings.Split(p, "/") // "", nodes, n, qemu|lxc, id, ...
		d, ok := f.ifaces[parts[2]+"/"+parts[3]+"/"+parts[4]]
		if !ok {
			w.WriteHeader(http.StatusInternalServerError) // wie Proxmox ohne laufenden Gast-Agent
			return
		}
		data = d
	default:
		w.WriteHeader(http.StatusNotImplemented)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
}

func (f *fakePVE) hit(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits["/api2/json"+path]
}

func (f *fakePVE) set(fn func(f *fakePVE)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// guest baut einen Gast-Eintrag wie cluster/resources.
func guest(typ string, vmid int, node, name, status string, extra map[string]any) map[string]any {
	m := map[string]any{
		"id": fmt.Sprintf("%s/%d", typ, vmid), "type": typ, "vmid": vmid, "node": node, "name": name, "status": status,
		"cpu": 0.25, "maxcpu": 4, "mem": 1 << 30, "maxmem": 4 << 30, "disk": 0, "maxdisk": 32 << 30,
		"netin": 1000, "netout": 2000, "diskread": 3000, "diskwrite": 4000, "uptime": 0, "template": 0,
	}
	if status == "running" {
		m["uptime"] = 5000
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func nodeRes(name, status string, uptime int) map[string]any {
	return map[string]any{"id": "node/" + name, "type": "node", "node": name, "status": status, "cpu": 0.1, "maxcpu": 16,
		"mem": 8 << 30, "maxmem": 64 << 30, "disk": 10 << 30, "maxdisk": 100 << 30, "uptime": uptime}
}

// newCluster: 3 Nodes (pve3 offline), Gaeste in allen Zustaenden, LXC, Vorlage, Tags, ein Storage-Eintrag.
func newCluster() *fakePVE {
	return &fakePVE{
		version: "8.2.4",
		hits:    map[string]int{},
		resources: []map[string]any{
			nodeRes("pve1", "online", 100000), nodeRes("pve2", "online", 200000), nodeRes("pve3", "offline", 0),
			guest("qemu", 100, "pve1", "web", "running", map[string]any{"tags": "prod;web", "hastate": "started"}),
			guest("qemu", 101, "pve1", "paused", "running", nil),
			guest("qemu", 102, "pve2", "susp-qmp", "running", nil),
			guest("qemu", 103, "pve1", "backup", "running", map[string]any{"lock": "backup"}),
			guest("qemu", 104, "pve2", "migrating", "running", map[string]any{"lock": "migrate"}),
			guest("qemu", 105, "pve2", "hibernated", "stopped", map[string]any{"lock": "suspended"}),
			guest("qemu", 106, "pve2", "off", "stopped", nil),
			guest("qemu", 107, "pve1", "crashed", "running", nil),
			guest("qemu", 108, "pve3", "on-dead-node", "unknown", nil),
			guest("lxc", 200, "pve2", "ct", "running", map[string]any{"tags": "db"}),
			guest("qemu", 9000, "pve1", "tpl", "stopped", map[string]any{"template": 1}),
			{"id": "storage/pve1/local", "type": "storage", "node": "pve1", "status": "available"},
		},
		status: []map[string]any{
			{"type": "cluster", "name": "lab", "quorate": 1, "nodes": 3, "version": 7},
			{"type": "node", "name": "pve1", "ip": "127.0.0.1", "online": 1, "local": 1},
			{"type": "node", "name": "pve2", "ip": "127.0.0.2", "online": 1},
			{"type": "node", "name": "pve3", "ip": "127.0.0.3", "online": 0},
		},
		qmp: map[string]string{
			"pve1/100": "running", "pve1/101": "paused", "pve2/102": "suspended", "pve1/103": "running",
			"pve2/104": "running", "pve1/107": "guest-panicked",
		},
	}
}

// newSingle: Einzel-Node ohne Cluster (cluster/status nur mit dem Node).
func newSingle() *fakePVE {
	return &fakePVE{
		version:   "8.2.4",
		hits:      map[string]int{},
		resources: []map[string]any{nodeRes("pve", "online", 1000), guest("qemu", 100, "pve", "vm", "running", nil)},
		status:    []map[string]any{{"type": "node", "name": "pve", "ip": "192.0.2.10", "online": 1, "local": 1}},
		qmp:       map[string]string{"pve/100": "running"},
		certs:     map[string][]map[string]any{"pve": {{"filename": "pve-ssl.pem", "fingerprint": strings.Repeat("AB:", 31) + "AB"}}},
	}
}

// genCert erzeugt ein eigenes selbstsigniertes Zertifikat (anderer Fingerabdruck als das von httptest).
func genCert(t *testing.T, ips ...string) tls.Certificate {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "pve-other"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range ips {
		tpl.IPAddresses = append(tpl.IPAddresses, net.ParseIP(ip))
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

// startTLS startet den Nachbau als TLS-Server (Zertifikat von httptest bzw. cert), optional auf fester Adresse.
func startTLS(t *testing.T, h http.Handler, listen string, cert *tls.Certificate) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if listen != "" {
		l, err := net.Listen("tcp", listen)
		if err != nil {
			t.Skipf("cannot listen on %s: %v", listen, err)
		}
		srv.Listener.Close()
		srv.Listener = l
	}
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func pinOf(srv *httptest.Server) string { return CertFingerprint(srv.Certificate().Raw) }

func testSys(pin string, addrs ...string) System {
	return System{ID: 7, Name: "lab", Addresses: addrs, TokenID: testTokenID, Secret: testSecret, PinSHA256: pin, Interval: 30, Enabled: true}
}

func mustClient(t *testing.T, sys System, roots *x509.CertPool) *Client {
	t.Helper()
	c, err := newClient(sys, roots, 2*time.Second, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// deadAddr ist eine Adresse, an der niemand lauscht.
func deadAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return "https://" + a
}

func TestClientTokenHeaderAndGetOnly(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	c := mustClient(t, testSys(pinOf(srv), srv.URL), nil)
	var v pveVersion
	if err := c.Get(context.Background(), "/version", &v); err != nil {
		t.Fatal(err)
	}
	if v.Version != "8.2.4" {
		t.Fatalf("version %q", v.Version)
	}
	if f.auths[0] != "PVEAPIToken=monitor@pve!node64="+testSecret {
		t.Fatalf("auth header %q", f.auths[0])
	}
	for _, m := range f.methods {
		if m != http.MethodGet {
			t.Fatalf("method %s", m)
		}
	}
	if c.Address() != srv.URL {
		t.Fatalf("address %q", c.Address())
	}
}

func TestClientPinning(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	// richtiger Pin, auch mit Doppelpunkten und Grossbuchstaben
	pin := strings.ToUpper(pinOf(srv))
	var colon []string
	for i := 0; i < len(pin); i += 2 {
		colon = append(colon, pin[i:i+2])
	}
	c := mustClient(t, testSys(strings.Join(colon, ":"), srv.URL), nil)
	if err := c.Get(context.Background(), "/version", &pveVersion{}); err != nil {
		t.Fatalf("right pin: %v", err)
	}
	// falscher Pin
	c = mustClient(t, testSys(strings.Repeat("ab", 32), srv.URL), nil)
	err := c.Get(context.Background(), "/version", &pveVersion{})
	if !errors.Is(err, ErrCertMismatch) {
		t.Fatalf("wrong pin: %v", err)
	}
	if !strings.Contains(err.Error(), "certificate mismatch") || !strings.Contains(err.Error(), pinOf(srv)) {
		t.Fatalf("text: %v", err)
	}
	if f.hit("/version") != 1 {
		t.Fatalf("request with wrong pin reached the server")
	}
	// kein Pin, System-CA kennt das Zertifikat nicht
	c = mustClient(t, testSys("", srv.URL), x509.NewCertPool())
	if err := c.Get(context.Background(), "/version", &pveVersion{}); !errors.Is(err, ErrCertInvalid) {
		t.Fatalf("untrusted: %v", err)
	}
	// ungueltiger Pin
	if _, err := NewClient(testSys("abc", srv.URL)); err == nil {
		t.Fatal("invalid pin accepted")
	}
}

func TestClientCA(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	c := mustClient(t, testSys("", srv.URL), roots)
	if err := c.Get(context.Background(), "/version", &pveVersion{}); err != nil {
		t.Fatalf("ca: %v", err)
	}
	// Name passt nicht zum Zertifikat (httptest: 127.0.0.1, example.com) -> nicht vertrauenswuerdig
	other := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	c = mustClient(t, testSys("", other), roots)
	if err := c.Get(context.Background(), "/version", &pveVersion{}); !errors.Is(err, ErrCertInvalid) {
		t.Fatalf("name mismatch: %v", err)
	}
}

func TestClientErrors(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	pin := pinOf(srv)
	ctx := context.Background()

	bad := testSys(pin, srv.URL)
	bad.Secret = "wrong"
	err := mustClient(t, bad, nil).Get(ctx, "/version", &pveVersion{})
	if !errors.Is(err, ErrToken) || !strings.HasPrefix(err.Error(), "401 token invalid") {
		t.Fatalf("401: %v", err)
	}

	f.set(func(f *fakePVE) { f.noRights = true })
	err = mustClient(t, testSys(pin, srv.URL), nil).Get(ctx, "/cluster/status", &[]pveStatusEntry{})
	if !errors.Is(err, ErrPermission) || !strings.Contains(err.Error(), "PVEAuditor") {
		t.Fatalf("403: %v", err)
	}
	f.set(func(f *fakePVE) { f.noRights = false })

	err = mustClient(t, testSys(pin, deadAddr(t)), nil).Get(ctx, "/version", &pveVersion{})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "not reachable") {
		t.Fatalf("unreachable: %v", err)
	}

	f.set(func(f *fakePVE) { f.code = http.StatusInternalServerError })
	err = mustClient(t, testSys(pin, srv.URL), nil).Get(ctx, "/version", &pveVersion{})
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("500: %v", err)
	}
	f.set(func(f *fakePVE) { f.code = 0 })

	// Zeitlimit der Anfrage
	f.set(func(f *fakePVE) { f.delay = 500 * time.Millisecond })
	c, _ := newClient(testSys(pin, srv.URL), nil, time.Second, 100*time.Millisecond)
	start := time.Now()
	err = c.Get(ctx, "/version", &pveVersion{})
	if !errors.Is(err, ErrTimeout) || !strings.HasPrefix(err.Error(), "timeout") {
		t.Fatalf("timeout: %v", err)
	}
	if time.Since(start) > 400*time.Millisecond {
		t.Fatalf("timeout too late: %v", time.Since(start))
	}
	f.set(func(f *fakePVE) { f.delay = 0 })

	// kein JSON
	plain := startTLS(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }), "", nil)
	err = mustClient(t, testSys(pin, plain.URL), nil).Get(ctx, "/version", &pveVersion{})
	if !errors.Is(err, ErrResponse) {
		t.Fatalf("no json: %v", err)
	}

	// falsche Eingaben
	for _, s := range []System{testSys(pin), testSys(pin, "http://pve:8006"), {Addresses: []string{srv.URL}, TokenID: testTokenID}} {
		if _, err := NewClient(s); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}

func TestClientFailoverConfigured(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	dead := deadAddr(t)
	c := mustClient(t, testSys(pinOf(srv), dead, srv.URL), nil)
	if err := c.Get(context.Background(), "/version", &pveVersion{}); err != nil {
		t.Fatalf("failover: %v", err)
	}
	if c.Address() != srv.URL {
		t.Fatalf("address %q", c.Address())
	}
	if o := c.order(); o[0] != srv.URL || o[1] != dead {
		t.Fatalf("last working not first: %v", o)
	}
	// 401 wechselt nicht die Adresse
	bad := testSys(pinOf(srv), srv.URL, dead)
	bad.Secret = "x"
	err := mustClient(t, bad, nil).Get(context.Background(), "/version", &pveVersion{})
	var e *Error
	if !errors.As(err, &e) || e.Others != 0 || !errors.Is(err, ErrToken) {
		t.Fatalf("401 failover: %v", err)
	}
	// alle tot: Fehler der ersten eingerichteten Adresse, Anzahl der weiteren
	err = mustClient(t, testSys(pinOf(srv), dead, deadAddr(t)), nil).Get(context.Background(), "/version", &pveVersion{})
	if !errors.As(err, &e) || e.Address != dead || e.Others != 1 || !strings.Contains(err.Error(), "1 more address") {
		t.Fatalf("all dead: %v", err)
	}
}

func TestClientLearnedAddresses(t *testing.T) {
	// Node 1 auf 127.0.0.1:P, Node 2 auf 127.0.0.2:P (gleicher Port, wie im Cluster)
	f1, f2 := newCluster(), newCluster()
	s1 := startTLS(t, f1, "127.0.0.1:0", nil)
	port := s1.Listener.Addr().(*net.TCPAddr).Port
	s2 := startTLS(t, f2, fmt.Sprintf("127.0.0.2:%d", port), nil)
	c := mustClient(t, testSys(pinOf(s1), s1.URL), nil)
	c.SetLearned([]string{"127.0.0.1", "127.0.0.2", "fe80::1%eth0", "kein-ip"})
	if c.learn[0] != s2.URL || len(c.learn) != 1 {
		t.Fatalf("learned %v (want %s)", c.learn, s2.URL)
	}
	s1.Close() // Node 1 faellt aus -> gelernte Adresse mit gleichem Zertifikat
	if err := c.Get(context.Background(), "/version", &pveVersion{}); err != nil {
		t.Fatalf("learned failover: %v", err)
	}
	if c.Address() != s2.URL {
		t.Fatalf("address %q", c.Address())
	}
}

func TestClientLearnedOtherCert(t *testing.T) {
	f1, f2 := newCluster(), newCluster()
	s1 := startTLS(t, f1, "127.0.0.1:0", nil)
	port := s1.Listener.Addr().(*net.TCPAddr).Port
	other := genCert(t, "127.0.0.2")
	startTLS(t, f2, fmt.Sprintf("127.0.0.2:%d", port), &other)
	c := mustClient(t, testSys(pinOf(s1), s1.URL), nil)
	c.SetLearned([]string{"127.0.0.2"})
	s1.Close()
	err := c.Get(context.Background(), "/version", &pveVersion{})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("want error of the configured address, got %v", err)
	}
	if f2.hit("/version") != 0 {
		t.Fatal("request sent to a node with another certificate")
	}
	if len(c.order()) != 1 {
		t.Fatalf("node with other certificate not paused: %v", c.order())
	}
}
