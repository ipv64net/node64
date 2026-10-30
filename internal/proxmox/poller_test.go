package proxmox

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// testPoller: Poller mit Testuhr (now zeigt auf *clock).
func testPoller(t *testing.T, sys System, fn SnapshotFunc, clock *time.Time) *Poller {
	t.Helper()
	c := mustClient(t, sys, nil)
	p := newPoller(testLog, sys, fn, c, nil)
	p.now = func() time.Time { return *clock }
	c.now = p.now
	return p
}

func byKey(s *Snapshot) map[string]Resource {
	m := map[string]Resource{}
	for _, r := range s.Resources {
		m[r.Key()] = r
	}
	return m
}

func TestPollerClusterStates(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	var got []*Snapshot
	p := testPoller(t, testSys(pinOf(srv), srv.URL), func(_ context.Context, s *Snapshot) { got = append(got, s) }, &clock)
	if p.Last() != nil {
		t.Fatal("Last before first poll")
	}
	s := p.Poll(context.Background())
	if !s.OK || s.Error != "" {
		t.Fatalf("poll: %+v", s)
	}
	if len(got) != 1 || got[0] != s || p.Last() != s {
		t.Fatal("snapshot not delivered")
	}
	if s.SystemID != 7 || s.Version != "8.2.4" || s.Cluster != "lab" || s.Quorate == nil || !*s.Quorate || s.Address != srv.URL {
		t.Fatalf("header: %+v", s)
	}
	if len(s.Resources) != 14 {
		t.Fatalf("resources %d (storage must be filtered)", len(s.Resources))
	}
	// Speicher: lokale je Node (auch nicht verfuegbare), der gemeinsame nur einmal mit den Werten des verfuegbaren Nodes
	var st []string
	for _, x := range s.Storages {
		pct, ok := x.UsedPercent()
		st = append(st, fmt.Sprintf("%s:%s:%v:%.0f", x.Key(), x.Status, ok, pct))
	}
	if got := strings.Join(st, " "); got != "pve1/local:available:false:0 pve1/local-lvm:available:true:95 pve2/local:available:true:30 pve3/local:unknown:false:0 nfs:available:true:25" {
		t.Errorf("storages: %s", got)
	}
	if lvm := s.Storages[1]; lvm.Type != "lvmthin" || lvm.Content != "images,rootdir" || lvm.Total != 100<<30 || s.Storages[4].Node != "" || !s.Storages[4].Shared {
		t.Errorf("storage fields: %+v %+v", lvm, s.Storages[4])
	}
	if s.Resources[0].Key() != "node/pve1" || s.Resources[3].Key() != "qemu/100" {
		t.Fatalf("order: %s %s", s.Resources[0].Key(), s.Resources[3].Key())
	}
	m := byKey(s)
	want := map[string]State{
		"node/pve1": StateOnline, "node/pve2": StateOnline, "node/pve3": StateOffline,
		"qemu/100": StateRunning, "qemu/101": StatePaused, "qemu/102": StateSuspended, "qemu/103": StateBackup,
		"qemu/104": StateLocked, "qemu/105": StateSuspended, "qemu/106": StateStopped, "qemu/107": StateError,
		"qemu/108": StateUnknown, "lxc/200": StateRunning, "qemu/9000": StateStopped,
	}
	for k, st := range want {
		if m[k].State != st {
			t.Errorf("%s: state %q, want %q (qmp %q)", k, m[k].State, st, m[k].QMP)
		}
	}
	if r := m["qemu/100"]; strings.Join(r.Tags, ",") != "prod,web" || r.HAState != "started" || r.QMP != "running" || r.MaxMem != 4<<30 || r.CPU != 0.25 {
		t.Errorf("qemu/100: %+v", r)
	}
	if !m["qemu/9000"].Template || m["qemu/100"].Template {
		t.Error("template flag")
	}
	if m["lxc/200"].Tags[0] != "db" || m["lxc/200"].QMP != "" {
		t.Errorf("lxc: %+v", m["lxc/200"])
	}
	if m["qemu/104"].Lock != "migrate" || m["node/pve1"].Name != "pve1" || m["node/pve1"].Uptime != 100000 {
		t.Error("lock/node fields")
	}
	// erste Abfrage: keine Raten
	if m["qemu/100"].NetIn != 0 || m["qemu/100"].Restarted {
		t.Error("rates on first poll")
	}
	// gelernte Adressen: nur Nodes, die online sind, ohne die eingerichtete
	if len(p.client.learn) != 1 || !strings.HasPrefix(p.client.learn[0], "https://127.0.0.2:") {
		t.Errorf("learned %v", p.client.learn)
	}
	// keine qmpstatus-Abfrage fuer gestoppte VMs, LXC, Vorlagen und Gaeste auf offline-Nodes
	for _, path := range []string{"pve2/qemu/106", "pve3/qemu/108", "pve2/lxc/200", "pve1/qemu/9000"} {
		if f.hit("/nodes/"+path+"/status/current") != 0 {
			t.Errorf("qmpstatus asked for %s", path)
		}
	}
}

func TestPollerSingleNode(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	clock := time.Now()
	s := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock).Poll(context.Background())
	if !s.OK || s.Cluster != "" || s.Quorate != nil || len(s.Resources) != 2 {
		t.Fatalf("single: %+v", s)
	}
	if byKey(s)["qemu/100"].State != StateRunning || byKey(s)["node/pve"].State != StateOnline {
		t.Fatalf("states: %+v", s.Resources)
	}
}

func TestPollerRatesAndRestart(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	p.Poll(context.Background())

	clock = clock.Add(30 * time.Second)
	f.set(func(f *fakePVE) {
		for _, r := range f.resources {
			switch r["id"] {
			case "qemu/100": // +3000 Byte in 30 s = 100 B/s
				r["netin"], r["netout"], r["diskread"], r["diskwrite"], r["uptime"] = 4000, 2000+30*50, 3000, 4000+30*1000, 5030
			case "qemu/101": // Zaehler zurueck und Uptime kleiner: neu gestartet
				r["netin"], r["uptime"] = 10, 20
			case "qemu/102": // auf anderen Node migriert: Uptime neu, aber kein Neustart
				r["node"], r["uptime"] = "pve1", 3
			case "qemu/106": // gestartet: kein Neustart
				r["status"], r["uptime"] = "running", 10
			case "node/pve2": // Node neu gestartet
				r["uptime"] = 50
			}
		}
	})
	m := byKey(p.Poll(context.Background()))
	r := m["qemu/100"]
	if r.NetIn != 100 || r.NetOut != 50 || r.DiskRead != 0 || r.DiskWrite != 1000 || r.Restarted {
		t.Fatalf("rates: in %v out %v read %v write %v restarted %v", r.NetIn, r.NetOut, r.DiskRead, r.DiskWrite, r.Restarted)
	}
	if m["qemu/101"].NetIn != 0 || !m["qemu/101"].Restarted {
		t.Fatalf("restart 101: %+v", m["qemu/101"])
	}
	if m["qemu/102"].Restarted || m["qemu/102"].Node != "pve1" {
		t.Fatalf("migrated 102: %+v", m["qemu/102"])
	}
	if m["qemu/106"].Restarted || m["qemu/106"].State != StateRunning {
		t.Fatalf("started 106: %+v", m["qemu/106"])
	}
	if !m["node/pve2"].Restarted || m["node/pve1"].Restarted {
		t.Fatal("node restart")
	}
	// naechste Abfrage ohne Aenderung: kein Neustart mehr, Raten 0
	clock = clock.Add(30 * time.Second)
	m = byKey(p.Poll(context.Background()))
	if m["qemu/101"].Restarted || m["qemu/100"].NetIn != 0 {
		t.Fatalf("third poll: %+v", m["qemu/101"])
	}
}

func TestPollerTakt(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	ctx := context.Background()
	qmp := func() int { return f.hit("/nodes/pve1/qemu/100/status/current") }

	p.Poll(ctx)
	if f.hit("/cluster/resources") != 1 || f.hit("/cluster/status") != 1 || f.hit("/version") != 1 || qmp() != 1 {
		t.Fatalf("first poll: %v", f.hits)
	}
	if f.hit("/nodes/pve1/qemu/107/status/current") != 1 || f.hit("/nodes/pve2/qemu/104/status/current") != 1 {
		t.Fatalf("qmp for running vms: %v", f.hits)
	}
	clock = clock.Add(30 * time.Second)
	s := p.Poll(ctx)
	if f.hit("/cluster/resources") != 2 || f.hit("/cluster/status") != 1 || qmp() != 1 {
		t.Fatalf("after 30 s: %v", f.hits)
	}
	// qmpstatus bleibt bis zur naechsten Runde gueltig
	if m := byKey(s); m["qemu/101"].State != StatePaused || m["qemu/107"].State != StateError {
		t.Fatalf("qmp kept: %+v", m["qemu/101"])
	}
	clock = clock.Add(30 * time.Second)
	p.Poll(ctx)
	if f.hit("/cluster/status") != 2 || qmp() != 1 {
		t.Fatalf("after 60 s: %v", f.hits)
	}
	clock = clock.Add(60 * time.Second)
	p.Poll(ctx)
	if qmp() != 2 || f.hit("/version") != 1 {
		t.Fatalf("after 2 min: %v", f.hits)
	}
	// Node geht laut cluster/resources offline -> cluster/status sofort neu, Gaeste unbekannt
	f.set(func(f *fakePVE) {
		f.resources[1]["status"] = "offline"
		f.status[2]["online"] = 0
	})
	clock = clock.Add(30 * time.Second)
	m := byKey(p.Poll(ctx))
	if f.hit("/cluster/status") != 4 {
		t.Fatalf("status not refreshed early: %d", f.hit("/cluster/status"))
	}
	if m["node/pve2"].State != StateOffline || m["lxc/200"].State != StateUnknown || m["qemu/106"].State != StateUnknown {
		t.Fatalf("offline node: %v %v", m["node/pve2"].State, m["lxc/200"].State)
	}
}

func TestPollerError(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Now()
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	if s := p.Poll(context.Background()); !s.OK {
		t.Fatal(s.Error)
	}
	f.set(func(f *fakePVE) { f.code = http.StatusUnauthorized })
	clock = clock.Add(30 * time.Second)
	s := p.Poll(context.Background())
	if s.OK || !strings.Contains(s.Error, "401") || len(s.Resources) != 0 || s.Resources == nil {
		t.Fatalf("error snapshot: %+v", s)
	}
	if s.Cluster != "lab" || s.Version == "" {
		t.Fatalf("cluster/version should stay: %+v", s)
	}
	// falsch eingerichtetes System: Snapshot mit Fehler statt Panik
	bad := NewPoller(nil, testSys("zz", srv.URL), nil)
	if s := bad.Poll(context.Background()); s.OK || !strings.Contains(s.Error, "fingerprint") {
		t.Fatalf("bad system: %+v", s)
	}
}

func TestPollerRun(t *testing.T) {
	f := newSingle()
	srv := startTLS(t, f, "", nil)
	var mu sync.Mutex
	n := 0
	ctx, cancel := context.WithCancel(context.Background())
	c := mustClient(t, testSys(pinOf(srv), srv.URL), nil)
	p := newPoller(testLog, testSys(pinOf(srv), srv.URL), func(_ context.Context, s *Snapshot) {
		mu.Lock()
		n++
		mu.Unlock()
		cancel()
	}, c, nil)
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if n != 1 || p.Last() == nil || !p.Last().OK || p.Last().Interval != 30*time.Second {
		t.Fatalf("run: n=%d last=%+v", n, p.Last())
	}
}

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

// colonFP: Fingerabdruck im Format von Proxmox (AA:BB:…).
func colonFP(der []byte) string {
	h := strings.ToUpper(CertFingerprint(der))
	var l []string
	for i := 0; i < len(h); i += 2 {
		l = append(l, h[i:i+2])
	}
	return strings.Join(l, ":")
}

// pveCertInfo baut certificates/info: pve-ssl.pem und optional pveproxy-ssl.pem (eigenes Zertifikat, hat Vorrang).
func pveCertInfo(pveSSL, proxy string) []map[string]any {
	l := []map[string]any{{"filename": "pve-root-ca.pem", "fingerprint": strings.Repeat("11:", 31) + "11"},
		{"filename": "pve-ssl.pem", "fingerprint": pveSSL}}
	if proxy != "" {
		l = append(l, map[string]any{"filename": "pveproxy-ssl.pem", "fingerprint": proxy})
	}
	return l
}

// clusterOnTwoIPs: Node pve1 auf 127.0.0.1:P (Zertifikat von httptest, gepinnt), Node pve2 auf 127.0.0.2:P mit
// eigenem Zertifikat (wie bei Proxmox: jeder Node hat sein eigenes pve-ssl.pem).
func clusterOnTwoIPs(t *testing.T) (f1, f2 *fakePVE, s1, s2 *httptest.Server) {
	f1, f2 = newCluster(), newCluster()
	s1 = startTLS(t, f1, "127.0.0.1:0", nil)
	port := s1.Listener.Addr().(*net.TCPAddr).Port
	other := genCert(t, "127.0.0.2")
	s2 = startTLS(t, f2, fmt.Sprintf("127.0.0.2:%d", port), &other)
	certs := map[string][]map[string]any{
		"pve1": pveCertInfo(colonFP(s1.Certificate().Raw), ""),
		// pve-ssl.pem ist hier ein altes Zertifikat, benutzt wird pveproxy-ssl.pem
		"pve2": pveCertInfo(strings.Repeat("22:", 31)+"22", colonFP(other.Certificate[0])),
	}
	f1.certs, f2.certs = certs, certs
	return f1, f2, s1, s2
}

func TestPollerLearnsNodePins(t *testing.T) {
	f1, f2, s1, s2 := clusterOnTwoIPs(t)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	sys := testSys(pinOf(s1), s1.URL)
	p := testPoller(t, sys, nil, &clock)
	ctx := context.Background()
	if s := p.Poll(ctx); !s.OK {
		t.Fatal(s.Error)
	}
	// nur fuer gelernte Nodes, die online sind (pve1 ist die eingerichtete Adresse, pve3 offline)
	if f1.hit("/nodes/pve2/certificates/info") != 1 || f1.hit("/nodes/pve1/certificates/info") != 0 || f1.hit("/nodes/pve3/certificates/info") != 0 {
		t.Fatalf("certificates/info: %v", f1.hits)
	}
	if got := p.client.lpins[s2.URL]; len(got) != 1 || got[0] != CertFingerprint(s2.TLS.Certificates[0].Certificate[0]) {
		t.Fatalf("learned pin %v", got)
	}
	// Node 1 faellt aus -> Failover auf Node 2 mit seinem eigenen Zertifikat
	s1.Close()
	clock = clock.Add(30 * time.Second)
	s := p.Poll(ctx)
	if !s.OK || s.Address != s2.URL || f2.hit("/cluster/resources") != 1 {
		t.Fatalf("failover: %+v", s)
	}
	// nach 10 min neu (jetzt ueber Node 2), dazwischen nicht
	clock = clock.Add(5 * time.Minute)
	p.Poll(ctx)
	if f2.hit("/nodes/pve2/certificates/info") != 0 {
		t.Fatal("refreshed too early")
	}
	clock = clock.Add(5 * time.Minute)
	p.Poll(ctx)
	if f2.hit("/nodes/pve2/certificates/info") != 1 {
		t.Fatalf("no refresh after 10 min: %v", f2.hits)
	}
	// der Pin des Systems bleibt unveraendert
	if p.sys.PinSHA256 != sys.PinSHA256 || p.client.pin != pinOf(s1) {
		t.Fatal("system pin changed")
	}
}

func TestPollerNodePinsWithoutRights(t *testing.T) {
	f1, f2, s1, _ := clusterOnTwoIPs(t)
	f1.noCerts = true
	clock := time.Now()
	p := testPoller(t, testSys(pinOf(s1), s1.URL), nil, &clock)
	if s := p.Poll(context.Background()); !s.OK {
		t.Fatal(s.Error)
	}
	if len(p.client.lpins) != 0 {
		t.Fatalf("pins without rights: %v", p.client.lpins)
	}
	// wie bisher: Node 2 hat ein anderes Zertifikat als der Pin des Systems -> nicht benutzt
	s1.Close()
	clock = clock.Add(30 * time.Second)
	s := p.Poll(context.Background())
	if s.OK || !strings.Contains(s.Error, "not reachable") || f2.hit("/cluster/resources") != 0 {
		t.Fatalf("without rights: %+v", s)
	}
}

func TestPollerNoNodePinsWithCA(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	f.certs = map[string][]map[string]any{"pve2": pveCertInfo(colonFP(srv.Certificate().Raw), "")}
	roots := x509.NewCertPool()
	roots.AddCert(srv.Certificate())
	sys := testSys("", srv.URL)
	c := mustClient(t, sys, roots)
	p := newPoller(testLog, sys, nil, c, nil)
	if s := p.Poll(context.Background()); !s.OK {
		t.Fatal(s.Error)
	}
	if f.hit("/nodes/pve2/certificates/info") != 0 || len(c.lpins) != 0 {
		t.Fatal("certificates/info asked for a CA system")
	}
}

// qmpstatus ungleich running wird bei jeder Abfrage neu gefragt: eine fortgesetzte VM zeigt nicht bis zur naechsten
// Runde (2 min) weiter „angehalten“; Fehler beim Nachfragen verwerfen den alten Wert.
func TestPollerQMPRecheck(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	ctx := context.Background()
	if m := byKey(p.Poll(ctx)); m["qemu/101"].State != StatePaused || m["qemu/107"].State != StateError {
		t.Fatalf("first poll: %v %v", m["qemu/101"].State, m["qemu/107"].State)
	}
	f.set(func(f *fakePVE) {
		f.qmp["pve1/101"] = "running" // fortgesetzt
		delete(f.qmp, "pve1/107")     // Nachfrage schlaegt fehl
	})
	clock = clock.Add(30 * time.Second)
	m := byKey(p.Poll(ctx))
	if m["qemu/101"].State != StateRunning || m["qemu/107"].State != StateRunning || m["qemu/107"].QMP != "" {
		t.Fatalf("after resume: %v %v", m["qemu/101"].State, m["qemu/107"].State)
	}
	if f.hit("/nodes/pve1/qemu/101/status/current") != 2 || f.hit("/nodes/pve1/qemu/100/status/current") != 1 {
		t.Fatalf("recheck: %v", f.hits)
	}
	// ab jetzt running: erst in der naechsten Runde wieder gefragt
	clock = clock.Add(30 * time.Second)
	p.Poll(ctx)
	if f.hit("/nodes/pve1/qemu/101/status/current") != 2 {
		t.Fatalf("running asked again: %v", f.hits)
	}
	// gemerkter Wert gilt nach Neustart (Uptime kleiner), Umzug oder geaendertem Lock nicht mehr
	p.qmp = map[string]pveQMP{
		"qemu/1": {status: "paused", node: "pve1", uptime: 100},
		"qemu/2": {status: "paused", node: "pve1", uptime: 100},
		"qemu/3": {status: "paused", node: "pve2", uptime: 100},
		"qemu/4": {status: "paused", node: "pve1", lock: "backup", uptime: 100},
	}
	vm := func(id int, uptime int64) Resource {
		return Resource{Type: TypeQEMU, VMID: id, Node: "pve1", Status: "running", Uptime: uptime}
	}
	res := []Resource{vm(1, 160), vm(2, 20), vm(3, 160), vm(4, 160)}
	p.evaluate(clock, res)
	for i, want := range []State{StatePaused, StateRunning, StateRunning, StateRunning} {
		if res[i].State != want {
			t.Errorf("qemu/%d: %v, want %v", i+1, res[i].State, want)
		}
	}
}

// Gestoppter Gast mit Lock: eine Weile neutral (Backup im Stopp-Modus), danach als gestoppt bewertet (haengender Lock).
func TestPollerStaleLock(t *testing.T) {
	f := newCluster()
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	ctx := context.Background()
	f.set(func(f *fakePVE) {
		for _, r := range f.resources {
			if r["id"] == "qemu/106" {
				r["lock"] = "backup"
			}
		}
	})
	if m := byKey(p.Poll(ctx)); m["qemu/106"].State != StateBackup {
		t.Fatalf("stopped backup: %v", m["qemu/106"].State)
	}
	clock = clock.Add(pveLockGrace - time.Minute)
	if m := byKey(p.Poll(ctx)); m["qemu/106"].State != StateBackup {
		t.Fatalf("within grace: %v", m["qemu/106"].State)
	}
	clock = clock.Add(time.Minute)
	if m := byKey(p.Poll(ctx)); m["qemu/106"].State != StateStopped || m["qemu/106"].Lock != "backup" {
		t.Fatalf("stale lock: %+v", m["qemu/106"])
	}
	// laufender Gast mit Lock bleibt Backup
	if m := byKey(p.Poll(ctx)); m["qemu/103"].State != StateBackup {
		t.Fatalf("running backup: %v", m["qemu/103"].State)
	}
}

// Adressen fuer den Ping der Latenz: Nodes aus cluster/status, laufende Gaeste nur auf Wunsch eines Checks (WantIP),
// je Gast hoechstens alle pveIPEvery; ohne Gast-Agent bleibt die Adresse leer. Dazu die Antwortzeit der API.
func TestPollerGuestIPs(t *testing.T) {
	f := newCluster()
	f.ifaces = map[string]any{
		"pve1/qemu/100": map[string]any{"result": []map[string]any{
			{"name": "lo", "ip-addresses": []map[string]any{{"ip-address-type": "ipv4", "ip-address": "127.0.0.1", "prefix": 8}, {"ip-address-type": "ipv6", "ip-address": "::1"}}},
			{"name": "eth0", "ip-addresses": []map[string]any{{"ip-address-type": "ipv6", "ip-address": "fe80::1"}, {"ip-address-type": "ipv6", "ip-address": "2001:db8::10"},
				{"ip-address-type": "ipv4", "ip-address": "192.0.2.10", "prefix": 24}}},
		}},
		"pve2/lxc/200": []map[string]any{{"name": "lo", "inet": "127.0.0.1/8", "inet6": "::1/128"}, {"name": "eth0", "inet": "192.0.2.20/24", "inet6": "fe80::2/64"}},
	}
	srv := startTLS(t, f, "", nil)
	clock := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p := testPoller(t, testSys(pinOf(srv), srv.URL), nil, &clock)
	ctx := context.Background()
	const agent100, agent107 = "/nodes/pve1/qemu/100/agent/network-get-interfaces", "/nodes/pve1/qemu/107/agent/network-get-interfaces"
	s := p.Poll(ctx)
	m := byKey(s)
	if m["node/pve1"].IP != "127.0.0.1" || m["node/pve2"].IP != "127.0.0.2" || m["qemu/100"].IP != "" || f.hit(agent100) != 0 || s.APILatency <= 0 {
		t.Fatalf("first poll: %q %q %q hits %d api %v", m["node/pve1"].IP, m["node/pve2"].IP, m["qemu/100"].IP, f.hit(agent100), s.APILatency)
	}
	for _, k := range []string{"qemu/100", "lxc/200", "qemu/107", "qemu/106"} {
		p.WantIP(k)
	}
	m = byKey(p.Poll(ctx))
	if m["qemu/100"].IP != "192.0.2.10" || m["lxc/200"].IP != "192.0.2.20" || m["qemu/107"].IP != "" || m["qemu/106"].IP != "" {
		t.Fatalf("addresses: %q %q %q %q", m["qemu/100"].IP, m["lxc/200"].IP, m["qemu/107"].IP, m["qemu/106"].IP)
	}
	if f.hit(agent100) != 1 || f.hit(agent107) != 1 || f.hit("/nodes/pve2/lxc/200/interfaces") != 1 || f.hit("/nodes/pve2/qemu/106/agent/network-get-interfaces") != 0 {
		t.Fatalf("requests: %v", f.hits)
	}
	// innerhalb von pveIPEvery: keine neuen Anfragen, Adresse bleibt
	clock = clock.Add(time.Minute)
	if m = byKey(p.Poll(ctx)); m["qemu/100"].IP != "192.0.2.10" || f.hit(agent100) != 1 || f.hit(agent107) != 1 {
		t.Fatalf("cached: %q hits %d", m["qemu/100"].IP, f.hit(agent100))
	}
	clock = clock.Add(pveIPEvery)
	p.WantIP("qemu/100")
	if m = byKey(p.Poll(ctx)); m["qemu/100"].IP != "192.0.2.10" || f.hit(agent100) != 2 {
		t.Fatalf("refresh: %q hits %d", m["qemu/100"].IP, f.hit(agent100))
	}
	// kein Check fragt mehr: Adresse entfaellt, keine Anfragen
	clock = clock.Add(pveIPWant)
	if m = byKey(p.Poll(ctx)); m["qemu/100"].IP != "" || f.hit(agent100) != 2 {
		t.Fatalf("not wanted: %q hits %d", m["qemu/100"].IP, f.hit(agent100))
	}
}

func TestPickIP(t *testing.T) {
	cases := map[string][]string{
		"10.0.0.5":    {"127.0.0.1", "::1", "fe80::1", "169.254.1.1/16", "2001:db8::5", "10.0.0.5/24"},
		"2001:db8::5": {"127.0.0.1", "fe80::1", "2001:db8::5/64", "fd00::1"},
		"":            {"127.0.0.1/8", "::1/128", "fe80::2/64", "", "garbage"},
	}
	for want, list := range cases {
		if got := pvePickIP(list); got != want {
			t.Errorf("%v: %q, want %q", list, got, want)
		}
	}
	if got := pveLXCIP([]pveLXCIface{{Name: "lo", Inet: "127.0.0.1/8"}, {Name: "eth0", Inet6: "2001:db8::7/64"}, {Name: "eth1", Inet: "192.168.1.4/24"}}); got != "192.168.1.4" {
		t.Errorf("lxc: %q", got)
	}
}
