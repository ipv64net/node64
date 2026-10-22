package honeypot

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/ipv64api"
)

// decoyTestCert erzeugt ein Zertifikat wie aus der Verwaltung (Namen in DNSNames).
func decoyTestCert(t *testing.T, names ...string) *tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// decoyPeer verbindet per TLS mit SNI und liefert das gezeigte Zertifikat.
func decoyPeer(t *testing.T, port int, sni string) (*tls.Conn, *x509.Certificate) {
	t.Helper()
	c, err := tls.Dial("tcp", sensorAddrOf(port), &tls.Config{InsecureSkipVerify: true, ServerName: sni})
	if err != nil {
		t.Fatal(err)
	}
	return c, c.ConnectionState().PeerCertificates[0]
}

func TestCertPublic(t *testing.T) {
	for _, tc := range []struct {
		svc, page, persona string
		want               bool
	}{
		{SvcHTTPS, "", PersonaNginx, true},
		{SvcHTTPS, "sslvpn", PersonaNginx, true},
		{SvcHTTPS, "wp-login", PersonaApache, true},
		{SvcHTTPS, "unifi", PersonaNginx, false}, // UniFi-Controller: selbst signiert
		{SvcHTTPS, "pbs", PersonaNginx, false},
		{SvcHTTPS, "", PersonaPVE, false},
		{SvcHTTPS, "", PersonaWebmin, false},
		{SvcHTTPS, "", PersonaNAS, false},
		{SvcHTTPS, "", PersonaGrafana, false},
		{SvcHTTPS, "", PersonaHA, false},
		{SvcHTTPS, "", PersonaElastic, false},
		{SvcSMTPS, "", "", true},
		{SvcIMAPS, "", "", true},
		{SvcPOP3S, "", "", true},
		{SvcHTTP, "", PersonaNginx, false},
		{SvcMTAPI, "", "", false}, // MikroTik API-SSL bleibt wie das Geraet
		{SvcSMTP, "", "", false},
	} {
		if got := CertPublic(tc.svc, tc.page, tc.persona); got != tc.want {
			t.Errorf("CertPublic(%s, %q, %s) = %v", tc.svc, tc.page, tc.persona, got)
		}
	}
	if CertCapable(SvcMTAPI) || !CertCapable(SvcHTTPS) || !CertCapable(SvcIMAPS) {
		t.Fatal("CertCapable")
	}
	// Auswahl: nur Webserver-Profile und Mail mit TLS, dazu ausdruecklich genannte Ports
	list := []Service{{SvcHTTPS, 443, ""}, {SvcHTTPS, 8006, "pve"}, {SvcHTTPS, 8443, "unifi"}, {SvcHTTPS, 10000, ""}, {SvcIMAPS, 993, ""}, {SvcHTTP, 80, ""}}
	if got := CertUses(Config{CertID: 1}, list, "seed"); strings.Join(got, ",") != "https 443,imaps 993" {
		t.Fatalf("CertUses: %v", got)
	}
	if got := CertUses(Config{CertID: 1, CertPorts: []int{8006}}, list, "seed"); strings.Join(got, ",") != "https 443,https 8006,imaps 993" {
		t.Fatalf("CertUses mit Port: %v", got)
	}
	if got := CertUses(Config{CertPorts: []int{8006}}, list, "seed"); got != nil {
		t.Fatalf("CertUses ohne Zertifikat: %v", got)
	}
}

// Zertifikat je Port: Webserver und IMAPS zeigen das Zertifikat der Verwaltung, Proxmox bleibt selbst signiert (bis der
// Port ausdruecklich genannt ist); SNI steht im Ereignis.
func TestSensorDecoyCert(t *testing.T) {
	pWeb, pPVE, pIMAPS := sensorFreePort(t), sensorFreePort(t), sensorFreePort(t)
	managed := decoyTestCert(t, "mail.decoy.example", "cloud.decoy.example")
	var mu sync.Mutex
	issued := true // false = noch nicht ausgestellt (ByID liefert nil)
	s := NewSensor(sensorTestLog(), t.TempDir())
	s.SetCertSource(func(id int64) *tls.Certificate {
		mu.Lock()
		defer mu.Unlock()
		if id != 7 || !issued {
			return nil
		}
		return managed
	})
	rec := &sensorRec{}
	cfg := Config{Services: []Service{{SvcHTTPS, pWeb, ""}, {SvcHTTPS, pPVE, "pve"}, {SvcIMAPS, pIMAPS, ""}}, CertID: 7}
	for _, st := range s.Apply(context.Background(), cfg, rec.sink) {
		if !st.Listen {
			t.Fatalf("nicht offen: %+v", st)
		}
	}
	t.Cleanup(s.Stop)
	isManaged := func(c *x509.Certificate) bool { return c.Equal(managed.Leaf) }

	// HTTPS mit Webserver-Profil: Zertifikat der Verwaltung, SNI im Detail
	cl := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "cloud.decoy.example"}}}
	resp, err := cl.Get("https://" + sensorAddrOf(pWeb) + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !isManaged(resp.TLS.PeerCertificates[0]) {
		t.Fatalf("web: %v", resp.TLS.PeerCertificates[0].Subject)
	}
	e := rec.wait(t, func(e Event) bool { return e.Port == pWeb && e.Kind == KindHTTPScan })
	if !strings.Contains(e.Detail, "sni=cloud.decoy.example") || eventSNI(e) != "cloud.decoy.example" || eventView(e).SNI != "cloud.decoy.example" {
		t.Fatalf("SNI: %+v", e)
	}

	// Proxmox: selbst signiert wie das Original
	c, peer := decoyPeer(t, pPVE, "pve.decoy.example")
	c.Close()
	if isManaged(peer) || !slices.Contains(peer.Subject.Organization, "Proxmox Virtual Environment") {
		t.Fatalf("pve: %v", peer.Subject)
	}

	// IMAPS: Zertifikat der Verwaltung, Anmeldung mit SNI (Host) und Dienst imaps
	c, peer = decoyPeer(t, pIMAPS, "mail.decoy.example")
	if !isManaged(peer) {
		t.Fatalf("imaps: %v", peer.Subject)
	}
	br := bufio.NewReader(c)
	if l, _ := br.ReadString('\n'); !strings.HasPrefix(l, "* OK") {
		t.Fatalf("imaps greeting %q", l)
	}
	_, _ = io.WriteString(c, "a1 LOGIN admin geheim\r\n")
	e = rec.wait(t, func(e Event) bool { return e.Port == pIMAPS && e.Username == "admin" })
	c.Close()
	if e.Service != SvcIMAPS || e.Kind != KindMailBrute || e.Host != "mail.decoy.example" || eventSNI(e) != "mail.decoy.example" {
		t.Fatalf("imaps: %+v", e)
	}

	// Port ausdruecklich genannt: auch Proxmox zeigt das Zertifikat
	cfg.CertPorts = []int{pPVE}
	s.Apply(context.Background(), cfg, rec.sink)
	c, peer = decoyPeer(t, pPVE, "pve.decoy.example")
	c.Close()
	if !isManaged(peer) {
		t.Fatalf("pve mit Port: %v", peer.Subject)
	}

	// noch nicht ausgestellt bzw. aus: selbst signiert (Snakeoil mit Hostname)
	mu.Lock()
	issued = false
	mu.Unlock()
	c, peer = decoyPeer(t, pIMAPS, "mail.decoy.example")
	c.Close()
	if isManaged(peer) || len(peer.DNSNames) != 1 || peer.DNSNames[0] != s.personas().id.host {
		t.Fatalf("imaps ohne Zertifikat: %v %v", peer.Subject, peer.DNSNames)
	}
	mu.Lock()
	issued = true
	mu.Unlock()
	cfg.CertID = 0
	s.Apply(context.Background(), cfg, rec.sink)
	c, peer = decoyPeer(t, pWeb, "cloud.decoy.example")
	c.Close()
	if isManaged(peer) {
		t.Fatal("aus: Zertifikat der Verwaltung")
	}
	// ohne Quelle (Modus ohne Oberflaeche)
	s.SetCertSource(nil)
	cfg.CertID = 7
	s.Apply(context.Background(), cfg, rec.sink)
	c, peer = decoyPeer(t, pWeb, "cloud.decoy.example")
	c.Close()
	if isManaged(peer) {
		t.Fatal("ohne Quelle: Zertifikat der Verwaltung")
	}
}

func TestDecoyNames(t *testing.T) {
	got, bad := DecoyNames("mail, VPN cloud.decoy.example.;portal\nmail", "Decoy.Example")
	if bad != "" || strings.Join(got, ",") != "mail.decoy.example,vpn.decoy.example,cloud.decoy.example,portal.decoy.example" {
		t.Fatalf("%v %q", got, bad)
	}
	for in, want := range map[string]string{"*.decoy.example": "honeypot.err.cert_wildcard", "*": "honeypot.err.cert_wildcard", "decoy.example": "honeypot.err.cert_apex",
		"mail_x": "honeypot.err.cert_name", " , ": "honeypot.err.cert_names", strings.Repeat("a,b", 0) + "": "honeypot.err.cert_names"} {
		if _, bad := DecoyNames(in, "decoy.example"); !strings.HasPrefix(bad, want) {
			t.Errorf("%q: %q", in, bad)
		}
	}
	many := make([]string, certMaxNames+1)
	for i := range many {
		many[i] = "n" + strconv.Itoa(i)
	}
	if _, bad := DecoyNames(strings.Join(many, ","), "decoy.example"); !strings.HasPrefix(bad, "honeypot.err.cert_many") {
		t.Fatalf("many: %q", bad)
	}
	if _, bad := DecoyNames("mail", ""); bad != "honeypot.err.cert_domain" {
		t.Fatalf("domain: %q", bad)
	}
	// andere Domain wird angehaengt (bleibt unter der gewaehlten)
	if got, _ := DecoyNames("mail.other.example", "decoy.example"); got[0] != "mail.other.example.decoy.example" {
		t.Fatalf("other: %v", got)
	}
}

func TestDNSTargets(t *testing.T) {
	if m, bad := dnsTargets("93.184.215.14, 2a01:4f8::10"); bad != "" || m["A"] != "93.184.215.14" || m["AAAA"] != "2a01:4f8::10" || len(m) != 2 {
		t.Fatalf("%v %q", m, bad)
	}
	if m, bad := dnsTargets("Home.DynDNS64.example."); bad != "" || m["CNAME"] != "home.dyndns64.example" {
		t.Fatalf("%v %q", m, bad)
	}
	if m, bad := dnsTargets(""); bad != "" || len(m) != 0 {
		t.Fatalf("leer: %v %q", m, bad)
	}
	for _, in := range []string{"192.168.1.5", "127.0.0.1", "93.184.215.1,93.184.215.2", "host.example,93.184.215.1", "93.184.215.1 host.example", "localhost", "x_y.example"} {
		if _, bad := dnsTargets(in); !strings.HasPrefix(bad, "honeypot.err.cert_dns") {
			t.Errorf("%q: %q", in, bad)
		}
	}
}

// fakeDNS ist decoyDNS im Speicher.
type fakeDNS struct {
	recs []ipv64api.Record
	add  []string
	fail string // Praefix, dessen Anlegen scheitert
}

func (f *fakeDNS) Records(_ context.Context, domain string) ([]ipv64api.Record, error) {
	return f.recs, nil
}

func (f *fakeDNS) Add(_ context.Context, domain, typ, prefix, content string) error {
	if prefix == f.fail {
		return errors.New("quota")
	}
	f.add = append(f.add, domain+"|"+typ+"|"+prefix+"|"+content)
	return nil
}

func TestDecoyRecords(t *testing.T) {
	d := &fakeDNS{recs: []ipv64api.Record{{Prefix: "vpn", Type: "cname", Content: "x.example"}, {Prefix: "mail", Type: "MX", Content: "10 mx"}}, fail: "portal"}
	res, err := decoyRecords(context.Background(), d, "decoy.example", []string{"mail.decoy.example", "vpn.decoy.example", "portal.decoy.example"},
		map[string]string{"A": "93.184.215.14", "AAAA": "2a01:4f8::10"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.add, " ") != "decoy.example|A|mail|93.184.215.14 decoy.example|AAAA|mail|2a01:4f8::10" {
		t.Fatalf("add: %v", d.add)
	}
	var sum []string
	for _, r := range res {
		sum = append(sum, r.Name+"/"+r.Type+"="+r.Result)
	}
	if strings.Join(sum, ",") != "mail.decoy.example/A=created,mail.decoy.example/AAAA=created,vpn.decoy.example/A=exists,vpn.decoy.example/AAAA=exists,portal.decoy.example/A=error,portal.decoy.example/AAAA=error" {
		t.Fatalf("res: %v", sum)
	}
}

// fakeCerts ist certManager im Speicher.
type fakeCerts struct {
	mu      sync.Mutex
	list    []*certs.Cert
	reqs    []certs.Request
	err     error
	domains []string
	dns     bool
}

func (f *fakeCerts) List(context.Context) ([]*certs.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*certs.Cert(nil), f.list...), nil
}

func (f *fakeCerts) Get(_ context.Context, id int64) (*certs.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.list {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, certs.ErrNotFound
}

func (f *fakeCerts) Create(_ context.Context, req certs.Request) (*certs.Cert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	f.reqs = append(f.reqs, req)
	c := &certs.Cert{ID: int64(100 + len(f.list)), Names: req.Names, Source: req.Source, Status: certs.StatusPending}
	f.list = append(f.list, c)
	return c, nil
}

func (f *fakeCerts) Domains(context.Context) ([]string, error) { return f.domains, nil }
func (f *fakeCerts) DNSReady(context.Context) bool             { return f.dns }
func (f *fakeCerts) ByID(int64) *tls.Certificate               { return nil }

// Anlegen ueber die Seite: Weg der Verwaltung (ipv64 DNS-01), Auswahl in der Einstellung, DNS-Records, Audit.
func TestModuleDecoyCert(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	var audit []auditEntry
	m.g = testGuards(&audit)
	m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) {
		audit = append(audit, auditEntry{"flash", kind, text})
	}
	fc := &fakeCerts{domains: []string{"decoy.example", "home.example"}, dns: true,
		list: []*certs.Cert{{ID: 5, Names: []string{"old.decoy.example"}, Status: certs.StatusValid, NotAfter: time.Now().Add(48 * time.Hour)}}}
	m.certs = fc
	d := &fakeDNS{}
	m.dnsrec = d
	post := func(v url.Values) {
		r := httptest.NewRequest(http.MethodPost, "/honeypot/cert", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		m.pageCert(w, r)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("status %d", w.Code)
		}
	}
	// fremde Domain und Wildcard: nichts angelegt
	post(url.Values{"cert_domain": {"other.example"}, "cert_names": {"mail"}})
	post(url.Values{"cert_domain": {"decoy.example"}, "cert_names": {"*.decoy.example"}})
	post(url.Values{"cert_domain": {"decoy.example"}, "cert_names": {"mail"}, "dns_target": {"10.0.0.1"}})
	if len(fc.reqs) != 0 {
		t.Fatalf("angelegt trotz Fehler: %+v", fc.reqs)
	}
	post(url.Values{"cert_domain": {"decoy.example"}, "cert_names": {"mail, vpn"}, "dns_target": {"93.184.215.14"}})
	if len(fc.reqs) != 1 || fc.reqs[0].Source != certs.SourceIPv64 || strings.Join(fc.reqs[0].Names, ",") != "mail.decoy.example,vpn.decoy.example" {
		t.Fatalf("Anfrage: %+v", fc.reqs)
	}
	id := fc.list[len(fc.list)-1].ID
	if c := m.loadConfig(context.Background()); c.CertID != id {
		t.Fatalf("nicht ausgewaehlt: %d", c.CertID)
	}
	if strings.Join(d.add, " ") != "decoy.example|A|mail|93.184.215.14 decoy.example|A|vpn|93.184.215.14" {
		t.Fatalf("dns: %v", d.add)
	}
	if !slices.ContainsFunc(audit, func(a auditEntry) bool {
		return a.action == "honeypot.config" && strings.Contains(a.details, "names=mail.decoy.example,vpn.decoy.example")
	}) {
		t.Fatalf("audit: %+v", audit)
	}
	// benutzt von Honeypot64 (Schutz beim Loeschen)
	if u := m.certUsers(context.Background()); len(u[id]) != 1 || u[id][0] != certOwner {
		t.Fatalf("users: %v", u)
	}
	// Nutzungsbedingungen fehlen: Hinweis, nichts geaendert
	fc.err = certs.ErrTOS
	post(url.Values{"cert_domain": {"decoy.example"}, "cert_names": {"portal"}})
	if last := audit[len(audit)-1]; last.action != "flash" || last.target != "danger" || last.details != "honeypot.cert.err_tos" {
		t.Fatalf("tos: %+v", last)
	}
	// Einstellung: unbekanntes Zertifikat und ungueltige Ports
	c := m.loadConfig(context.Background())
	c.CertID, c.CertPorts = 999, []int{8006, 0}
	_, err := m.SaveConfig(context.Background(), c)
	var fe FieldErrors
	if !errors.As(err, &fe) || !strings.HasPrefix(fe["cert_id"], "honeypot.err.cert|999") || !strings.HasPrefix(fe["cert_ports"], "honeypot.err.cert_ports|0") {
		t.Fatalf("validate: %v", err)
	}
	c.CertID, c.CertPorts = 5, []int{10000, 8006, 8006}
	saved, err := m.SaveConfig(context.Background(), c)
	if err != nil || saved.CertID != 5 || !slices.Equal(saved.CertPorts, []int{8006, 10000}) {
		t.Fatalf("save: %+v %v", saved.Config, err)
	}
	// Import von einer anderen Node: unbekannte Kennung faellt weg
	if _, err := m.Import(context.Background(), []byte(`{"profile":"minimal","cert_id":4711,"cert_ports":[8006]}`)); err != nil {
		t.Fatal(err)
	}
	if c := m.loadConfig(context.Background()); c.CertID != 0 || !slices.Equal(c.CertPorts, []int{8006}) {
		t.Fatalf("import: %+v", c.Config)
	}
	if v := m.certViews(context.Background()); len(v) < 2 || !v[0].Valid || v[1].Valid {
		t.Fatalf("views: %+v", v)
	}
}
