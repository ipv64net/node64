package honeypot

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const personaTestSeed = "0b5c3f0e-1d2a-4c7b-9e8f-112233445566"

func TestPersonaDefaults(t *testing.T) {
	for _, c := range []struct {
		svc  string
		port int
		page string
		want string
	}{
		{SvcHTTPS, 8006, "", PersonaPVE}, {SvcHTTPS, 10000, "", PersonaWebmin}, {SvcHTTP, 8123, "", PersonaHA}, {SvcHTTP, 3000, "", PersonaGrafana},
		{SvcHTTP, 5000, "", PersonaNAS}, {SvcHTTPS, 5001, "", PersonaNAS}, {SvcHTTP, 9200, "", PersonaElastic}, {SvcHTTP, 80, "", PersonaNginx},
		{SvcHTTPS, 443, "", PersonaNginx}, {SvcHTTP, 8080, "", PersonaNginx}, {SvcHTTP, 18006, "pve", PersonaPVE}, {SvcHTTP, 2375, "docker", PersonaNginx},
		{SvcSSH, 22, "", PersonaOpenSSH}, {SvcTelnet, 23, "", PersonaBusyBox}, {SvcMySQL, 3306, "", PersonaMySQL}, {SvcRedis, 6379, "", ""},
	} {
		if got := DefaultPersona(c.svc, c.port, c.page); got != c.want {
			t.Errorf("%s %d %s: %q, want %q", c.svc, c.port, c.page, got, c.want)
		}
	}
	// jedes Standardprofil ist waehlbar, jede Auswahl hat eine Anzeige
	for svc, list := range personaList {
		if !personaValid(svc, DefaultPersona(svc, 1, "")) {
			t.Errorf("%s: default not in list", svc)
		}
		for _, p := range list {
			if PersonaLabels[p] == "" {
				t.Errorf("%s: no label", p)
			}
		}
	}
	// Pruefung und Normalisierung
	c := Config{Hostname: " PVE01.Lan ", Personas: map[string]string{"SSH:22": "Dropbear", "http:80": "", "https:8443": "pve"}}
	if p := PersonaProblems(&c); len(p) != 0 || c.Hostname != "pve01.lan" || len(c.Personas) != 2 || c.Personas["ssh:22"] != PersonaDropbear {
		t.Fatalf("normalize: %v %+v", p, c)
	}
	c = Config{Hostname: "-bad_host", Personas: map[string]string{"ssh:22": "pve", "ssh:x": "dropbear", "redis:6379": "mysql"}}
	if p := PersonaProblems(&c); len(p) != 4 || !strings.HasPrefix(p[0], "honeypot.err.hostname|") || !strings.HasPrefix(p[1], "honeypot.err.persona|") {
		t.Fatalf("problems: %v", p)
	}
	for h, ok := range map[string]bool{"srv01": true, "a.b-c.d": true, "": false, "a..b": false, "x-": false, "Upper": false, strings.Repeat("a", 64): false} {
		if ValidHostname(h) != ok {
			t.Errorf("ValidHostname(%q) != %v", h, ok)
		}
	}
}

// Variation je Sensor: gleicher Seed = gleiche Identitaet (ueber Neustarts), verschiedene Seeds = verschiedene.
func TestSensorIdentStable(t *testing.T) {
	a, b := newSensorIdent(personaTestSeed, "", nil), newSensorIdent(personaTestSeed, "", nil)
	if *a != *b || a.sshBanner(PersonaOpenSSH) != b.sshBanner(PersonaOpenSSH) || a.nginxServer() != b.nginxServer() || !ValidHostname(a.fqdn()) {
		t.Fatalf("not stable: %+v %+v", a, b)
	}
	hosts, banners := map[string]bool{}, map[string]bool{}
	for i := 0; i < 40; i++ {
		id := newSensorIdent("seed-"+strconv.Itoa(i), "", nil)
		hosts[id.host] = true
		banners[id.sshBanner(PersonaOpenSSH)] = true
		if !ValidHostname(id.host) || (id.distro != "debian" && id.distro != "ubuntu") {
			t.Fatalf("ident %+v", id)
		}
	}
	if len(hosts) < 10 || len(banners) < 4 {
		t.Fatalf("too little variation: %d hosts, %d banners", len(hosts), len(banners))
	}
	// eingestellter Hostname (FQDN) und ausdrueckliches OpenSSH-Profil legen Hostname und Distribution fest
	id := newSensorIdent(personaTestSeed, "files.example.org", map[string]string{"ssh:22": PersonaOpenSSHUbuntu})
	if id.host != "files" || id.domain != "example.org" || id.distro != "ubuntu" || id.telnetHost(PersonaBusyBox) != "files" ||
		!strings.HasPrefix(id.sshBanner(PersonaOpenSSH), "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.") || id.nginxServer() != "nginx/1.24.0 (Ubuntu)" {
		t.Fatalf("hostname/distro: %+v", id)
	}
	if !strings.HasPrefix(id.sshBanner(PersonaDropbear), "SSH-2.0-dropbear_2024.8") ||
		!strings.HasPrefix(newSensorIdent("x", "", map[string]string{"ssh:2222": PersonaOpenSSHDebian}).sshBanner(PersonaOpenSSH), "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u") {
		t.Fatal("banner")
	}
	// ohne Seed (Modus ohne Oberflaeche): Sensor-Kennung aus dem Datenverzeichnis; nach dem Neustart gleiche
	// Identitaet und dasselbe Zertifikat (Datei wiederverwendet)
	dir := t.TempDir()
	s1, s2 := NewSensor(sensorTestLog(), dir), NewSensor(sensorTestLog(), dir)
	s1.Apply(context.Background(), Config{}, nil)
	s2.Apply(context.Background(), Config{}, nil)
	if i1, i2 := s1.personas().id, s2.personas().id; *i1 != *i2 || !validSensorID(i1.seed) {
		t.Fatalf("restart: %+v %+v", i1, i2)
	}
	k1, err := s1.personaCert(certPVE, s1.personas().id)
	if err != nil {
		t.Fatal(err)
	}
	k2, _ := s2.personaCert(certPVE, s2.personas().id)
	if k1.Leaf.SerialNumber.Cmp(k2.Leaf.SerialNumber) != 0 {
		t.Fatal("certificate not reused after restart")
	}
	// Zertifikatsdaten: Ausstellung je Seed stabil
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	c1, _, err := certCreate(certGeneric, a, t0)
	if err != nil {
		t.Fatal(err)
	}
	c2, _, _ := certCreate(certGeneric, b, t0)
	x1, x2 := personaParseCert(t, c1), personaParseCert(t, c2)
	if !x1.NotBefore.Equal(x2.NotBefore) || x1.SerialNumber.Cmp(x2.SerialNumber) == 0 || x1.Subject.CommonName != a.host {
		t.Fatalf("cert: %v %v %v", x1.NotBefore, x2.NotBefore, x1.Subject)
	}
}

// personaClient folgt keinen Weiterleitungen und prueft keine Zertifikate.
func personaClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func TestSensorHTTPPersonas(t *testing.T) {
	ports := map[string]int{}
	cfg := Config{Seed: personaTestSeed, Personas: map[string]string{}}
	for _, x := range []struct {
		name, svc string
	}{{PersonaPVE, SvcHTTPS}, {PersonaWebmin, SvcHTTPS}, {PersonaHA, SvcHTTP}, {PersonaGrafana, SvcHTTP}, {PersonaNAS, SvcHTTP}, {PersonaElastic, SvcHTTP}, {PersonaApache, SvcHTTP}} {
		p := sensorFreePort(t)
		ports[x.name] = p
		cfg.Services = append(cfg.Services, Service{Service: x.svc, Port: p})
		cfg.Personas[PersonaKey(x.svc, p)] = x.name
	}
	_, rec := sensorStart(t, cfg)
	id := newSensorIdent(personaTestSeed, "", cfg.Personas)
	cl := personaClient()
	u := func(persona, path string) string {
		scheme := "http"
		if persona == PersonaPVE || persona == PersonaWebmin {
			scheme = "https"
		}
		return scheme + "://" + sensorAddrOf(ports[persona]) + path
	}

	// Proxmox VE: API ohne Ticket 401 {"data":null}, Startseite mit Hostname im Titel, Zertifikat wie pve-ssl.pem
	code, body, h := sensorGet(t, cl, "GET", u(PersonaPVE, "/api2/json/version"), "curl/8", "", nil)
	if code != 401 || body != `{"data":null}` || h.Get("Server") != "pve-api-daemon/3.0" {
		t.Fatalf("pve api: %d %q %v", code, body, h)
	}
	code, body, _ = sensorGet(t, cl, "GET", u(PersonaPVE, "/"), "curl/8", "", nil)
	if code != 200 || !strings.Contains(body, "<title>"+id.host+" - Proxmox Virtual Environment</title>") || strings.Contains(body, "<script") {
		t.Fatalf("pve /: %d %q", code, body)
	}
	if e := rec.wait(t, func(e Event) bool { return e.Port == ports[PersonaPVE] && e.Path == "/" }); e.Page != "pve" {
		t.Fatalf("pve event: %+v", e)
	}
	leaf := personaPeerCert(t, ports[PersonaPVE])
	if leaf.Subject.CommonName != id.fqdn() || strings.Join(leaf.Subject.Organization, "") != "Proxmox Virtual Environment" ||
		strings.Join(leaf.Subject.OrganizationalUnit, "") != "PVE Cluster Node" || strings.Join(leaf.Issuer.Organization, "") != "PVE Cluster Manager CA" ||
		leaf.NotAfter.Sub(leaf.NotBefore) > 731*24*time.Hour || !leaf.NotBefore.Before(time.Now().Add(-23*time.Hour)) {
		t.Fatalf("pve cert: %v / %v %v-%v", leaf.Subject, leaf.Issuer, leaf.NotBefore, leaf.NotAfter)
	}
	// Login wie bisher erfasst, Geraet proxmox
	sensorGet(t, cl, "POST", u(PersonaPVE, "/api2/json/access/ticket"), "curl/8", "username=root%40pam&password=x1", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindHTTPBrute && e.Username == "root@pam" && e.Password == "x1" && strings.Contains(e.Detail, "device=proxmox")
	})

	// Webmin: MiniServ, Login-Seite auf jedem Pfad, POST erfasst (device=webmin), Zertifikat wie Webmin
	code, body, h = sensorGet(t, cl, "GET", u(PersonaWebmin, "/"), "curl/8", "", nil)
	if code != 200 || !strings.HasPrefix(h.Get("Server"), "MiniServ/2.") || h.Get("Auth-Type") != "auth-required=1" ||
		!strings.Contains(body, `action="/session_login.cgi"`) || !strings.Contains(body, `name="user"`) || !strings.Contains(body, `name="pass"`) {
		t.Fatalf("webmin: %d %v %q", code, h, body)
	}
	code, body, _ = sensorGet(t, cl, "POST", u(PersonaWebmin, "/session_login.cgi"), "curl/8", "user=root&pass=webmin1", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if code != 200 || !strings.Contains(body, "Invalid username or password") {
		t.Fatalf("webmin login: %d %q", code, body)
	}
	rec.wait(t, func(e Event) bool {
		return e.Username == "root" && e.Password == "webmin1" && strings.Contains(e.Detail, "device=webmin")
	})
	if leaf = personaPeerCert(t, ports[PersonaWebmin]); leaf.Subject.CommonName != "*" || strings.Join(leaf.Subject.Organization, "") != "Webmin Webserver on "+id.host {
		t.Fatalf("webmin cert: %v", leaf.Subject)
	}

	// Home Assistant: API ohne Token 401, Sicherheits-Kopfzeilen, kein Server-Kopf
	code, body, h = sensorGet(t, cl, "GET", u(PersonaHA, "/api/"), "curl/8", "", nil)
	if code != 401 || body != "401: Unauthorized" || h.Get("Server") != "" || h.Get("X-Frame-Options") != "SAMEORIGIN" || h.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("ha api: %d %q %v", code, body, h)
	}
	if code, body, _ = sensorGet(t, cl, "GET", u(PersonaHA, "/auth/providers"), "curl/8", "", nil); code != 200 || !strings.Contains(body, `"type":"homeassistant"`) {
		t.Fatalf("ha providers: %d %q", code, body)
	}
	if code, body, _ = sensorGet(t, cl, "POST", u(PersonaHA, "/auth/login_flow"), "curl/8", `{"client_id":"x"}`, map[string]string{"Content-Type": "application/json"}); code != 200 || !strings.Contains(body, `"step_id":"init"`) {
		t.Fatalf("ha login_flow: %d %q", code, body)
	}

	// Grafana: /api/health mit Version, / leitet auf /login
	code, body, h = sensorGet(t, cl, "GET", u(PersonaGrafana, "/api/health"), "curl/8", "", nil)
	var health map[string]string
	if code != 200 || json.Unmarshal([]byte(body), &health) != nil || health["database"] != "ok" || len(health["commit"]) != 40 ||
		!strings.Contains("10.4.12 11.2.2 11.3.1 11.5.2 12.0.2", health["version"]) || h.Get("X-Frame-Options") != "deny" {
		t.Fatalf("grafana health: %d %q", code, body)
	}
	if code, _, h = sensorGet(t, cl, "GET", u(PersonaGrafana, "/"), "curl/8", "", nil); code != 302 || h.Get("Location") != "/login" {
		t.Fatalf("grafana /: %d %v", code, h)
	}
	if code, body, _ = sensorGet(t, cl, "GET", u(PersonaGrafana, "/login"), "curl/8", "", nil); code != 200 || !strings.Contains(body, "<title>Grafana</title>") {
		t.Fatalf("grafana login: %d", code)
	}

	// NAS: DSM-API, Startseite mit Hostname, nginx ohne Version
	code, body, h = sensorGet(t, cl, "GET", u(PersonaNAS, "/webapi/query.cgi?api=SYNO.API.Info&method=query&version=1&query=all"), "curl/8", "", nil)
	if code != 200 || !strings.Contains(body, `"success":true`) || h.Get("Server") != "nginx" {
		t.Fatalf("nas query: %d %q %v", code, body, h)
	}
	if code, body, _ = sensorGet(t, cl, "GET", u(PersonaNAS, "/nothing"), "curl/8", "", nil); code != 404 || !strings.Contains(body, "<center>nginx</center>") {
		t.Fatalf("nas 404: %d %q", code, body)
	}

	// Elasticsearch: Wurzel mit Knotenname = Hostname, Version 7.17.x
	code, body, h = sensorGet(t, cl, "GET", u(PersonaElastic, "/"), "curl/8", "", nil)
	var es struct {
		ClusterName string `json:"cluster_name"`
		Version     struct {
			Number string `json:"number"`
		} `json:"version"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &es) != nil || !strings.Contains(body, `"name" : "`+id.host+`"`) || es.ClusterName != "elasticsearch" ||
		!strings.HasPrefix(es.Version.Number, "7.17.") || h.Get("X-Elastic-Product") != "Elasticsearch" {
		t.Fatalf("elastic: %d %q %v", code, body, h)
	}
	if code, body, _ = sensorGet(t, cl, "GET", u(PersonaElastic, `/my"idx/_search`), "curl/8", "", nil); code != 404 || !json.Valid([]byte(body)) || !strings.Contains(body, "index_not_found_exception") {
		t.Fatalf("elastic index: %d %q", code, body)
	}

	// Apache: Server-Kopf und Fehlerseite mit Port, Host-Kopf maskiert
	code, body, h = sensorGet(t, cl, "GET", u(PersonaApache, "/nothing"), "curl/8", "", nil)
	if code != 404 || !strings.HasPrefix(h.Get("Server"), "Apache/2.4.") || !strings.Contains(body, h.Get("Server")+" Server at 127.0.0.1 Port "+strconv.Itoa(ports[PersonaApache])) {
		t.Fatalf("apache: %d %q %v", code, body, h)
	}
	w, r := httptest.NewRecorder(), httptest.NewRequest("GET", "/x", nil)
	r.Host = "<x>:80"
	if sensorHTTPError(w, r, PersonaApache, id, 80, 403); w.Code != 403 || !strings.Contains(w.Body.String(), "Server at &lt;x&gt; Port 80") {
		t.Fatalf("apache host: %d %q", w.Code, w.Body.String())
	}
	// Webserver-Profil: Koeder wie bisher, Geraete ohne eigenes Profil weiter dort, Proxmox-Endpunkt nicht
	if code, body, _ = sensorGet(t, cl, "GET", u(PersonaApache, "/wp-login.php"), "curl/8", "", nil); code != 200 || !strings.Contains(body, `name="log"`) {
		t.Fatalf("apache bait: %d", code)
	}
	if code, _, _ = sensorGet(t, cl, "POST", u(PersonaApache, "/api2/json/access/ticket"), "curl/8", "username=a&password=b", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); code != 404 {
		t.Fatalf("apache pve endpoint: %d", code)
	}
	rec.wait(t, func(e Event) bool {
		return e.Port == ports[PersonaApache] && e.Username == "a" && e.Password == "b" && !strings.Contains(e.Detail, "device=")
	})
}

func personaParseCert(t *testing.T, pemData []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(pemData)
	if b == nil {
		t.Fatal("no pem")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// personaPeerCert liefert das Zertifikat, das der Dienst beim Handshake zeigt.
func personaPeerCert(t *testing.T, port int) *x509.Certificate {
	t.Helper()
	c, err := tls.Dial("tcp", sensorAddrOf(port), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.ConnectionState().PeerCertificates[0]
}

// personaKexInit liest Banner und KEXINIT des Servers (Algorithmen-Listen: kex, Host-Schluessel).
func personaKexInit(t *testing.T, port int) (banner string, kex, hostKeys []string) {
	t.Helper()
	c, err := net.Dial("tcp", sensorAddrOf(port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.WriteString(c, "SSH-2.0-PersonaTest_1.0\r\n")
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var hdr [5]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		t.Fatal(err)
	}
	pkt := make([]byte, binary.BigEndian.Uint32(hdr[:4])-1)
	if _, err := io.ReadFull(br, pkt); err != nil || pkt[0] != 20 {
		t.Fatalf("kexinit: %v %x", err, pkt[:1])
	}
	rest := pkt[17:]
	list := func() []string {
		n := binary.BigEndian.Uint32(rest)
		v := string(rest[4 : 4+n])
		rest = rest[4+n:]
		return strings.Split(v, ",")
	}
	return strings.TrimSpace(line), list(), list()
}

func TestSensorSSHPersonas(t *testing.T) {
	p1, p2 := sensorFreePort(t), sensorFreePort(t)
	_, rec := sensorStart(t, Config{Seed: personaTestSeed, Services: []Service{{SvcSSH, p1, ""}, {SvcSSH, p2, ""}},
		Personas: map[string]string{PersonaKey(SvcSSH, p1): PersonaOpenSSHDebian, PersonaKey(SvcSSH, p2): PersonaDropbear}})
	id := newSensorIdent(personaTestSeed, "", nil)

	banner, kex, hk := personaKexInit(t, p1)
	if banner != id.sshBanner(PersonaOpenSSHDebian) || kex[0] != "curve25519-sha256" || kex[1] != "curve25519-sha256@libssh.org" ||
		strings.Contains(strings.Join(kex, ","), "mlkem") || strings.Contains(strings.Join(kex, ","), "group14-sha1") ||
		!strings.Contains(strings.Join(kex, ","), "diffie-hellman-group-exchange-sha256") || kex[len(kex)-1] != "kex-strict-s-v00@openssh.com" {
		t.Fatalf("openssh: %q %v", banner, kex)
	}
	if strings.Join(hk, ",") != "rsa-sha2-256,rsa-sha2-512,ecdsa-sha2-nistp256,ssh-ed25519" {
		t.Fatalf("openssh host keys: %v", hk)
	}
	banner, kex, hk = personaKexInit(t, p2)
	if !strings.HasPrefix(banner, "SSH-2.0-dropbear_2024.8") || !strings.Contains(strings.Join(kex, ","), "diffie-hellman-group14-sha1") ||
		strings.Contains(strings.Join(kex, ","), "group-exchange") || hk[0] != "ssh-ed25519" || hk[len(hk)-1] != "ssh-rsa" {
		t.Fatalf("dropbear: %q %v %v", banner, kex, hk)
	}
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindProbe && e.Port == p2
	})
}

func TestSensorTelnetPersonas(t *testing.T) {
	old := sensorTelDelay
	sensorTelDelay = 0
	t.Cleanup(func() { sensorTelDelay = old })
	p1, p2 := sensorFreePort(t), sensorFreePort(t)
	sensorStart(t, Config{Seed: personaTestSeed, Hostname: "fileserver", Services: []Service{{SvcTelnet, p1, ""}, {SvcTelnet, p2, ""}},
		Personas: map[string]string{PersonaKey(SvcTelnet, p1): PersonaLinux}})
	id := newSensorIdent(personaTestSeed, "fileserver", nil)
	for _, c := range []struct {
		port      int
		iac, want string
	}{{p1, string(sensorTelIACLinux), "\r\n" + id.osIssue() + "\r\nfileserver login: "}, {p2, string(sensorTelIAC), "\r\nfileserver login: "}} {
		conn, err := net.Dial("tcp", sensorAddrOf(c.port))
		if err != nil {
			t.Fatal(err)
		}
		got := sensorReadUntil(t, conn, "login: ")
		conn.Close()
		if string(got) != c.iac+c.want {
			t.Fatalf("port %d: %q", c.port, got)
		}
	}
	// BusyBox ohne Hostname: Geraete-Name
	if h := newSensorIdent(personaTestSeed, "", nil).telnetHost(PersonaBusyBox); !strings.Contains("localhost (none) router gateway OpenWrt", h) {
		t.Fatalf("busybox host %q", h)
	}
}

func TestSensorMySQLPersonas(t *testing.T) {
	p1, p2 := sensorFreePort(t), sensorFreePort(t)
	sensorStart(t, Config{Seed: personaTestSeed, Services: []Service{{SvcMySQL, p1, ""}, {SvcMySQL, p2, ""}},
		Personas: map[string]string{PersonaKey(SvcMySQL, p1): PersonaMariaDB, PersonaKey(SvcMySQL, p2): PersonaMariaDB11}})
	id := newSensorIdent(personaTestSeed, "", nil)
	for _, c := range []struct {
		port   int
		prefix string
	}{{p1, "5.5.5-10.11."}, {p2, "5.5.5-11.4."}} {
		conn := sensorPGDial(t, c.port)
		_, g := sensorMySQLGet(t, conn)
		r := &sensorMySQLReader{b: g[1:]}
		ver := r.cstr()
		r.skip(13)
		lo := r.skip(2)
		cs := r.byte()
		r.skip(2)
		hi := r.skip(2)
		r.skip(11)
		r.skip(13)
		plugin := r.cstr()
		caps := uint32(binary.LittleEndian.Uint16(lo)) | uint32(binary.LittleEndian.Uint16(hi))<<16
		if !strings.HasPrefix(ver, c.prefix) || !strings.Contains(ver, "-MariaDB") || plugin != sensorMySQLNative || cs != 45 || caps&1 != 0 ||
			caps&sensorMySQLCapSSL != 0 || caps&sensorMySQLCapPlugin == 0 || r.bad {
			t.Fatalf("port %d: %q %q cs=%d caps=%x", c.port, ver, plugin, cs, caps)
		}
	}
	if pr := sensorMySQLProfileFor(PersonaMySQL, id); !strings.HasPrefix(pr.version, "8.0.") || pr.plugin != sensorMySQLSHA2 || pr.charset != 255 || pr.caps&sensorMySQLCapSSL != 0 {
		t.Fatalf("mysql: %+v", pr)
	}
}

// Alte Einstellung ohne Profile laedt unveraendert (Standard je Port); Profile und Hostname werden geprueft und
// gespeichert; die Tabelle speichert nur Abweichungen vom Standard.
func TestPersonaConfig(t *testing.T) {
	m, _ := modTest(t, modFreePort(t))
	ctx := context.Background()
	old := `{"profile":"full","scan":true,"retention_days":7,"max_events":200000}`
	if err := m.core.SetSetting(ctx, setConfig, old); err != nil {
		t.Fatal(err)
	}
	c := m.loadConfig(ctx)
	if c.Profile != ProfileFull || c.Personas != nil || c.Hostname != "" {
		t.Fatalf("old config: %+v", c)
	}
	info := m.catalogInfo(ctx, nil)
	for _, e := range info.Entries {
		if e.Port == 8006 && (e.Persona != PersonaPVE || e.DefaultPersona != PersonaPVE || len(e.Personas) != len(personaWeb)) {
			t.Fatalf("catalog 8006: %+v", e)
		}
	}
	if !ValidHostname(info.Hostname) {
		t.Fatalf("hostname %q", info.Hostname)
	}

	c.Hostname, c.Personas = "bad host", map[string]string{"ssh:22": "pve"}
	_, err := m.SaveConfig(ctx, c)
	fe, _ := err.(FieldErrors)
	if fe["hostname"] == "" || !strings.Contains(fe["personas"], "honeypot.err.persona|ssh:22|pve") {
		t.Fatalf("errors: %v", err)
	}

	// Tabelle: ssh 22 Dropbear, http 80 nginx (Standard, nicht gespeichert)
	v := catFormValues(map[string]bool{"ssh 22": true, "http 80": true})
	for i, e := range Catalog() {
		switch {
		case e.Service == SvcSSH && e.Port == 22:
			v.Set("persona_"+strconv.Itoa(i), PersonaDropbear)
		case e.Service == SvcHTTP && e.Port == 80:
			v.Set("persona_"+strconv.Itoa(i), PersonaNginx)
		}
	}
	v.Set("hostname", "gw01")
	if r := catPost(t, m, v); r.status != http.StatusSeeOther {
		t.Fatalf("save: %d %v", r.status, r.data.Errors)
	}
	c = m.loadConfig(ctx)
	if c.Profile != ProfileMinimal || len(c.Personas) != 1 || c.Personas["ssh:22"] != PersonaDropbear || c.Hostname != "gw01" {
		t.Fatalf("saved: %+v", c)
	}
	raw := m.core.SettingOr(ctx, setConfig, "")
	if !strings.Contains(raw, `"personas":{"ssh:22":"dropbear"}`) || !strings.Contains(raw, `"hostname":"gw01"`) {
		t.Fatalf("json: %s", raw)
	}
	// Ansicht nach Fehler: Auswahl wie eingegeben, Standard markiert
	v.Set("hostname", "bad host")
	r := catPost(t, m, v)
	if r.status != http.StatusUnprocessableEntity || r.data.Errors["hostname"] == "" || r.data.HostAuto == "" {
		t.Fatalf("bad hostname: %d %v", r.status, r.data.Errors)
	}
	for _, row := range r.data.CatRows {
		if row.Service == SvcSSH && row.Port == "22" && (row.PersonaSel != PersonaDropbear || len(row.Personas) != 4 || !row.Personas[0].Default) {
			t.Fatalf("row: %+v", row)
		}
	}
}

// „Verwundbar wirken“ (H8): aeltere Versionen nur auf den gewaehlten Ports, Pruefung der Einstellung.
func TestSensorVulnerable(t *testing.T) {
	p1, p2, p3 := sensorFreePort(t), sensorFreePort(t), sensorFreePort(t)
	cfg := Config{Seed: personaTestSeed, Services: []Service{{SvcHTTP, p1, ""}, {SvcHTTP, p2, ""}, {SvcSSH, p3, ""}},
		Personas:   map[string]string{PersonaKey(SvcHTTP, p1): PersonaApache, PersonaKey(SvcHTTP, p2): PersonaApache},
		Vulnerable: []string{PersonaKey(SvcHTTP, p1), PersonaKey(SvcSSH, p3)}}
	_, rec := sensorStart(t, cfg)
	cl := personaClient()
	_, _, h := sensorGet(t, cl, "GET", "http://"+sensorAddrOf(p1)+"/nichtda", "curl/8", "", nil)
	if s := h.Get("Server"); (s != "Apache/2.4.49 (Unix)" && s != "Apache/2.4.50 (Unix)") || !strings.HasPrefix(h.Get("X-Powered-By"), "PHP/7.4.") {
		t.Fatalf("alt: %v", h)
	}
	_, _, h = sensorGet(t, cl, "GET", "http://"+sensorAddrOf(p2)+"/nichtda", "curl/8", "", nil)
	if s := h.Get("Server"); strings.Contains(s, "2.4.49") || strings.Contains(s, "2.4.50") || h.Get("X-Powered-By") != "" {
		t.Fatalf("normal: %v", h)
	}
	banner, _, _ := personaKexInit(t, p3)
	if !strings.HasPrefix(banner, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.") && !strings.HasPrefix(banner, "SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u") {
		t.Fatalf("ssh: %q", banner)
	}
	rec.wait(t, func(e Event) bool { return e.Port == p1 })

	id := newSensorIdent(personaTestSeed, "", nil)
	old := *id
	old.old = true
	if v := old.grafanaVersion(); !strings.HasPrefix(v, "8.") || id.grafanaVersion() == v {
		t.Fatalf("grafana: %s / %s", v, id.grafanaVersion())
	}
	if v := old.webminVersion(); !strings.HasPrefix(v, "1.") {
		t.Fatalf("webmin: %s", v)
	}
	if pr := sensorMySQLProfileFor(PersonaMySQL, &old); !strings.HasPrefix(pr.version, "5.7.") {
		t.Fatalf("mysql: %s", pr.version)
	}
	if pr := sensorMySQLProfileFor(PersonaMariaDB, &old); !strings.HasPrefix(pr.version, "5.5.5-10.3.") {
		t.Fatalf("mariadb: %s", pr.version)
	}

	c := Config{Vulnerable: []string{" SSH:22 ", "http:80", "ssh:22", "redis:6379", "x"}}
	probs := PersonaProblems(&c)
	if strings.Join(c.Vulnerable, ",") != "http:80,ssh:22" || len(probs) != 2 || !strings.HasPrefix(probs[0], "honeypot.err.vulnerable|") {
		t.Fatalf("config: %v %v", c.Vulnerable, probs)
	}
	f := catForm{Rows: []catRow{{On: true, Service: SvcSSH, Port: "22", Old: true}, {On: false, Service: SvcHTTP, Port: "80", Old: true},
		{On: true, Service: SvcRedis, Port: "6379", Old: true}}}
	if v := f.vulnerable(); strings.Join(v, ",") != "ssh:22" {
		t.Fatalf("form: %v", v)
	}
	f.Rows[0].Old = false
	f.withOld([]string{"ssh:22"})
	if !f.Rows[0].Old || f.Rows[1].Old {
		t.Fatalf("withOld: %+v", f.Rows)
	}
}
