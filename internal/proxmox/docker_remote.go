package proxmox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Docker-Hosts aus der Ferne – ohne eigenen Agenten, die Docker-API reicht:
//
//	tcp://host:2375, http(s)://…  Docker-API direkt bzw. ueber docker-socket-proxy (nur lesend freigeben)
//	https://host:2376             Docker-Daemon mit TLS (--tlsverify): Client-Zertifikat und -Schluessel, Server per CA
//	                              (ca.pem), festgepinntem Zertifikat (wie Proxmox) oder System-CA
//	ssh://user@host[:port][/sock] per SSH zum Socket des Hosts: Socket-Weiterleitung (direct-streamlocal, braucht
//	                              AllowTcpForwarding) bzw. sonst „docker system dial-stdio“ auf dem Host wie der Docker-
//	                              Client bei -H ssh:// (geht auch mit restrict,command="docker system dial-stdio" im
//	                              authorized_keys); Schluessel ohne Passphrase, Host-Key festgepinnt (SHA-256)
//
// Zugangsdaten stehen als JSON im Secret des Systems (verschluesselt), der Pin im Feld PinSHA256 (Zertifikat bzw.
// Host-Key, Hex). Eine SSH-Verbindung je Host, darueber ein Kanal je HTTP-Verbindung.

const (
	dockerSSHPort      = "22"
	dockerSSHSocket    = "/var/run/docker.sock"
	dockerDialTimeout  = 10 * time.Second
	dockerMaxSecret    = 64 << 10
	dockerKeyComment   = "node64"
	dockerSSHKeepAlive = 30 * time.Second
)

// Fehler der Fernverbindung (errors.Is).
var (
	ErrDockerUnconfirmed = errors.New("fingerprint not confirmed yet")
	errDockerNoKey       = errors.New("no ssh key")
)

// DockerCreds sind die Zugangsdaten eines Docker-Hosts (Secret als JSON).
type DockerCreds struct {
	Key  string `json:"key,omitempty"`  // privater Schluessel (PEM): SSH bzw. TLS-Client
	Cert string `json:"cert,omitempty"` // TLS-Client-Zertifikat (PEM)
	CA   string `json:"ca,omitempty"`   // CA des Docker-Daemons (PEM); leer = Pin bzw. System-CA
}

// ParseDockerCreds liest das Secret (leer bzw. kaputt = keine Zugangsdaten). Ein Secret ohne JSON (API: secret =
// privater SSH-Schluessel als PEM) ist der Schluessel.
func ParseDockerCreds(secret string) DockerCreds {
	var c DockerCreds
	switch s := strings.TrimSpace(secret); {
	case strings.HasPrefix(s, "{"):
		_ = json.Unmarshal([]byte(s), &c)
	case strings.HasPrefix(s, "-----BEGIN"):
		c.Key = s + "\n"
	}
	return c
}

// Empty sagt, ob keine Zugangsdaten gesetzt sind.
func (c DockerCreds) Empty() bool { return c.Key == "" && c.Cert == "" && c.CA == "" }

// DockerNoCreds als Secret loescht gespeicherte Zugangsdaten (ein leeres Secret heisst beim Aendern „behalten“).
const DockerNoCreds = "{}"

// Encode schreibt die Zugangsdaten als Secret ("" ohne Zugangsdaten).
func (c DockerCreds) Encode() string {
	if c.Empty() {
		return ""
	}
	b, _ := json.Marshal(c)
	return string(b)
}

// DockerScheme ist die Art der Verbindung: unix, tcp, http, https oder ssh.
func DockerScheme(host string) string {
	s, _, _ := strings.Cut(host, "://")
	return strings.ToLower(s)
}

// DockerUsesSecret sagt, ob der Host Zugangsdaten bzw. einen Pin haben kann (https, ssh).
func DockerUsesSecret(host string) bool {
	s := DockerScheme(host)
	return s == "https" || s == "ssh"
}

// DockerLocal sagt, ob der Host ein Socket dieser Maschine ist.
func DockerLocal(host string) bool { return DockerScheme(host) == "unix" }

// dockerSSHTarget zerlegt ssh://user@host[:port][/pfad] (Port 22, Socket /var/run/docker.sock).
func dockerSSHTarget(host string) (user, addr, sock string, err error) {
	u, err := url.Parse(host)
	if err != nil || u.Scheme != "ssh" || u.User == nil || u.User.Username() == "" || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" {
		return "", "", "", errors.New("use ssh://user@host[:port][/path/to/docker.sock]")
	}
	if _, has := u.User.Password(); has {
		return "", "", "", errors.New("no password in the address, the node uses an ssh key")
	}
	port := u.Port()
	if port == "" {
		port = dockerSSHPort
	}
	sock = u.Path
	if sock == "" || sock == "/" {
		sock = dockerSSHSocket
	}
	if !dockerSockRe.MatchString(sock) { // geht auch in den Befehl docker -H unix://…
		return "", "", "", errors.New("socket path may only contain letters, digits and / . _ -")
	}
	return u.User.Username(), net.JoinHostPort(u.Hostname(), port), sock, nil
}

var dockerSockRe = regexp.MustCompile(`^/[A-Za-z0-9/._-]{1,200}$`)

// SSHFingerprint ist der SHA-256 des Host-Keys (Hex wie die Pins, ohne Doppelpunkte).
func SSHFingerprint(key ssh.PublicKey) string {
	s := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(s[:])
}

// PinBase64 zeigt einen Hex-Pin wie ssh-keygen -l (SHA256:…); "" bei ungueltigem Pin.
func PinBase64(pin string) string {
	b, err := hex.DecodeString(pin)
	if err != nil || len(b) != sha256.Size {
		return ""
	}
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(b)
}

// NormalizeDockerPin nimmt einen Pin als Hex (mit oder ohne Doppelpunkte) oder wie ssh-keygen (SHA256:…).
func NormalizeDockerPin(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if rest, ok := strings.CutPrefix(s, "SHA256:"); ok {
		b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(rest, "="))
		if err != nil || len(b) != sha256.Size {
			return "", false
		}
		return hex.EncodeToString(b), true
	}
	return NormalizePin(s)
}

// GenerateDockerSSHKey erzeugt einen ed25519-Schluessel (PEM) fuer einen Docker-Host per SSH.
func GenerateDockerSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, dockerKeyComment)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// DockerSSHPublicKey liefert die Zeile fuer authorized_keys zum privaten Schluessel ("" bei Fehler).
func DockerSSHPublicKey(privPEM string) string {
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " " + dockerKeyComment
}

// validateDockerCreds prueft die Zugangsdaten passend zur Art der Verbindung.
func validateDockerCreds(host string, c DockerCreds) error {
	switch DockerScheme(host) {
	case "ssh":
		if c.Key == "" {
			return pveFerr("key", "docker.err.key")
		}
		if _, err := ssh.ParsePrivateKey([]byte(c.Key)); err != nil {
			var pp *ssh.PassphraseMissingError
			if errors.As(err, &pp) {
				return pveFerr("key", "docker.err.key_passphrase")
			}
			return pveFerr("key", "docker.err.key")
		}
	case "https":
		if (c.Cert == "") != (c.Key == "") {
			return pveFerr("cert", "docker.err.cert_pair")
		}
		if c.Cert != "" {
			if _, err := tls.X509KeyPair([]byte(c.Cert), []byte(c.Key)); err != nil {
				return pveFerr("cert", "docker.err.cert")
			}
		}
		if c.CA != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.CA)) {
			return pveFerr("ca", "docker.err.ca")
		}
	}
	return nil
}

// dockerConn ist die Verbindung zu einem Docker-Host (HTTP-Client, Basis-URL, Schliessen).
type dockerConn struct {
	hc    *http.Client
	base  string
	close func()
}

// dockerConnect baut die Verbindung eines Systems. seen bekommt den Fingerabdruck des Zertifikats bzw. Host-Keys
// (Test im Formular); ohne Pin und ohne Vertrauen bricht die Verbindung mit ErrDockerUnconfirmed ab, ehe Schluessel
// oder Zertifikat benutzt werden.
func dockerConnect(sys System, seen func(fp string, trusted bool)) (*dockerConn, error) {
	host := DefaultDockerHost()
	if len(sys.Addresses) > 0 && strings.TrimSpace(sys.Addresses[0]) != "" {
		host = strings.TrimSpace(sys.Addresses[0])
	}
	pin, ok := NormalizeDockerPin(sys.PinSHA256)
	if !ok {
		return nil, errors.New("fingerprint must be 64 hex digits (SHA-256) or SHA256:…")
	}
	creds := ParseDockerCreds(sys.Secret)
	switch DockerScheme(host) {
	case "ssh":
		return dockerConnectSSH(host, pin, creds, seen)
	case "https":
		return dockerConnectTLS(host, pin, creds, seen)
	}
	hc, base, err := dockerHTTP(host)
	if err != nil {
		return nil, err
	}
	return &dockerConn{hc: hc, base: base, close: hc.CloseIdleConnections}, nil
}

// dockerConnectTLS: Server per Pin (nur der Fingerabdruck des Leaf-Zertifikats), sonst CA bzw. System-CA mit Hostname.
func dockerConnectTLS(host, pin string, creds DockerCreds, seen func(string, bool)) (*dockerConn, error) {
	u, err := url.Parse(host)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("invalid docker host %q", host)
	}
	var roots *x509.CertPool
	if creds.CA != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM([]byte(creds.CA)) {
			return nil, errors.New("CA certificate (ca.pem) is not valid PEM")
		}
	}
	name := u.Hostname()
	// Kette und Hostname selbst pruefen (InsecureSkipVerify nur zusammen mit dieser Pruefung): so sieht der Test den
	// Fingerabdruck auch eines unbekannten Zertifikats.
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // eigene Pruefung unten
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return &errPinMismatch{got: "(none)"}
			}
			got := CertFingerprint(raw[0])
			trusted := false
			if leaf, err := x509.ParseCertificate(raw[0]); err == nil {
				inter := x509.NewCertPool()
				for _, r := range raw[1:] {
					if c, err := x509.ParseCertificate(r); err == nil {
						inter.AddCert(c)
					}
				}
				_, verr := leaf.Verify(x509.VerifyOptions{DNSName: name, Roots: roots, Intermediates: inter})
				trusted = verr == nil
			}
			if seen != nil {
				seen(got, trusted)
			}
			switch {
			case pin != "" && got != pin:
				return &errPinMismatch{got: got}
			case pin == "" && !trusted:
				return ErrDockerUnconfirmed
			}
			return nil
		}}
	if creds.Cert != "" {
		pair, err := tls.X509KeyPair([]byte(creds.Cert), []byte(creds.Key))
		if err != nil {
			return nil, errors.New("client certificate and key do not match: " + err.Error())
		}
		tc.Certificates = []tls.Certificate{pair}
	}
	d := &net.Dialer{Timeout: dockerDialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{Proxy: nil, DialContext: d.DialContext, TLSClientConfig: tc, TLSHandshakeTimeout: dockerDialTimeout,
		ResponseHeaderTimeout: dockerRequestTimeout, MaxIdleConnsPerHost: dockerParallel, IdleConnTimeout: 90 * time.Second}
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &dockerConn{hc: hc, base: strings.TrimRight(host, "/"), close: tr.CloseIdleConnections}, nil
}

// dockerHostKeyAlgos: Ed25519 zuerst (wie der Hinweis im Formular: ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub),
// ohne Zertifikats-Algorithmen (der Pin ist der Schluessel des Hosts).
var dockerHostKeyAlgos = []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}

// dockerStdioFor: so lange nach einer verweigerten Socket-Weiterleitung gleich dial-stdio, danach wieder versuchen.
const dockerStdioFor = 10 * time.Minute

// dockerSSH haelt die SSH-Verbindung eines Hosts (bei Abbruch neu).
type dockerSSH struct {
	addr, sock string
	cfg        *ssh.ClientConfig
	stdioUntil atomic.Int64 // Unix-Zeit: bis dahin docker system dial-stdio (Socket-Weiterleitung verweigert)
	mu         sync.Mutex
	c          *ssh.Client
	closed     bool
}

func dockerConnectSSH(host, pin string, creds DockerCreds, seen func(string, bool)) (*dockerConn, error) {
	user, addr, sock, err := dockerSSHTarget(host)
	if err != nil {
		return nil, err
	}
	if creds.Key == "" {
		return nil, errDockerNoKey
	}
	signer, err := ssh.ParsePrivateKey([]byte(creds.Key))
	if err != nil {
		return nil, errors.New("ssh key: " + err.Error())
	}
	cfg := &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, Timeout: dockerDialTimeout,
		HostKeyAlgorithms: dockerHostKeyAlgos,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if c, ok := key.(*ssh.Certificate); ok { // Host-Zertifikat: der Schluessel zaehlt, nicht die Ausstellung
				key = c.Key
			}
			got := SSHFingerprint(key)
			if seen != nil {
				seen(got, false)
			}
			switch {
			case pin == "":
				return ErrDockerUnconfirmed
			case got != pin:
				return fmt.Errorf("ssh host key %s does not match the pin", PinBase64(got))
			}
			return nil
		}}
	d := &dockerSSH{addr: addr, sock: sock, cfg: cfg}
	tr := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return d.dial(ctx) },
		ResponseHeaderTimeout: dockerRequestTimeout, MaxIdleConnsPerHost: dockerParallel, MaxConnsPerHost: dockerParallel,
		IdleConnTimeout: 90 * time.Second} // MaxConnsPerHost: wartende Anfragen stauen keine Verbindungsversuche (Host haengt)
	return &dockerConn{hc: &http.Client{Transport: tr}, base: "http://docker", close: func() {
		tr.CloseIdleConnections()
		d.shutdown()
	}}, nil
}

// client liefert die SSH-Verbindung (baut sie bei Bedarf auf).
func (d *dockerSSH) client(ctx context.Context) (*ssh.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, net.ErrClosed
	}
	if d.c != nil {
		return d.c, nil
	}
	nd := &net.Dialer{Timeout: dockerDialTimeout, KeepAlive: dockerSSHKeepAlive}
	conn, err := nd.DialContext(ctx, "tcp", d.addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(dockerDialTimeout))
	cc, chans, reqs, err := ssh.NewClientConn(conn, d.addr, d.cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	d.c = ssh.NewClient(cc, chans, reqs)
	go d.keepAlive(d.c)
	return d.c, nil
}

// keepAlive haelt die Verbindung offen und erkennt tote Verbindungen (dann wird beim naechsten Mal neu verbunden).
func (d *dockerSSH) keepAlive(c *ssh.Client) {
	t := time.NewTicker(dockerSSHKeepAlive)
	defer t.Stop()
	done := make(chan struct{})
	go func() { _ = c.Wait(); close(done) }()
	for {
		select {
		case <-done:
			d.drop(c)
			return
		case <-t.C:
			res := make(chan error, 1)
			go func() { _, _, err := c.SendRequest("keepalive@openssh.com", true, nil); res <- err }()
			select {
			case err := <-res:
				if err != nil {
					d.drop(c)
					return
				}
			case <-time.After(dockerDialTimeout):
				d.drop(c)
				return
			case <-done:
				d.drop(c)
				return
			}
		}
	}
}

// drop schliesst c, wenn es noch die aktuelle Verbindung ist.
func (d *dockerSSH) drop(c *ssh.Client) {
	d.mu.Lock()
	if d.c == c {
		d.c = nil
	}
	d.mu.Unlock()
	c.Close()
}

func (d *dockerSSH) shutdown() {
	d.mu.Lock()
	c := d.c
	d.c, d.closed = nil, true
	d.mu.Unlock()
	if c != nil {
		c.Close()
	}
}

// dial oeffnet eine Verbindung zur Docker-API; ist die SSH-Verbindung weg, einmal neu verbinden.
func (d *dockerSSH) dial(ctx context.Context) (net.Conn, error) {
	var last error
	for try := 0; try < 2; try++ {
		c, err := d.client(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := d.open(ctx, c)
		if err == nil {
			return conn, nil
		}
		if ctx.Err() != nil {
			d.drop(c)
			return nil, ctx.Err()
		}
		last = err
		var oc *ssh.OpenChannelError
		if errors.As(err, &oc) { // Server lehnt ab (Rechte, Weiterleitung aus): neu verbinden hilft nicht
			return nil, err
		}
		d.drop(c)
	}
	return nil, last
}

// open: Socket-Weiterleitung (direct-streamlocal); verweigert der Server sie (AllowTcpForwarding no, restrict), startet
// es auf dem Host „docker system dial-stdio“ und merkt sich das.
func (d *dockerSSH) open(ctx context.Context, c *ssh.Client) (net.Conn, error) {
	if time.Now().Unix() < d.stdioUntil.Load() {
		return sshConnCtx(ctx, func() (net.Conn, error) { return d.stdioConn(c) })
	}
	conn, err := sshConnCtx(ctx, func() (net.Conn, error) { return c.Dial("unix", d.sock) })
	var oc *ssh.OpenChannelError
	if err == nil || !errors.As(err, &oc) {
		return conn, err
	}
	conn, serr := sshConnCtx(ctx, func() (net.Conn, error) { return d.stdioConn(c) })
	if serr != nil {
		return nil, fmt.Errorf("%w; docker system dial-stdio: %v", err, serr)
	}
	d.stdioUntil.Store(time.Now().Add(dockerStdioFor).Unix()) // nicht fuer immer: ein kurz fehlender Socket sieht genauso aus
	return conn, nil
}

// sshConnCtx fuehrt f aus, bricht mit ctx ab (eine spaeter doch geoeffnete Verbindung wird geschlossen).
func sshConnCtx(ctx context.Context, f func() (net.Conn, error)) (net.Conn, error) {
	type res struct {
		conn net.Conn
		err  error
	}
	ch := make(chan res, 1)
	go func() { conn, err := f(); ch <- res{conn, err} }()
	select {
	case r := <-ch:
		return r.conn, r.err
	case <-ctx.Done():
		go func() {
			if r := <-ch; r.err == nil {
				r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

// stdioConn startet „docker system dial-stdio“ auf dem Host; Ein- und Ausgabe sind die Verbindung zur Docker-API.
func (d *dockerSSH) stdioConn(c *ssh.Client) (net.Conn, error) {
	s, err := c.NewSession()
	if err != nil {
		return nil, err
	}
	in, err := s.StdinPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	out, err := s.StdoutPipe()
	if err != nil {
		s.Close()
		return nil, err
	}
	stderr := &sshErrBuf{}
	s.Stderr = stderr
	cmd := "docker system dial-stdio"
	if d.sock != dockerSSHSocket {
		cmd = "docker -H unix://" + d.sock + " system dial-stdio" // Pfad nur aus dockerSockRe
	}
	if err := s.Start(cmd); err != nil {
		s.Close()
		return nil, err
	}
	return &sshStdioConn{s: s, r: out, w: in, stderr: stderr, d: d}, nil
}

// sshErrBuf sammelt die ersten 1024 Byte der Fehlerausgabe.
type sshErrBuf struct {
	mu sync.Mutex
	b  []byte
}

func (e *sshErrBuf) Write(p []byte) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if room := 1024 - len(e.b); room > 0 {
		e.b = append(e.b, p[:min(len(p), room)]...)
	}
	return len(p), nil
}

func (e *sshErrBuf) String() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return strings.TrimSpace(string(e.b))
}

// sshStdioConn ist eine Verbindung ueber Ein- und Ausgabe eines Befehls (ohne Deadlines; Abbruch per Close).
type sshStdioConn struct {
	s        *ssh.Session
	r        io.Reader
	w        io.WriteCloser
	stderr   *sshErrBuf
	d        *dockerSSH // scheitert der Befehl, gleich wieder die Weiterleitung versuchen
	got      atomic.Bool
	wmu      sync.Mutex // x/crypto/ssh: Write und CloseWrite (stdin schliessen) nicht gleichzeitig
	once     sync.Once
	waitOnce sync.Once
	waited   chan struct{}
}

func (c *sshStdioConn) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.got.Store(true)
	}
	if err == io.EOF && !c.got.Load() { // Befehl ohne Ausgabe beendet: Fehler von docker bzw. der Shell zeigen
		return n, c.failed(err)
	}
	return n, err
}

func (c *sshStdioConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	n, err := c.w.Write(p)
	c.wmu.Unlock()
	if err != nil && !c.got.Load() { // Befehl schon beendet (nicht gefunden, keine Rechte)
		return n, c.failed(err)
	}
	return n, err
}

// failed wartet kurz auf das Ende des Befehls und liefert seine Fehlerausgabe statt err (falls vorhanden).
func (c *sshStdioConn) failed(err error) error {
	c.waitOnce.Do(func() {
		c.waited = make(chan struct{})
		go func() { _ = c.s.Wait(); close(c.waited) }()
	})
	select {
	case <-c.waited:
	case <-time.After(2 * time.Second):
	}
	if c.d != nil {
		c.d.stdioUntil.Store(0)
	}
	if msg := c.stderr.String(); msg != "" {
		return errors.New("docker system dial-stdio: " + msg)
	}
	return err
}

func (c *sshStdioConn) Close() error {
	c.once.Do(func() {
		if c.wmu.TryLock() { // haengt ein Write (volles Fenster), beendet s.Close die Sitzung auch ohne EOF
			_ = c.w.Close()
			c.wmu.Unlock()
		}
		_ = c.s.Close()
	})
	return nil
}

func (c *sshStdioConn) LocalAddr() net.Addr              { return sshStdioAddr{} }
func (c *sshStdioConn) RemoteAddr() net.Addr             { return sshStdioAddr{} }
func (c *sshStdioConn) SetDeadline(time.Time) error      { return nil }
func (c *sshStdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *sshStdioConn) SetWriteDeadline(time.Time) error { return nil }

type sshStdioAddr struct{}

func (sshStdioAddr) Network() string { return "ssh" }
func (sshStdioAddr) String() string  { return "docker system dial-stdio" }

// DockerProbeResult ist das Ergebnis des Verbindungstests im Formular.
type DockerProbeResult struct {
	OK          bool
	Error       string
	Fingerprint string // gesehenes Zertifikat bzw. Host-Key (Hex)
	Trusted     bool   // Zertifikat von CA bzw. System-CA bestaetigt (https)
	NeedConfirm bool   // Fingerabdruck erst bestaetigen (Schluessel bzw. Zertifikat wurden nicht benutzt)
	Info        *DockerInfo
	Containers  int
	Running     int
	Warning     string
}

// DockerProbe testet einen Docker-Host: Verbindung (mit Fingerabdruck), /version, Containerliste, /info.
func DockerProbe(ctx context.Context, sys System) (res DockerProbeResult) {
	var mu sync.Mutex
	var fp string
	var trusted bool
	defer func() {
		mu.Lock()
		res.Fingerprint, res.Trusted = fp, trusted
		mu.Unlock()
	}()
	conn, err := dockerConnect(sys, func(f string, t bool) {
		mu.Lock()
		fp, trusted = f, t
		mu.Unlock()
	})
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer conn.close()
	p := &DockerPoller{hc: conn.hc, base: conn.base}
	host := dockerSysAddr(sys)
	var ver struct {
		Version string `json:"Version"`
		Os      string `json:"Os"`
	}
	if err := p.get(ctx, "/version", &ver); err != nil {
		if errors.Is(err, ErrDockerUnconfirmed) {
			res.NeedConfirm = true
			return res
		}
		res.Error = dockerHintFor(host, err)
		return res
	}
	var list []struct {
		State string `json:"State"`
	}
	if err := p.get(ctx, "/containers/json?all=1", &list); err != nil {
		res.Error = dockerHintFor(host, err)
		return res
	}
	res.OK = true
	res.Containers = len(list)
	for _, c := range list {
		if c.State == "running" {
			res.Running++
		}
	}
	var info dockerInfoRaw
	if err := p.get(ctx, "/info", &info); err == nil {
		res.Info = info.toInfo()
	} else {
		res.Info = &DockerInfo{OS: ver.Os}
		res.Warning = "GET /info failed (docker-socket-proxy: INFO=1): " + err.Error()
	}
	if res.Info.Version == "" {
		res.Info.Version = ver.Version
	}
	return res
}

// dockerSysAddr: Adresse eines Systems (leer = Standard).
func dockerSysAddr(sys System) string {
	if len(sys.Addresses) > 0 && strings.TrimSpace(sys.Addresses[0]) != "" {
		return strings.TrimSpace(sys.Addresses[0])
	}
	return DefaultDockerHost()
}

// dockerHintFor erklaert typische Fehler je Art der Verbindung.
func dockerHintFor(host string, err error) string {
	msg := err.Error()
	switch DockerScheme(host) {
	case "unix", "":
		return dockerHint(err)
	case "ssh":
		switch {
		case strings.Contains(msg, "unable to authenticate"):
			return msg + " – add the public key of this host to ~/.ssh/authorized_keys of the user on the docker host"
		case strings.Contains(msg, "dial-stdio") && strings.Contains(msg, "not found"):
			return msg + " – the docker CLI is missing on the host: install it (docker-ce-cli) or allow socket forwarding in sshd (AllowTcpForwarding yes, key without restrict)"
		case strings.Contains(strings.ToLower(msg), "permission denied"), strings.Contains(msg, "connect failed"), strings.Contains(msg, "open failed"):
			return msg + " – the user may not open the docker socket: add it to the group docker, or check the socket path"
		}
	case "https":
		if errors.Is(err, ErrDockerUnconfirmed) || strings.Contains(msg, "certificate") {
			return msg + " – check the CA (ca.pem) or confirm the certificate fingerprint"
		}
		if strings.Contains(msg, "remote error: tls") {
			return msg + " – the docker daemon rejected the client certificate (cert.pem/key.pem signed by its CA?)"
		}
	}
	return msg
}
