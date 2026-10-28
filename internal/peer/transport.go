package peer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Uebertragung im Cluster: nur HTTPS, das Zertifikat wird nicht geprueft (selbst signiert ok). Gegen einen
// Mittelsmann schuetzt die Bindung an die Kopplung: beide Seiten leiten aus ihrer TLS-Verbindung einen Wert ab
// (Exporter, RFC 5705/8446), der in die Ed25519-Signatur jeder Anfrage und jeder Antwort eingeht. Ein Proxy, der
// TLS terminiert, hat zu beiden Seiten eigene Verbindungen mit anderen Werten: die Node lehnt die Anfrage ab, bevor
// ihr Handler laeuft, und der Client erkennt die Antwort nicht an. Anfragen mit Body gehen erst nach einem
// signierten Ping ueber dieselbe Verbindung raus (die Gegenseite ist dann bewiesen, bevor Daten fliessen).
// Zertifikate spielen keine Rolle (kein Pinning): ein Zertifikatswechsel der Node aendert nichts.
const (
	hdrNonce  = "X-Node64-Nonce"
	hdrBind   = "X-Node64-Bind"  // eigener Exporter (nur zur Diagnose: Bindung falsch statt Signatur falsch)
	hdrProto  = "X-Node64-Proto" // Antworten der Cluster-Version (fehlt = aeltere Version)
	proto     = "2"
	bindLabel = "EXPORTER-node64-cluster"
	bindLen   = 32
	// callTimeout gilt, wenn ctx keine Frist hat
	callTimeout = 10 * time.Second
)

func reqMsg(method, path, ts, acc, nonce string, bind, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("node64-req\n" + method + "\n" + path + "\n" + ts + "\n" + acc + "\n" + nonce + "\n" + hex.EncodeToString(bind) + "\n" + hex.EncodeToString(h[:]))
}

func respMsg(status int, nonce, node string, bind, body []byte) []byte {
	h := sha256.Sum256(body)
	return []byte("node64-resp\n" + strconv.Itoa(status) + "\n" + nonce + "\n" + node + "\n" + hex.EncodeToString(bind) + "\n" + hex.EncodeToString(h[:]))
}

func tlsBind(cs *tls.ConnectionState) ([]byte, error) {
	if cs == nil {
		return nil, errors.New("no tls")
	}
	return cs.ExportKeyingMaterial(bindLabel, nil, bindLen)
}

// suspendErr: die Antwort zeigt eine grundlegende Aenderung (call setzt das Mitglied aus).
type suspendErr struct {
	reason string
	msg    string
}

func (e *suspendErr) Error() string { return e.msg }

// httpsURL macht aus einer Adresse eine https-Adresse (ohne Schema oder mit http: https, gleicher Port).
func httpsURL(s string) string {
	s = strings.TrimRight(strings.TrimSpace(s), "/")
	l := strings.ToLower(s)
	switch {
	case s == "" || strings.HasPrefix(l, "https://"):
		return s
	case strings.HasPrefix(l, "http://"):
		return "https://" + s[len("http://"):]
	case !strings.Contains(s, "://"):
		return "https://" + s
	}
	return s
}

// selfAddr: https-Adresse dieser Node aus u ("" = kein Host). Ein angegebener Port bleibt (von aussen gesehen, z. B.
// Docker-Portweiterleitung; der Web-Port spricht auch TLS), ohne Port gilt der eigene HTTPS-Port.
func selfAddr(u string, port int) string {
	p, err := url.Parse(httpsURL(u))
	if err != nil || p.Hostname() == "" {
		return ""
	}
	if p.Port() != "" {
		return "https://" + p.Host
	}
	return "https://" + net.JoinHostPort(p.Hostname(), strconv.Itoa(port))
}

// HTTPSPort ist der Port, ueber den der Cluster diese Node erreicht (0 = keiner, dann kein Cluster: ErrNoHTTPS).
func (m *Manager) HTTPSPort() int { return m.httpsPort() }

// TLSAvailable: diese Node ist per TLS erreichbar (HTTPS-Port oder Web-Port per Dualport), der Cluster ist moeglich.
func (m *Manager) TLSAvailable() bool { return m.httpsPort() > 0 }

func (m *Manager) httpsPort() int {
	if m.d.HTTPSPort == nil {
		return 0
	}
	return m.d.HTTPSPort()
}

// ---------------------------------------------------------------- Client

// peerConn ist eine TLS-Verbindung zu einer Node (eine je Aufruf, Anfragen nacheinander).
type peerConn struct {
	c      *tls.Conn
	br     *bufio.Reader
	base   string
	bind   []byte
	stop   func() bool
	cancel context.CancelFunc
}

func (p *peerConn) Close() {
	p.stop()
	_ = p.c.Close()
	p.cancel()
}

// dialPeer baut die TLS-Verbindung auf (ohne Zertifikatspruefung) und leitet den Wert fuer die Bindung ab.
func dialPeer(ctx context.Context, raw string) (*peerConn, error) {
	base := httpsURL(raw)
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" || u.Scheme != "https" {
		return nil, fmt.Errorf("invalid cluster address %q", raw)
	}
	cancel := context.CancelFunc(func() {})
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, callTimeout)
	}
	addr := u.Host
	if u.Port() == "" {
		addr = net.JoinHostPort(u.Hostname(), "443")
	}
	var d net.Dialer
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		cancel()
		return nil, err
	}
	cfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}} //nolint:gosec // Schutz ueber die Bindung an die Kopplung
	if net.ParseIP(u.Hostname()) == nil {
		cfg.ServerName = u.Hostname()
	}
	c := tls.Client(nc, cfg)
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	p := &peerConn{c: c, br: bufio.NewReader(c), base: base, stop: context.AfterFunc(ctx, func() { _ = c.Close() }), cancel: cancel}
	if err := c.HandshakeContext(ctx); err != nil {
		p.Close()
		return nil, err
	}
	cs := c.ConnectionState()
	if p.bind, err = tlsBind(&cs); err != nil {
		p.Close()
		return nil, &suspendErr{ReasonTLSBinding, "tls binding not available: " + err.Error()}
	}
	return p, nil
}

// do schickt eine Anfrage ueber die Verbindung und liest die Antwort.
func (p *peerConn) do(ctx context.Context, method, path string, body []byte, hdr http.Header) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if err := req.Write(p.c); err != nil {
		return 0, nil, nil, err
	}
	resp, err := http.ReadResponse(p.br, req)
	if err != nil {
		return 0, nil, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	resp.Body.Close()
	if err != nil {
		return 0, nil, nil, err
	}
	if len(b) > maxBody { // abgeschnitten: die Signatur passte nicht, das ist aber kein Identitaetswechsel
		return 0, nil, nil, fmt.Errorf("cluster answer larger than %d bytes", maxBody)
	}
	return resp.StatusCode, resp.Header, b, nil
}

// exchange schickt eine signierte Anfrage an ein Mitglied und prueft die Antwort (Signatur, Bindung, Kennung).
// Mit Body geht zuerst ein Ping ueber dieselbe Verbindung (Daten erst, wenn die Gegenseite bewiesen ist).
func (m *Manager) exchange(ctx context.Context, x Member, method, path string, body []byte) (int, []byte, error) {
	p, err := dialPeer(ctx, x.URL)
	if err != nil {
		return 0, nil, err
	}
	defer p.Close()
	if len(body) > 0 {
		st, b, err := m.signedDo(ctx, p, x, http.MethodGet, "/peer/v1/ping", nil)
		if err != nil || st != http.StatusOK {
			return st, b, err
		}
	}
	return m.signedDo(ctx, p, x, method, path, body)
}

func (m *Manager) signedDo(ctx context.Context, p *peerConn, x Member, method, path string, body []byte) (int, []byte, error) {
	n := make([]byte, 16)
	if _, err := rand.Read(n); err != nil {
		return 0, nil, err
	}
	nonce := hex.EncodeToString(n)
	ts, accS := strconv.FormatInt(time.Now().Unix(), 10), strconv.FormatInt(m.d.AccountID(), 10)
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("User-Agent", "node64/"+m.d.Version)
	hdr.Set(hdrNode, m.d.NodeID())
	hdr.Set(hdrTime, ts)
	hdr.Set(hdrAcc, accS)
	hdr.Set(hdrNonce, nonce)
	hdr.Set(hdrBind, hex.EncodeToString(p.bind))
	hdr.Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(m.priv, reqMsg(method, path, ts, accS, nonce, p.bind, body))))
	st, rh, b, err := p.do(ctx, method, path, body, hdr)
	if err != nil {
		return 0, nil, err
	}
	if err := checkResp(x, st, rh, b, p.bind, nonce); err != nil {
		return st, b, err
	}
	return st, b, nil
}

// checkResp prueft, dass die Antwort von der gekoppelten Node ueber genau diese Verbindung kommt.
func checkResp(x Member, status int, h http.Header, body, bind []byte, nonce string) error {
	if h.Get(hdrProto) == "" {
		var e struct {
			Error string `json:"error"`
		}
		if (status == http.StatusUnauthorized || status == http.StatusForbidden) && json.Unmarshal(body, &e) == nil && e.Error != "" {
			return &suspendErr{ReasonVersionTooOld, "node64 version without cluster protocol"} // aeltere Node (alte Signatur)
		}
		return fmt.Errorf("no node64 cluster answer (HTTP %d)", status)
	}
	if id := h.Get(hdrNode); id != x.NodeID {
		return &suspendErr{ReasonIdentityChanged, "other node at this address"}
	}
	pub, err := base64.StdEncoding.DecodeString(x.PubKey)
	sig, err2 := base64.StdEncoding.DecodeString(h.Get(hdrSig))
	if err != nil || err2 != nil || len(pub) != ed25519.PublicKeySize {
		return &suspendErr{ReasonIdentityChanged, "answer not signed by the paired key"}
	}
	if ed25519.Verify(ed25519.PublicKey(pub), respMsg(status, nonce, x.NodeID, bind, body), sig) {
		return nil
	}
	// echte Node, aber ueber eine andere Verbindung signiert: ein Mittelsmann terminiert TLS
	if pb, err := hex.DecodeString(h.Get(hdrBind)); err == nil && len(pb) == bindLen && !bytes.Equal(pb, bind) &&
		ed25519.Verify(ed25519.PublicKey(pub), respMsg(status, nonce, x.NodeID, pb, body), sig) {
		return &suspendErr{ReasonTLSBinding, "connection not bound to the pairing (proxy in between?)"}
	}
	return &suspendErr{ReasonIdentityChanged, "answer not signed by the paired key"}
}

// ---------------------------------------------------------------- Server

// sigWriter sammelt die Antwort eines Handlers, damit sie signiert werden kann.
type sigWriter struct {
	hdr  http.Header
	code int
	buf  bytes.Buffer
}

func (s *sigWriter) Header() http.Header { return s.hdr }
func (s *sigWriter) WriteHeader(code int) {
	if s.code == 0 {
		s.code = code
	}
}
func (s *sigWriter) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.buf.Write(b)
}

// sendSigned schickt die gesammelte Antwort mit Signatur ueber Status, Nonce der Anfrage, Bindung und Body.
func (m *Manager) sendSigned(w http.ResponseWriter, s *sigWriter, r *http.Request, bind []byte) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	for k, v := range s.hdr {
		w.Header()[k] = v
	}
	body := s.buf.Bytes()
	w.Header().Set(hdrProto, proto)
	w.Header().Set(hdrNode, m.d.NodeID())
	w.Header().Set(hdrBind, hex.EncodeToString(bind))
	w.Header().Set(hdrSig, base64.StdEncoding.EncodeToString(ed25519.Sign(m.priv, respMsg(s.code, r.Header.Get(hdrNonce), m.d.NodeID(), bind, body))))
	w.WriteHeader(s.code)
	_, _ = w.Write(body)
}

// nonceFresh merkt sich eine Nonce (false = schon gesehen, Wiederholung). Gemerkt wird so lange, wie eine
// Anfrage wegen ihres Zeitstempels gilt.
func (m *Manager) nonceFresh(n string) bool {
	m.nmu.Lock()
	defer m.nmu.Unlock()
	now := time.Now()
	if m.nonces == nil {
		m.nonces = map[string]time.Time{}
	}
	if len(m.nonces) > 1000 {
		for k, t := range m.nonces {
			if now.Sub(t) > 2*timeSkew {
				delete(m.nonces, k)
			}
		}
	}
	if _, seen := m.nonces[n]; seen {
		return false
	}
	m.nonces[n] = now
	return true
}

// errHTTPS: Anfrage ohne TLS an /peer/* (der Cluster spricht nur HTTPS).
var errHTTPS = errors.New("https required (cluster requests only over https)")

func rejectPlain(w http.ResponseWriter) {
	writeJSON(w, http.StatusUpgradeRequired, map[string]string{"error": errHTTPS.Error()})
}
