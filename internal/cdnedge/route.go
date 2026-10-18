package cdnedge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/tunnel"
)

// Modus 1 (durchreichen): Besucher auf Port 443 (nach SNI) und 80 (nach Host) roh in den Tunnel der Node, der der
// Name gehoert. Ist die Node gerade nicht mit diesem Server verbunden, geht die Verbindung ueber den Nachbarserver
// (Abschnitt 4.3 der Planung). Unbekannte Namen: 443 schliessen, 80 an die eigene Seite (/health, ACME, 404).

// route: ein Name hinter CDN64 online (aus ipv64 oder fest in der Konfiguration).
type route struct {
	Name    string   // wie bei ipv64 eingetragen (Zaehler und Meldung laufen auf diesen Namen)
	Tunnels []string // Tunnels, die ihn bedienen (der erste verbundene gewinnt)
	HostID  int      // cdn64o_hosts.id (0 = feste Testkonfiguration, wird nicht gemeldet)
	UserID  int
	Blocked string // gesetzt = abweisen (z. B. "traffic")
	Mode    int    // 1 = durchreichen, 2 = TLS endet hier (terminate.go), 3 = direkt zum Ziel (direct.go)
	Target  *target
	ACL     *acl
}

// routes: Name -> route (exakt oder *.domain).
type routes struct {
	exact map[string]*route
	wild  map[string]*route // "domain" fuer *.domain
}

func normName(n string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), ".")) }

// newRoutes: feste Eintraege und die Hosts von ipv64 (Wildcard-Domains bekommen *.name dazu, wie im DNS).
func newRoutes(static []HostEntry, api *apiConfig) *routes {
	r := &routes{exact: map[string]*route{}, wild: map[string]*route{}}
	for _, h := range static {
		n, mode := normName(h.Name), max(h.Mode, 1)
		if d, ok := strings.CutPrefix(n, "*."); ok {
			r.wild[d] = &route{Name: n, Tunnels: []string{h.Tunnel}, Mode: mode}
		} else if n != "" {
			r.exact[n] = &route{Name: n, Tunnels: []string{h.Tunnel}, Mode: mode}
		}
	}
	if api != nil {
		for _, h := range api.Hosts {
			n := normName(h.Name)
			if n == "" || h.Mode < 1 || h.Mode > 3 || (h.Mode == 3 && h.Target == nil) {
				continue
			}
			e := &route{Name: n, Tunnels: h.Tunnels, HostID: h.ID, UserID: h.UserID, Blocked: h.Blocked, Mode: h.Mode,
				Target: newTarget(h.Target), ACL: newACL(h.ACL)}
			r.exact[n] = e
			if h.Wildcard {
				r.wild[n] = e
			}
		}
	}
	return r
}

// lookup: route fuer einen Namen (nil = unbekannt).
func (r *routes) lookup(name string) *route {
	name = normName(name)
	if e, ok := r.exact[name]; ok {
		return e
	}
	for s := name; ; { // *.domain gilt wie im DNS auch fuer tiefere Namen (a.b.domain)
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return nil
		}
		s = s[i+1:]
		if e, ok := r.wild[s]; ok {
			return e
		}
	}
}

// hostStat: Zaehler je Name (lokal in /health; ab T3 an ipv64).
type hostStat struct {
	Conns    atomic.Int64
	BytesIn  atomic.Int64 // Besucher -> Node
	BytesOut atomic.Int64 // Node -> Besucher
	ViaPeer  atomic.Int64 // ueber den Nachbarserver
	NoTunnel atomic.Int64 // weder hier noch beim Nachbarn verbunden
	Requests atomic.Int64 // Modus 2: Anfragen
	Rejected atomic.Int64 // Modus 2: abgewiesen (Anfrage-Limit)
}

type stats struct {
	mu sync.Mutex
	m  map[string]*hostStat
}

func (s *stats) of(name string) *hostStat {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.m[name]
	if st == nil {
		st = &hostStat{}
		s.m[name] = st
	}
	return st
}

// acceptLoop nimmt Besucher-Verbindungen an: Schutz zuerst, dann je Verbindung eine Goroutine.
func (s *Server) acceptLoop(ln net.Listener, handle func(c net.Conn)) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		release, why := s.guard.admit(addrOf(c.RemoteAddr()))
		if why != "" {
			_ = c.Close()
			continue
		}
		go func() {
			defer release()
			handle(c)
		}()
	}
}

// handle443: SNI lesen, roh in den Tunnel.
func (s *Server) handle443(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, data, ok := edge.PeekSNI(c)
	_ = c.SetReadDeadline(time.Time{})
	if !ok || sni == "" {
		_ = c.Close()
		return
	}
	if s.tun != nil && s.isPublicName(sni) { // G1: Tunnel der Node ueber Port 443
		s.tun.ServeTCPConn(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	if re := s.routes.Load().lookup(sni); re != nil && re.Mode == 3 { // Modus 3: TLS endet hier (Stufe 1 = nur HTTP)
		if re.Target.frontend <= 1 || !s.certs.has(re.Name) || !re.ACL.allows(addrOf(c.RemoteAddr())) {
			_ = c.Close()
			return
		}
		s.term.tls.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	if re := s.routes.Load().lookup(sni); re != nil && re.Mode == 2 && s.certs.has(re.Name) { // Modus 2: TLS endet hier
		s.term.tls.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	s.forward(c, tunnel.KindTLS, sni, 443, data, c.RemoteAddr().String(), false)
}

// handle80: Kopf der ersten Anfrage lesen; bekannter Name -> Tunnel, sonst die eigene Seite.
func (s *Server) handle80(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, data := peekHTTPHost(c)
	_ = c.SetReadDeadline(time.Time{})
	if s.serveToken(c, data) { // HTTP-01 fuer Modus-2-Zertifikate (auch die des Nachbarn)
		return
	}
	if re := s.routes.Load().lookup(host); host != "" && re != nil {
		if re.Mode == 3 { // Modus 3: je nach Stufe bedienen, umleiten oder abweisen
			pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)}
			switch frontendPlain(re.Target, s.certs.has(re.Name)) {
			case "serve":
				s.term.plain.push(pc)
			case "redirect":
				s.term.http.push(pc)
			case "off": // nur Portmapper
				_ = c.Close()
			default:
				s.term.refuse.push(pc)
			}
			return
		}
		if re.Mode == 2 && s.certs.has(re.Name) { // Modus 2: auf HTTPS umleiten
			s.term.http.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
			return
		}
		s.forward(c, tunnel.KindHTTP80, host, 80, data, c.RemoteAddr().String(), false)
		return
	}
	s.local.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
}

// peekHTTPHost liest bis zum Ende des Kopfes (hoechstens 16 KB) und liefert den Host ohne Port.
func peekHTTPHost(c net.Conn) (string, []byte) {
	var buf []byte
	tmp := make([]byte, 4096)
	for len(buf) < 16<<10 {
		n, err := c.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if i := bytes.Index(buf, []byte("\r\n\r\n")); i >= 0 {
			for _, line := range strings.Split(string(buf[:i]), "\r\n")[1:] {
				if k, v, ok := strings.Cut(line, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "host") {
					h := strings.TrimSpace(v)
					if hh, _, err := net.SplitHostPort(h); err == nil {
						h = hh
					}
					return strings.ToLower(h), buf
				}
			}
			return "", buf
		}
		if err != nil {
			break
		}
	}
	return "", buf
}

// forward: Verbindung in den Tunnel des Namens; ohne Tunnel hier ueber den Nachbarn (nie zurueck, fromPeer).
// Gezaehlt und begrenzt (Bandbreite je Account) wird nur hier, beim Server mit dem Tunnel.
func (s *Server) forward(c net.Conn, kind, host string, port int, data []byte, client string, fromPeer bool) {
	re := s.routes.Load().lookup(host)
	if re == nil {
		_ = c.Close()
		return
	}
	if re.Blocked != "" {
		blockedReply(c, kind)
		return
	}
	if ap, err := netip.ParseAddrPort(client); err == nil && !re.ACL.allows(ap.Addr()) { // Liste (Modus 1: nur nach IP)
		blockedReply(c, kind)
		return
	}
	st := s.stats.of(re.Name)
	p := s.peerFor(re.Tunnels)
	if p == nil {
		if !fromPeer && s.viaPeer(c, kind, host, port, data, client, st) {
			return
		}
		st.NoTunnel.Add(1)
		_ = c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ts, err := s.openPeer(ctx, p, tunnel.Header{Kind: kind, Client: client, Host: host, Port: port})
	cancel()
	if err != nil {
		st.NoTunnel.Add(1)
		_ = c.Close()
		return
	}
	if len(data) > 0 {
		if _, err := ts.Write(data); err != nil {
			_ = ts.Close()
			_ = c.Close()
			return
		}
		st.BytesIn.Add(int64(len(data)))
	}
	st.Conns.Add(1)
	tunnel.Join(&meter{Conn: c, n: &st.BytesIn, bw: s.bw, uid: re.UserID}, &meter{Conn: ts, n: &st.BytesOut, bw: s.bw, uid: re.UserID})
}

// meter zaehlt gelesene Bytes laufend (Meldung jede Minute, auch bei langen Verbindungen) und haelt das
// Bandbreiten-Limit des Accounts ein.
type meter struct {
	net.Conn
	n   *atomic.Int64
	bw  *bandwidth
	uid int
}

func (m *meter) Read(p []byte) (int, error) {
	n, err := m.Conn.Read(p)
	if n > 0 {
		m.n.Add(int64(n))
		m.bw.take(m.uid, n)
	}
	return n, err
}

func (m *meter) CloseWrite() error {
	if cw, ok := m.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return m.Conn.Close()
}

// blockedReply: gesperrter Name (z. B. Traffic aufgebraucht) - Port 80 bekommt eine neutrale 503, 443 wird getrennt.
func blockedReply(c net.Conn, kind string) {
	if kind == tunnel.KindHTTP80 || kind == tunnel.KindHTTP {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, _ = io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 24\r\nConnection: close\r\n\r\n503 service unavailable\n")
	}
	_ = c.Close()
}

// ---------------------------------------------------------------- Nachbarserver

// peerHello: erste Zeile auf dem Nachbar-Port, danach die Daten des Besuchers.
type peerHello struct {
	Secret string `json:"secret"`
	Kind   string `json:"kind"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Client string `json:"client"`
	From   string `json:"from"`
}

// viaPeer reicht die Verbindung an einen Nachbarn, der den Tunnel hat (false = keiner erreichbar).
func (s *Server) viaPeer(c net.Conn, kind, host string, port int, data []byte, client string, st *hostStat) bool {
	pc := s.dialPeer(context.Background(), kind, host, port, client, data)
	if pc == nil {
		return false
	}
	st.ViaPeer.Add(1)
	tunnel.Join(c, pc)
	return true
}

// dialPeer: Verbindung zu einem Nachbarn, der die Daten in seinen Tunnel gibt (nil = keiner erreichbar).
func (s *Server) dialPeer(ctx context.Context, kind, host string, port int, client string, data []byte) net.Conn {
	for _, p := range s.cfg.Peers {
		h, _, _ := net.SplitHostPort(p.Addr)
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: h, RootCAs: s.peerRoots, MinVersion: tls.VersionTLS13}}
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		pc, err := d.DialContext(dctx, "tcp", p.Addr)
		cancel()
		if err != nil {
			s.log.Debug("peer not reachable", "peer", p.Name, "err", err)
			continue
		}
		b, _ := json.Marshal(peerHello{Secret: s.cfg.PeerSecret, Kind: kind, Host: host, Port: port, Client: client, From: s.cfg.Name})
		if _, err := pc.Write(append(append(b, '\n'), data...)); err != nil {
			_ = pc.Close()
			continue
		}
		return pc
	}
	return nil
}

// servePeer: Verbindungen vom Nachbarn annehmen (Geheimnis pruefen) und in den eigenen Tunnel geben.
func (s *Server) servePeer(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go func() {
			_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReaderSize(c, 8<<10)
			line, err := br.ReadSlice('\n')
			var h peerHello
			if err != nil || json.Unmarshal(line, &h) != nil ||
				subtle.ConstantTimeCompare([]byte(h.Secret), []byte(s.cfg.PeerSecret)) != 1 {
				_ = c.Close()
				return
			}
			_ = c.SetReadDeadline(time.Time{})
			if h.Kind == "acme" { // HTTP-01-Token des Nachbarn
				if h.Host != "" && h.Client != "" {
					s.acmeTokens.set(h.Host, h.Client)
				}
				_ = c.Close()
				return
			}
			if h.Kind == "rates" { // Bandbreite: Raten des Nachbarn
				s.readRates(br)
				_ = c.Close()
				return
			}
			rest, _ := br.Peek(br.Buffered())
			pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(append([]byte(nil), rest...)), c)}
			s.forward(pc, h.Kind, h.Host, h.Port, nil, h.Client, true)
		}()
	}
}

// ---------------------------------------------------------------- Hilfen

// prefixConn liest zuerst die schon gelesenen Bytes.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *prefixConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// chanListener: Verbindungen an den eigenen http.Server (Port 80 ohne bekannten Namen).
type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error   { l.once.Do(func() { close(l.done) }); return nil }
func (l *chanListener) Addr() net.Addr { return l.addr }

func (l *chanListener) push(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}
