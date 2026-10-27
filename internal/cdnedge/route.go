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
	"net/http"
	"net/netip"
	"slices"
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
	WAF     bool   // Muster-WAF (Modus 2/3, waf.go)
	JA4     string // ja4Off | ja4Count | ja4Block (ja4.go)
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
			r.wild[d] = &route{Name: n, Tunnels: []string{h.Tunnel}, Mode: mode, WAF: true, JA4: ja4Count}
		} else if n != "" {
			r.exact[n] = &route{Name: n, Tunnels: []string{h.Tunnel}, Mode: mode, WAF: true, JA4: ja4Count}
		}
	}
	if api != nil {
		for _, h := range api.Hosts {
			n := normName(h.Name)
			if n == "" || h.Mode < 1 || h.Mode > 3 || (h.Mode == 3 && h.Target == nil) {
				continue
			}
			e := &route{Name: n, Tunnels: h.Tunnels, HostID: h.ID, UserID: h.UserID, Blocked: h.Blocked, Mode: h.Mode,
				Target: newTarget(h.Target), ACL: newACL(h.ACL), WAF: h.WAF == nil || *h.WAF, JA4: ja4Mode(h.JA4)}
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
	// Schutz (cdn64-edge 0.19.0, an ipv64 als Differenzen)
	BlockedList  atomic.Int64            // Blocklisten (vor TLS; Name aus SNI bzw. Host-Kopf)
	BlockedACL   atomic.Int64            // Zugriffsliste
	BlockedFlood atomic.Int64            // Ueberlast: Verbindungen je IP, Verbindungsrate, Verbindungen insgesamt
	BlockedWAF   atomic.Int64            // WAF-Muster (Modus 2/3)
	BlockedJA4   atomic.Int64            // JA4 auf der Liste, gesperrt
	JA4Hits      atomic.Int64            // JA4 auf der Liste (gesperrt oder nur gezaehlt)
	ConnsV4      atomic.Int64            // davon Verbindungen von IPv4-Besuchern
	mu           sync.Mutex              // ips, ja4: nur bei Abweisungen und JA4-Treffern
	ips          map[netip.Addr]struct{} // gesperrte IPs (IPv6 je /64) seit der letzten Meldung, hoechstens hsMaxIPs
	ja4          map[string]int64        // JA4-Treffer seit der letzten Meldung, hoechstens hsMaxJA4 verschiedene
}

const (
	hsMaxIPs = 1000 // verschiedene gesperrte IPs je Name und Meldeintervall
	hsMaxJA4 = 64   // verschiedene JA4 je Name und Meldeintervall (gemeldet werden die ja4TopMax haeufigsten)
)

// Gruende fuer hostStat.block.
const (
	bList  = iota
	bACL   // Zugriffsliste
	bFlood // Ueberlast vor TLS
	bWAF
	bJA4
	bLimit // Anfrage-Limit (Rejected)
)

// conn zaehlt eine Verbindung des Besuchers ip (IPv4 auch als ::ffff:).
func (st *hostStat) conn(ip netip.Addr) {
	st.Conns.Add(1)
	if ip.Unmap().Is4() {
		st.ConnsV4.Add(1)
	}
}

// block zaehlt eine Abweisung und merkt die IP (Anzahl verschiedener IPs je Meldung). st = nil: Name unbekannt.
func (st *hostStat) block(why int, ip netip.Addr) {
	if st == nil {
		return
	}
	switch why {
	case bList:
		st.BlockedList.Add(1)
	case bACL:
		st.BlockedACL.Add(1)
	case bFlood:
		st.BlockedFlood.Add(1)
	case bWAF:
		st.BlockedWAF.Add(1)
	case bJA4:
		st.BlockedJA4.Add(1)
	case bLimit:
		st.Rejected.Add(1)
	}
	if !ip.IsValid() {
		return
	}
	k := gkey(ip)
	st.mu.Lock()
	if st.ips == nil {
		st.ips = map[netip.Addr]struct{}{}
	}
	if len(st.ips) < hsMaxIPs {
		st.ips[k] = struct{}{}
	}
	st.mu.Unlock()
}

// ja4Hit zaehlt einen Treffer der JA4-Liste.
func (st *hostStat) ja4Hit(j string) {
	st.JA4Hits.Add(1)
	st.mu.Lock()
	if st.ja4 == nil {
		st.ja4 = map[string]int64{}
	}
	if _, ok := st.ja4[j]; ok || len(st.ja4) < hsMaxJA4 {
		st.ja4[j]++
	}
	st.mu.Unlock()
}

// takeSets holt IPs und JA4-Treffer seit der letzten Meldung (danach leer).
func (st *hostStat) takeSets() (map[netip.Addr]struct{}, map[string]int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	ips, ja4 := st.ips, st.ja4
	st.ips, st.ja4 = nil, nil
	return ips, ja4
}

// putSets legt nicht gemeldete IPs und JA4-Treffer zurueck (Meldung gescheitert).
func (st *hostStat) putSets(ips map[netip.Addr]struct{}, ja4 map[string]int64) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(ips) > 0 && st.ips == nil {
		st.ips = map[netip.Addr]struct{}{}
	}
	for k := range ips {
		if len(st.ips) < hsMaxIPs {
			st.ips[k] = struct{}{}
		}
	}
	if len(ja4) > 0 && st.ja4 == nil {
		st.ja4 = map[string]int64{}
	}
	for k, v := range ja4 {
		if _, ok := st.ja4[k]; ok || len(st.ja4) < hsMaxJA4 {
			st.ja4[k] += v
		}
	}
}

// repN: Zahl der Zaehler in der Meldung (counters, apiState.sent).
const repN = 12

// counters: Stand fuer die Meldung - in, out, conns, requests, rejected, blocked_list, blocked_acl, blocked_flood,
// blocked_waf, blocked_ja4, ja4_hits, conns_v4.
func (st *hostStat) counters() [repN]int64 {
	return [repN]int64{st.BytesIn.Load(), st.BytesOut.Load(), st.Conns.Load(), st.Requests.Load(), st.Rejected.Load(),
		st.BlockedList.Load(), st.BlockedACL.Load(), st.BlockedFlood.Load(), st.BlockedWAF.Load(), st.BlockedJA4.Load(),
		st.JA4Hits.Load(), st.ConnsV4.Load()}
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

// acceptLoop nimmt Besucher-Verbindungen an: Schutz zuerst, dann je Verbindung eine Goroutine. handle bekommt den
// Zustand der IP im Schutz (gs.mark: angefragter Name, dort zaehlt spaetere Ueberlast). peek liefert bei einem
// Blocklisten-Treffer den angefragten Namen (Zaehler je Name); nil = nur die Gesamtzahl.
func (s *Server) acceptLoop(ln net.Listener, handle func(c net.Conn, gs *gstate), peek func(c net.Conn) string) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		a := addrOf(c.RemoteAddr())
		release, gs, why := s.guard.admitG(a, nil)
		if why != "" {
			if why == "blocklist" && peek != nil {
				s.blockedPeek(c, a, peek)
				continue
			}
			_ = c.Close()
			continue
		}
		go func() {
			defer release()
			handle(c, gs)
		}()
	}
}

// peekMax: so viele Blocklisten-Treffer lesen gleichzeitig ihren Namen; darueber nur die Gesamtzahl.
const peekMax = 256

// blockedPeek: Blocklisten-Treffer - vor dem Schliessen noch den Namen lesen (hoechstens 1 s und 4 KB) und beim Namen
// zaehlen.
func (s *Server) blockedPeek(c net.Conn, a netip.Addr, peek func(c net.Conn) string) {
	if s.peeking.Add(1) > peekMax {
		s.peeking.Add(-1)
		_ = c.Close()
		return
	}
	go func() {
		defer s.peeking.Add(-1)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		name := peek(&capConn{Conn: c, n: 4 << 10})
		_ = c.Close()
		if re := s.routes.Load().lookup(name); name != "" && re != nil {
			s.stats.of(re.Name).block(bList, a)
		}
	}()
}

func peek443(c net.Conn) string { sni, _, _, _ := edge.PeekHello(c); return sni }

func peek80(c net.Conn) string { h, _ := peekHTTPHost(c); return h }

// capConn liest hoechstens n Bytes (danach io.EOF).
type capConn struct {
	net.Conn
	n int
}

func (c *capConn) Read(p []byte) (int, error) {
	if c.n <= 0 {
		return 0, io.EOF
	}
	if len(p) > c.n {
		p = p[:c.n]
	}
	n, err := c.Conn.Read(p)
	c.n -= n
	return n, err
}

// handle443: SNI lesen (und JA4 pruefen), roh in den Tunnel.
func (s *Server) handle443(c net.Conn, gs *gstate) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	sni, alpn, data, ok := edge.PeekHello(c)
	_ = c.SetReadDeadline(time.Time{})
	if !ok || sni == "" {
		_ = c.Close()
		return
	}
	if s.tun != nil && s.isPublicName(sni) { // G1: Tunnel der Node ueber Port 443; ein Browser bekommt die Infoseite
		if s.own != nil && !slices.Contains(alpn, tunnel.ALPN) {
			s.own.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
			return
		}
		s.tun.ServeTCPConn(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	re := s.routes.Load().lookup(sni)
	var st *hostStat
	if re != nil {
		st = s.stats.of(re.Name)
		gs.mark(st)
		if s.ja4Check(re, st, data, addrOf(c.RemoteAddr())) { // alle Modi: bekanntes Angriffs-Werkzeug
			_ = c.Close()
			return
		}
	}
	if re != nil && re.Mode == 3 { // Modus 3: TLS endet hier (Stufe 1 = nur HTTP)
		if re.Target.frontend <= 1 || !s.certs.has(re.Name) {
			_ = c.Close()
			return
		}
		if ip := addrOf(c.RemoteAddr()); !re.ACL.allows(ip) {
			st.block(bACL, ip)
			_ = c.Close()
			return
		}
		s.term.tls.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	if re != nil && re.Mode == 2 && s.certs.has(re.Name) { // Modus 2: TLS endet hier
		s.term.tls.push(&prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(data), c)})
		return
	}
	s.forward(c, tunnel.KindTLS, sni, 443, data, c.RemoteAddr().String(), false)
}

// handle80: Kopf der ersten Anfrage lesen; bekannter Name -> Tunnel, sonst die eigene Seite.
func (s *Server) handle80(c net.Conn, gs *gstate) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, data := peekHTTPHost(c)
	_ = c.SetReadDeadline(time.Time{})
	if s.serveToken(c, data) { // HTTP-01 fuer Modus-2-Zertifikate (auch die des Nachbarn)
		return
	}
	if re := s.routes.Load().lookup(host); host != "" && re != nil {
		gs.mark(s.stats.of(re.Name))
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
		blockedReply(c, kind, host, data)
		return
	}
	var ip netip.Addr
	if ap, err := netip.ParseAddrPort(client); err == nil {
		ip = ap.Addr()
	}
	st := s.stats.of(re.Name)
	if ip.IsValid() && !re.ACL.allows(ip) { // Liste (Modus 1: nur nach IP)
		st.block(bACL, ip)
		blockedReply(c, kind, host, data)
		return
	}
	p := s.peerFor(re.Tunnels)
	if p == nil {
		if !fromPeer && s.viaPeer(c, kind, host, port, data, client, st) {
			return
		}
		st.NoTunnel.Add(1)
		if !fromPeer {
			unreachableReply(c, kind, host, data)
		}
		_ = c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ts, err := s.openPeer(ctx, p, tunnel.Header{Kind: kind, Client: client, Host: host, Port: port})
	cancel()
	if err != nil {
		st.NoTunnel.Add(1)
		if !fromPeer {
			unreachableReply(c, kind, host, data)
		}
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
	st.conn(ip)
	defer s.track(re.Name, re.Mode, ip, func() { _ = c.Close(); _ = ts.Close() })()
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

// blockedReply: gesperrter Name (z. B. Traffic aufgebraucht) bzw. nicht auf der Liste - Port 80 bekommt die
// Fehlerseite (503), 443 wird getrennt.
func blockedReply(c net.Conn, kind, host string, data []byte) {
	if kind == tunnel.KindHTTP80 || kind == tunnel.KindHTTP {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		rawPage(c, data, http.StatusServiceUnavailable, host, "Dieser Dienst ist vorübergehend nicht verfügbar.", "This service is temporarily unavailable.")
	}
	_ = c.Close()
}

// unreachableReply: Node nicht verbunden - Port 80 bekommt die Fehlerseite (502), 443 (TLS beim Kunden) nichts.
func unreachableReply(c net.Conn, kind, host string, data []byte) {
	if kind == tunnel.KindHTTP80 || kind == tunnel.KindHTTP {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		rawPage(c, data, http.StatusBadGateway, host, "Der Server hinter dieser Adresse ist gerade nicht erreichbar. Bitte später noch einmal versuchen.",
			"The server behind this address is not reachable right now. Please try again later.")
	}
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
