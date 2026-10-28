package cdnedge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Portmapper (T8): ein Port der Server (Bereich port_range, Standard 50000-62000) geht roh per TCP bzw. UDP an einen
// Port des Ziels - wie der Portmapper des alten CDN. Modus 3: direkt zum Ziel des Namens (SSRF-Schutz wie bei HTTP).
// Modus 1/2: durch den Tunnel der Node (Stream tcp bzw. udp, Port = Ziel-Port = Port eines Streams in der Node), ohne
// Tunnel hier ueber den Nachbarserver; die Node braucht die Faehigkeit "ports". Beide Server oeffnen dieselben Ports
// (der Name zeigt im DNS auf beide). Sperre (auch Pause) und Liste kommen bei jeder Verbindung aus dem aktuellen Stand
// des Namens. Gezaehlt wird auf den Namen (Traffic, Verbindungen).

// apiMapping: ein Eintrag von ipv64.
type apiMapping struct {
	Listen    int    `json:"listen_port"`
	Transport string `json:"transport"` // tcp | udp
	Port      int    `json:"target_port"`
}

type pmKey struct {
	udp  bool
	port int
}

// pmEntry: wohin ein Port gerade geht.
type pmEntry struct {
	name string // Name des Modus-3-Hosts (route)
	port int    // Port am Ziel
}

const (
	udpIdle        = 2 * time.Minute // ruhige UDP-Sitzung schliessen
	udpMaxSessions = 4096            // je Port
	udpQueue       = 8               // Datagramme, die warten, bis die Verbindung zum Ziel steht
	udpNewPerSec   = 200             // neue Sitzungen je Port und Sekunde (gefaelschte Absender)
	udpFree        = 32 << 10        // so viele Bytes darf das Ziel einem Besucher immer schicken ...
	udpAmp         = 10              // ... danach hoechstens das Zehnfache dessen, was vom Besucher kam
	tcpIdle        = time.Hour       // TCP ohne Daten in beide Richtungen: trennen (ruhende Verbindungen binden nichts)
)

type portmapper struct {
	s      *Server
	lo, hi int // erlaubter Bereich; lo = 0: aus
	want   atomic.Pointer[map[pmKey]pmEntry]
	mu     sync.Mutex
	tcp    map[int]net.Listener
	udp    map[int]*udpPort
	failed map[pmKey]bool // Port belegt: einmal melden
	closed bool
	idle   time.Duration // TCP-Leerlauf bis zum Trennen (Tests kuerzer)
}

func newPortmapper(s *Server, rng string) *portmapper {
	p := &portmapper{s: s, tcp: map[int]net.Listener{}, udp: map[int]*udpPort{}, failed: map[pmKey]bool{}, idle: tcpIdle}
	p.lo, p.hi = parsePortRange(rng)
	m := map[pmKey]pmEntry{}
	p.want.Store(&m)
	return p
}

// parsePortRange: "50000-62000" (Standard bei leer), "off" = aus.
func parsePortRange(r string) (int, int) {
	r = strings.TrimSpace(r)
	if r == "" {
		return 50000, 62000
	}
	a, b, ok := strings.Cut(r, "-")
	lo, err1 := strconv.Atoi(strings.TrimSpace(a))
	hi, err2 := strconv.Atoi(strings.TrimSpace(b))
	if !ok || err1 != nil || err2 != nil || lo < 1024 || hi > 65535 || lo > hi {
		return 0, 0
	}
	return lo, hi
}

// apply: Soll-Stand aus der Konfiguration; Ports oeffnen bzw. schliessen.
func (p *portmapper) apply(c *apiConfig) {
	m := map[pmKey]pmEntry{}
	if p.lo > 0 && c != nil {
		for _, h := range c.Hosts {
			if h.Mode == 3 && h.Target == nil || h.Mode != 3 && len(h.Tunnels) == 0 {
				continue
			}
			for _, x := range h.Mappings {
				k := pmKey{udp: x.Transport == "udp", port: x.Listen}
				if x.Listen < p.lo || x.Listen > p.hi || x.Port < 1 || x.Port > 65535 || (x.Transport != "tcp" && x.Transport != "udp") {
					continue
				}
				if _, dup := m[k]; !dup {
					m[k] = pmEntry{name: normName(h.Name), port: x.Port}
				}
			}
		}
	}
	p.want.Store(&m)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	for port, ln := range p.tcp {
		if _, ok := m[pmKey{port: port}]; !ok {
			_ = ln.Close()
			delete(p.tcp, port)
		}
	}
	for port, u := range p.udp {
		if _, ok := m[pmKey{udp: true, port: port}]; !ok {
			u.close()
			delete(p.udp, port)
		}
	}
	for k := range m {
		if k.udp {
			if p.udp[k.port] != nil {
				continue
			}
			pc, err := net.ListenPacket("udp", ":"+strconv.Itoa(k.port))
			if err != nil {
				p.fail(k, err)
				continue
			}
			u := &udpPort{p: p, port: k.port, pc: pc.(*net.UDPConn), done: make(chan struct{}), sess: map[netip.AddrPort]*udpSess{}}
			p.udp[k.port] = u
			go u.serve()
		} else {
			if p.tcp[k.port] != nil {
				continue
			}
			ln, err := net.Listen("tcp", ":"+strconv.Itoa(k.port))
			if err != nil {
				p.fail(k, err)
				continue
			}
			p.tcp[k.port] = ln
			port := k.port
			go p.s.acceptLoop(ln, func(c net.Conn, gs *gstate) { p.serveTCP(port, c, gs) }, func(net.Conn) string { return p.portName(port) })
		}
		delete(p.failed, k)
	}
}

func (p *portmapper) fail(k pmKey, err error) {
	if !p.failed[k] {
		p.failed[k] = true
		p.s.log.Warn("portmapper: port not opened", "port", k.port, "udp", k.udp, "err", err)
	}
}

// close: alle Ports zu (Ende des Dienstes).
func (p *portmapper) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for _, ln := range p.tcp {
		_ = ln.Close()
	}
	for _, u := range p.udp {
		u.close()
	}
}

// udpSessions: offene UDP-Sitzungen aller Ports (Prometheus).
func (p *portmapper) udpSessions() int {
	p.mu.Lock()
	ports := make([]*udpPort, 0, len(p.udp))
	for _, u := range p.udp {
		ports = append(ports, u)
	}
	p.mu.Unlock()
	n := 0
	for _, u := range ports {
		u.mu.Lock()
		n += len(u.sess)
		u.mu.Unlock()
	}
	return n
}

// open: Anzahl offener Ports (fuer /health).
func (p *portmapper) open() (tcp, udp int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.tcp), len(p.udp)
}

// resolve: aktueller Name und Ziel-Port eines Ports; nil = nicht (mehr) bedient oder gesperrt. acl: Name, dessen Liste
// den Besucher abweist (fuer die Zaehler).
func (p *portmapper) resolve(k pmKey, client netip.Addr) (*route, int, *route) {
	e, ok := (*p.want.Load())[k]
	if !ok {
		return nil, 0, nil
	}
	re := p.s.routes.Load().lookup(e.name)
	if re == nil || re.Mode == 3 && re.Target == nil || re.Blocked != "" {
		return nil, 0, nil
	}
	if !re.ACL.allows(client) {
		return nil, 0, re
	}
	return re, e.port, nil
}

// portName: Name eines TCP-Ports (Blocklisten-Treffer, ohne zu lesen).
func (p *portmapper) portName(port int) string {
	return (*p.want.Load())[pmKey{port: port}].name
}

var errNoPortTunnel = errors.New("portmapper: node not connected or without port mappings")

// upstream: Verbindung fuer einen Besucher - Modus 3 direkt zum Ziel, Modus 1/2 durch den Tunnel der Node bzw. ueber
// den Nachbarn (UDP dann als Datagramme mit Laenge). counted = false: der Nachbar zaehlt und begrenzt.
func (p *portmapper) upstream(ctx context.Context, network string, re *route, port int, client string) (net.Conn, bool, error) {
	if re.Mode == 3 {
		c, err := p.dial(ctx, network, re, port)
		return c, true, err
	}
	kind := tunnel.KindTCP
	if network == "udp" {
		kind = tunnel.KindUDP
	}
	var c net.Conn
	counted := true
	if pe := p.s.peerFor(re.Tunnels); pe != nil {
		if !tunnel.HasCap(pe.Caps, tunnel.CapPorts) {
			return nil, false, errNoPortTunnel
		}
		ts, err := p.s.openPeer(ctx, pe, tunnel.Header{Kind: kind, Client: client, Host: re.Name, Port: port})
		if err != nil {
			return nil, false, err
		}
		c = ts
	} else if pc := p.s.dialPeer(ctx, kind, re.Name, port, client, nil); pc != nil {
		c, counted = pc, false
		p.s.stats.of(re.Name).ViaPeer.Add(1)
	} else {
		return nil, false, errNoPortTunnel
	}
	if network == "udp" {
		c = &dgramConn{Conn: c}
	}
	return c, counted, nil
}

// dgramConn: UDP ueber einen Stream (tunnel.WriteDatagram/ReadDatagram); jeder Fehler beim Lesen beendet die
// Sitzung (net.ErrClosed).
type dgramConn struct {
	net.Conn
	wmu sync.Mutex
}

func (d *dgramConn) Read(b []byte) (int, error) {
	n, err := tunnel.ReadDatagram(d.Conn, b)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", net.ErrClosed, err)
	}
	return n, nil
}

func (d *dgramConn) Write(b []byte) (int, error) {
	d.wmu.Lock()
	defer d.wmu.Unlock()
	if err := tunnel.WriteDatagram(d.Conn, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// targetGen: Stand des Ziels (Modus 3, DynDNS); Modus 1/2 hat keins.
func targetGen(re *route) string {
	if re.Target == nil {
		return ""
	}
	return re.Target.gen
}

// dial: Verbindung zum Ziel (wie directDial: oeffentliche Adressen, nach dem Verbinden noch einmal geprueft).
// UDP merkt keinen Fehlschlag (nimmt die erste Adresse): dort immer IPv6 zuerst - eine A-Adresse, ueber die der
// Anschluss nicht erreichbar ist (z. B. die geteilte IPv4 bei DS-Lite), soll nie gewinnen.
func (p *portmapper) dial(ctx context.Context, network string, re *route, port int) (net.Conn, error) {
	addrs, err := p.s.targetAddrs(ctx, re.Target)
	if err != nil {
		return nil, err
	}
	if network == "udp" {
		sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].Is6() && !addrs[j].Is6() })
	}
	var last error
	for _, a := range addrs {
		d := net.Dialer{Timeout: 5 * time.Second}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), strconv.Itoa(port)))
		if err != nil {
			last = err
			continue
		}
		if !p.s.publicTarget(addrOf(c.RemoteAddr())) {
			_ = c.Close()
			last = errBadTarget
			continue
		}
		return c, nil
	}
	return nil, last
}

// ---------------------------------------------------------------- TCP

func (p *portmapper) serveTCP(port int, c net.Conn, gs *gstate) {
	re, tport, denied := p.resolve(pmKey{port: port}, addrOf(c.RemoteAddr()))
	if re == nil {
		if denied != nil {
			p.s.stats.of(denied.Name).block(bACL, addrOf(c.RemoteAddr()))
		}
		_ = c.Close()
		return
	}
	st := p.s.stats.of(re.Name)
	gs.mark(st)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	up, counted, err := p.upstream(ctx, "tcp", re, tport, clientOf(c.RemoteAddr()))
	cancel()
	if err != nil {
		st.NoTunnel.Add(1)
		_ = c.Close()
		return
	}
	defer p.s.track(re.Name, re.Mode, addrOf(c.RemoteAddr()), func() { _ = c.Close(); _ = up.Close() })()
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	defer p.idleWatch(&last, func() { _ = c.Close(); _ = up.Close() })()
	var vc, uc net.Conn = &activeConn{Conn: c, last: &last}, &activeConn{Conn: up, last: &last}
	if !counted {
		tunnel.Join(vc, uc)
		return
	}
	st.conn(addrOf(c.RemoteAddr()))
	tunnel.Join(&meter{Conn: vc, n: &st.BytesIn, bw: p.s.bw, uid: re.UserID}, &meter{Conn: uc, n: &st.BytesOut, bw: p.s.bw, uid: re.UserID})
}

// idleWatch trennt eine TCP-Verbindung nach p.idle ohne Daten (Rueckgabe: beenden).
func (p *portmapper) idleWatch(last *atomic.Int64, cut func()) func() {
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(max(p.idle/12, 10*time.Millisecond))
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > p.idle {
					cut()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}

// activeConn merkt sich, wann zuletzt Daten kamen (Leerlauf).
type activeConn struct {
	net.Conn
	last *atomic.Int64
}

func (c *activeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.last.Store(time.Now().UnixNano())
	}
	return n, err
}

func (c *activeConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

// clientOf: Besucher-Adresse ip:port (IPv4 ohne ::ffff:) fuer den Kopf im Tunnel.
func clientOf(a net.Addr) string {
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return a.String()
}

// ---------------------------------------------------------------- UDP

// udpPort: ein UDP-Port; je Besucher (Adresse:Port) eine Sitzung mit eigenem Socket zum Ziel. Die Lese-Schleife
// wartet nie: die Verbindung zum Ziel entsteht im Hintergrund (Datagramme bis dahin in einer kleinen Warteschlange).
// Schutz vor Reflexion mit gefaelschten Absendern: neue Sitzungen je Port begrenzt, und das Ziel darf einem Besucher
// nach udpFree Bytes hoechstens udpAmp-mal so viel schicken, wie von ihm kam.
type udpPort struct {
	p       *portmapper
	port    int
	pc      *net.UDPConn
	done    chan struct{}
	mu      sync.Mutex
	sess    map[netip.AddrPort]*udpSess
	newTok  float64 // Kontingent neuer Sitzungen
	newLast time.Time
	aclLast netip.AddrPort // zuletzt nach der Liste abgewiesener Absender (je Absender einmal zaehlen, nicht je Datagramm)
}

type udpSess struct {
	mu      sync.Mutex
	up      net.Conn // nil, solange die Verbindung zum Ziel entsteht
	queue   [][]byte
	dead    bool
	gen     string // Stand des Ziels: aendert er sich (DynDNS), neue Sitzung
	tport   int
	st      *hostStat
	uid     int
	free    bool         // ueber den Nachbarn: der zaehlt und begrenzt
	last    atomic.Int64 // Unix-Nanosekunden der letzten Aktivitaet
	in, out atomic.Int64 // Bytes vom bzw. zum Besucher
	release func()
	untrack func()
	once    sync.Once
}

func (u *udpPort) close() {
	close(u.done)
	_ = u.pc.Close()
	u.mu.Lock()
	all := make([]*udpSess, 0, len(u.sess))
	for k, s := range u.sess {
		all = append(all, s)
		delete(u.sess, k)
	}
	u.mu.Unlock()
	for _, s := range all {
		s.end()
	}
}

func (s *udpSess) end() {
	s.once.Do(func() {
		s.mu.Lock()
		s.dead = true
		up := s.up
		s.queue = nil
		s.mu.Unlock()
		if up != nil {
			_ = up.Close()
		}
		if s.release != nil {
			s.release()
		}
		if s.untrack != nil {
			s.untrack()
		}
	})
}

// drop nimmt eine Sitzung heraus und beendet sie.
func (u *udpPort) drop(from netip.AddrPort, s *udpSess) {
	u.mu.Lock()
	if u.sess[from] == s {
		delete(u.sess, from)
	}
	u.mu.Unlock()
	s.end()
}

func (u *udpPort) serve() {
	buf := make([]byte, 64<<10)
	go u.sweep()
	for {
		n, from, err := u.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		s := u.session(from)
		if s == nil {
			continue
		}
		s.last.Store(time.Now().UnixNano())
		s.mu.Lock()
		up := s.up
		if up == nil && !s.dead && len(s.queue) < udpQueue {
			s.queue = append(s.queue, append([]byte(nil), buf[:n]...))
		}
		s.mu.Unlock()
		if up == nil {
			continue
		}
		if _, err := up.Write(buf[:n]); err == nil {
			s.countIn(u, n)
		}
	}
}

func (s *udpSess) countIn(u *udpPort, n int) {
	s.in.Add(int64(n))
	if !s.free {
		s.st.BytesIn.Add(int64(n))
		u.p.s.bw.take(s.uid, n)
	}
}

// newOK: Kontingent fuer eine neue Sitzung auf diesem Port (u.mu gehalten).
func (u *udpPort) newOK(now time.Time) bool {
	if u.newLast.IsZero() {
		u.newTok, u.newLast = udpNewPerSec, now
	}
	u.newTok = min(udpNewPerSec, u.newTok+now.Sub(u.newLast).Seconds()*udpNewPerSec)
	u.newLast = now
	if u.newTok < 1 {
		return false
	}
	u.newTok--
	return true
}

// session: bestehende Sitzung (solange Ziel und Name unveraendert) oder eine neue (Verbindung zum Ziel entsteht im
// Hintergrund); nil = verwerfen.
func (u *udpPort) session(from netip.AddrPort) *udpSess {
	re, tport, denied := u.p.resolve(pmKey{udp: true, port: u.port}, from.Addr())
	u.mu.Lock()
	s := u.sess[from]
	if s != nil && (re == nil || s.gen != targetGen(re) || s.tport != tport) {
		delete(u.sess, from)
		u.mu.Unlock()
		s.end()
		u.mu.Lock()
		s = nil
	}
	if s != nil || re == nil {
		count := s == nil && denied != nil && from != u.aclLast
		if count {
			u.aclLast = from
		}
		u.mu.Unlock()
		if count {
			u.p.s.stats.of(denied.Name).block(bACL, from.Addr())
		}
		return s
	}
	if len(u.sess) >= udpMaxSessions || !u.newOK(time.Now()) {
		u.mu.Unlock()
		return nil
	}
	u.mu.Unlock()
	st := u.p.s.stats.of(re.Name)
	// UDP-Absender koennen gefaelscht sein: Sperrliste und eigenes UDP-Budget, nicht die Grenzen der Verbindungen
	release, why := u.p.s.guard.admitUDP(from.Addr(), st)
	if why != "" {
		return nil
	}
	s = &udpSess{gen: targetGen(re), tport: tport, st: st, uid: re.UserID, release: release}
	s.last.Store(time.Now().UnixNano())
	u.mu.Lock()
	if old := u.sess[from]; old != nil { // gleichzeitig angelegt: die vorhandene nehmen
		u.mu.Unlock()
		release()
		return old
	}
	u.sess[from] = s
	u.mu.Unlock()
	s.untrack = u.p.s.track(re.Name, re.Mode, from.Addr(), func() { u.drop(from, s) })
	go u.connect(from, s, re, tport)
	return s
}

// connect baut die Verbindung zum Ziel auf, schickt die wartenden Datagramme und reicht dann die Antworten zurueck.
func (u *udpPort) connect(from netip.AddrPort, s *udpSess, re *route, tport int) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	up, counted, err := u.p.upstream(ctx, "udp", re, tport, from.String())
	cancel()
	if err != nil {
		s.st.NoTunnel.Add(1)
		u.drop(from, s)
		return
	}
	s.mu.Lock()
	if s.dead {
		s.mu.Unlock()
		_ = up.Close()
		return
	}
	q := s.queue
	s.up, s.queue, s.free = up, nil, !counted
	s.mu.Unlock()
	if counted {
		s.st.conn(from.Addr())
	}
	for _, p := range q {
		if _, err := up.Write(p); err == nil {
			s.countIn(u, len(p))
		}
	}
	u.back(from, s, up)
}

// back: Antworten des Ziels an den Besucher (hoechstens udpFree + udpAmp x Eingang).
func (u *udpPort) back(to netip.AddrPort, s *udpSess, up net.Conn) {
	buf := make([]byte, 64<<10)
	for {
		n, err := up.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				break
			}
			time.Sleep(10 * time.Millisecond) // z. B. ICMP "Port unreachable": Sitzung bleibt, bis sie ruhig wird
			continue
		}
		s.last.Store(time.Now().UnixNano())
		if s.out.Load()+int64(n) > udpFree+udpAmp*s.in.Load() {
			continue // mehr Antwort als Anfrage: gefaelschter Absender, verwerfen
		}
		if _, err := u.pc.WriteToUDPAddrPort(buf[:n], to); err == nil {
			s.out.Add(int64(n))
			if !s.free {
				s.st.BytesOut.Add(int64(n))
				u.p.s.bw.take(s.uid, n)
			}
		}
	}
	u.drop(to, s)
}

// sweep schliesst ruhige Sitzungen.
func (u *udpPort) sweep() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-u.done:
			return
		case <-t.C:
		}
		cut := time.Now().Add(-udpIdle).UnixNano()
		var idle []*udpSess
		u.mu.Lock()
		for k, s := range u.sess {
			if s.last.Load() < cut {
				delete(u.sess, k)
				idle = append(idle, s)
			}
		}
		u.mu.Unlock()
		for _, s := range idle {
			s.end()
		}
	}
}
