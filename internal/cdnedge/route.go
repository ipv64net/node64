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

// routes: Name -> Tunnel (exakt oder *.domain).
type routes struct {
	exact map[string]string
	wild  map[string]string // "domain" fuer *.domain
}

func newRoutes(list []HostEntry) *routes {
	r := &routes{exact: map[string]string{}, wild: map[string]string{}}
	for _, h := range list {
		n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h.Name), "."))
		if d, ok := strings.CutPrefix(n, "*."); ok {
			r.wild[d] = h.Tunnel
		} else if n != "" {
			r.exact[n] = h.Tunnel
		}
	}
	return r
}

// lookup: Tunnel fuer einen Namen ("" = unbekannt).
func (r *routes) lookup(name string) string {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if t, ok := r.exact[name]; ok {
		return t
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		return r.wild[name[i+1:]]
	}
	return ""
}

// hostStat: Zaehler je Name (lokal in /health; ab T3 an ipv64).
type hostStat struct {
	Conns    atomic.Int64
	BytesIn  atomic.Int64 // Besucher -> Node
	BytesOut atomic.Int64 // Node -> Besucher
	ViaPeer  atomic.Int64 // ueber den Nachbarserver
	NoTunnel atomic.Int64 // weder hier noch beim Nachbarn verbunden
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
	s.forward(c, tunnel.KindTLS, sni, 443, data, c.RemoteAddr().String(), false)
}

// handle80: Kopf der ersten Anfrage lesen; bekannter Name -> Tunnel, sonst die eigene Seite.
func (s *Server) handle80(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	host, data := peekHTTPHost(c)
	_ = c.SetReadDeadline(time.Time{})
	if host != "" && s.routes.Load().lookup(host) != "" {
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
func (s *Server) forward(c net.Conn, kind, host string, port int, data []byte, client string, fromPeer bool) {
	tid := s.routes.Load().lookup(host)
	if tid == "" {
		_ = c.Close()
		return
	}
	st := s.stats.of(host)
	if s.peer(tid) == nil {
		if !fromPeer && s.viaPeer(c, kind, host, port, data, client, st) {
			return
		}
		st.NoTunnel.Add(1)
		_ = c.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	ts, err := s.open(ctx, tid, tunnel.Header{Kind: kind, Client: client, Host: host, Port: port})
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
	}
	st.Conns.Add(1)
	in, out := tunnel.Join(c, ts)
	st.BytesIn.Add(in + int64(len(data)))
	st.BytesOut.Add(out)
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
	for _, p := range s.cfg.Peers {
		h, _, _ := net.SplitHostPort(p.Addr)
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: h, RootCAs: s.peerRoots, MinVersion: tls.VersionTLS13}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		pc, err := d.DialContext(ctx, "tcp", p.Addr)
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
		st.ViaPeer.Add(1)
		tunnel.Join(c, pc)
		return true
	}
	return false
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
