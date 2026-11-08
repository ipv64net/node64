package edge

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// PROXY protocol (HAProxy, v1 Text und v2 binaer) auf den TCP-Ports 80/443: Steht PROXY64 hinter einem anderen
// Proxy, der TCP bzw. TLS nur durchreicht (z. B. Traefik mit serversTransport proxyProtocol), kommt die echte
// Besucher-Adresse nur so an. Angenommen wird der Kopf nur von den Adressen bzw. Netzen in Config.ProxyProtocol;
// von dort ist er freiwillig (Health-Checks des Proxys ohne Kopf gehen weiter), von allen anderen wird nichts
// gelesen - ein Besucher kann sich also keine fremde Adresse geben. Die Verbindung traegt danach die Adresse aus dem
// Kopf (Zugriffslisten, Logs, Honeypot, Bremsen, Sperren). Verbindungen aus dem CDN64-Tunnel betrifft das nicht.

const (
	ppHeaderWait = 5 * time.Second // so lange darf der vertraute Proxy fuer den Kopf brauchen
	ppV1Max      = 107             // laengster v1-Kopf samt CRLF
	ppV2Max      = 16 + 2048       // v2: Kopf + Adressen/TLVs (mehr schickt kein ueblicher Proxy)
)

var ppV2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

// parseTrustedNets: Adressen bzw. Netze, durch Leerzeichen, Komma oder Zeilen getrennt ("" = keine).
func parseTrustedNets(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if p, err := netip.ParsePrefix(f); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(strings.Trim(f, "[]"))
		if err != nil {
			return nil, errors.New("proxy_protocol: " + strconv.Quote(f) + " is not an address or network")
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trustedAddr(nets []netip.Prefix, a net.Addr) bool {
	ta, ok := a.(*net.TCPAddr)
	if !ok {
		return false
	}
	ip, ok := netip.AddrFromSlice(ta.IP)
	if !ok {
		return false
	}
	ip = ip.Unmap()
	for _, p := range nets {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ppListener liest bei Verbindungen von vertrauten Adressen den PROXY-Kopf (in eigener Goroutine, damit ein
// langsamer Absender das Annehmen nicht aufhaelt) und gibt die Verbindung mit der echten Adresse weiter.
type ppListener struct {
	net.Listener
	nets []netip.Prefix
	ch   chan net.Conn
	errc chan error
	done chan struct{}
	once sync.Once
}

// proxyListen: ln unveraendert, wenn keine vertrauten Adressen eingetragen sind.
func proxyListen(ln net.Listener, raw string) net.Listener {
	nets, err := parseTrustedNets(raw)
	if err != nil || len(nets) == 0 {
		return ln
	}
	l := &ppListener{Listener: ln, nets: nets, ch: make(chan net.Conn), errc: make(chan error, 1), done: make(chan struct{})}
	go l.loop()
	return l
}

func (l *ppListener) loop() {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			select {
			case l.errc <- err:
			case <-l.done:
			}
			return
		}
		if !trustedAddr(l.nets, c.RemoteAddr()) {
			l.deliver(c)
			continue
		}
		go func() {
			pc, err := readProxyHeader(c)
			if err != nil {
				_ = c.Close()
				return
			}
			l.deliver(pc)
		}()
	}
}

func (l *ppListener) deliver(c net.Conn) {
	select {
	case l.ch <- c:
	case <-l.done:
		_ = c.Close()
	}
}

func (l *ppListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case err := <-l.errc:
		l.errc <- err // auch fuer weitere Aufrufe
		return nil, err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *ppListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.Listener.Close()
}

// ppConn: Verbindung mit der Adresse aus dem PROXY-Kopf; schon gepufferte Bytes kommen zuerst.
type ppConn struct {
	net.Conn
	r      *bufio.Reader
	remote net.Addr
}

func (c *ppConn) Read(p []byte) (int, error) { return c.r.Read(p) }
func (c *ppConn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

// CloseWrite: halb schliessen wie die TCP-Verbindung darunter (TLS durchreichen).
func (c *ppConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// readProxyHeader liest einen v1- bzw. v2-Kopf, falls einer kommt (sonst bleibt die Verbindung, wie sie ist).
func readProxyHeader(c net.Conn) (net.Conn, error) {
	_ = c.SetReadDeadline(time.Now().Add(ppHeaderWait))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	br := bufio.NewReaderSize(c, ppV2Max)
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	switch first[0] {
	case 'P': // v1 "PROXY ..."
		head, err := br.Peek(6)
		if err != nil || string(head) != "PROXY " {
			return &ppConn{Conn: c, r: br}, nil // kein Kopf (z. B. HTTP vom Proxy selbst)
		}
		line, err := readV1Line(br)
		if err != nil {
			return nil, err
		}
		addr, err := parseV1(line)
		if err != nil {
			return nil, err
		}
		return &ppConn{Conn: c, r: br, remote: addr}, nil
	case '\r': // v2
		sig, err := br.Peek(16)
		if err != nil || !bytes.Equal(sig[:12], ppV2Sig) {
			return &ppConn{Conn: c, r: br}, nil
		}
		n := int(binary.BigEndian.Uint16(sig[14:16]))
		if 16+n > ppV2Max {
			return nil, errors.New("proxy protocol v2: header too long")
		}
		buf := make([]byte, 16+n)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		addr, err := parseV2(buf)
		if err != nil {
			return nil, err
		}
		return &ppConn{Conn: c, r: br, remote: addr}, nil
	}
	return &ppConn{Conn: c, r: br}, nil
}

func readV1Line(br *bufio.Reader) (string, error) {
	var b []byte
	for len(b) < ppV1Max {
		ch, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		b = append(b, ch)
		if ch == '\n' {
			if len(b) < 2 || b[len(b)-2] != '\r' {
				return "", errors.New("proxy protocol v1: missing CRLF")
			}
			return string(b[:len(b)-2]), nil
		}
	}
	return "", errors.New("proxy protocol v1: header too long")
}

// parseV1: "PROXY TCP4 <src> <dst> <sport> <dport>" bzw. "PROXY UNKNOWN ..." (dann Adresse der Verbindung, nil).
func parseV1(line string) (net.Addr, error) {
	f := strings.Fields(line)
	if len(f) >= 2 && f[1] == "UNKNOWN" {
		return nil, nil
	}
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return nil, errors.New("proxy protocol v1: bad header")
	}
	ip, err := netip.ParseAddr(f[2])
	if err != nil || (f[1] == "TCP4") != ip.Is4() {
		return nil, errors.New("proxy protocol v1: bad source address")
	}
	port, err := strconv.ParseUint(f[4], 10, 16)
	if err != nil {
		return nil, errors.New("proxy protocol v1: bad source port")
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, uint16(port))), nil
}

// parseV2: binaerer Kopf (Signatur, Version/Befehl, Familie, Laenge, Adressen, TLVs). LOCAL bzw. unbekannte
// Familie: Adresse der Verbindung (nil).
func parseV2(b []byte) (net.Addr, error) {
	if len(b) < 16 || b[12]>>4 != 2 {
		return nil, errors.New("proxy protocol v2: bad version")
	}
	switch b[12] & 0x0f {
	case 0: // LOCAL (z. B. Health-Check des Proxys)
		return nil, nil
	case 1: // PROXY
	default:
		return nil, errors.New("proxy protocol v2: bad command")
	}
	body := b[16:]
	switch b[13] >> 4 {
	case 1: // AF_INET: src(4) dst(4) sport(2) dport(2)
		if len(body) < 12 {
			return nil, errors.New("proxy protocol v2: short ipv4 block")
		}
		ip := netip.AddrFrom4([4]byte(body[0:4]))
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[8:10]))), nil
	case 2: // AF_INET6: src(16) dst(16) sport(2) dport(2)
		if len(body) < 36 {
			return nil, errors.New("proxy protocol v2: short ipv6 block")
		}
		ip := netip.AddrFrom16([16]byte(body[0:16])).Unmap()
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ip, binary.BigEndian.Uint16(body[32:34]))), nil
	}
	return nil, nil // AF_UNSPEC/AF_UNIX: Adresse der Verbindung
}
