package cdnedge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Modus 2 (terminieren, Abschnitt 6 der Planung): TLS endet hier mit dem Zertifikat des Namens (certs.go), HTTP/1.1,
// HTTP/2 und auf Wunsch HTTP/3. Jede Anfrage geht als eigener Stream (kind "http", echte Besucher-Adresse im Kopf)
// durch den Tunnel zur Node, die sie wie HTTPS behandelt; WebSockets laufen ueber denselben Stream weiter. Fehlt das
// Zertifikat noch, wird wie in Modus 1 durchgereicht - ein Wechsel 1 -> 2 faellt so nie aus. Der Host-Kopf muss zum
// SNI-Namen gehoeren (kein Domain-Fronting, G10). Je IP (IPv6 je /64) begrenzt ein Anfrage-Limit (429).

type termCtxKey struct{}

// termReq: was der Verbindungsaufbau zur Node fuer eine Anfrage braucht.
type termReq struct {
	re     *route
	host   string
	client string
}

type terminator struct {
	tls   *chanListener // Modus-2-Verbindungen auf 443 (nach SNI) an den eigenen HTTPS-Server
	http  *chanListener // Port 80 fuer Modus-2-Namen: Umleitung auf HTTPS
	srvs  []*http.Server
	h3    *http3.Server
	udp   *quic.Listener // UDP 443: HTTP/3 und Tunnel (ALPN), gemeinsam
	proxy *httputil.ReverseProxy
	rl    *reqLimiter
}

func (s *Server) termInit() {
	t := &terminator{tls: newChanListener(&net.TCPAddr{}), http: newChanListener(&net.TCPAddr{}), rl: newReqLimiter(s.cfg.Shield.ReqRate)}
	discard := log.New(io.Discard, "", 0)
	tr := &http.Transport{DialContext: s.termDial, DisableKeepAlives: true, MaxResponseHeaderBytes: 1 << 20, ExpectContinueTimeout: time.Second}
	t.proxy = &httputil.ReverseProxy{Transport: tr, FlushInterval: -1, ErrorLog: discard, ErrorHandler: s.termError,
		Rewrite: func(pr *httputil.ProxyRequest) { // X-Forwarded-* und Forwarded entfernt Rewrite schon
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", pr.In.Host, pr.In.Host
			pr.Out.Header.Del("X-Real-Ip")
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		}}
	hs := &http.Server{Handler: http.HandlerFunc(s.serveTerm), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: discard,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: s.termCert}}
	redir := &http.Server{Handler: http.HandlerFunc(termRedirect), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: discard}
	go func() { _ = hs.ServeTLS(t.tls, "", "") }()
	go func() { _ = redir.Serve(t.http) }()
	t.srvs = []*http.Server{hs, redir}
	if s.cfg.HTTP3 && s.cfg.ListenHTTPS != "" {
		t.h3 = &http3.Server{Handler: http.HandlerFunc(s.serveTerm)}
	}
	s.term = t
}

// listenUDP443: ein QUIC-Listener auf UDP listen_https fuer HTTP/3 (Modus 2) und den Tunnel (G1, Netze, die nur 443
// hinauslassen). Getrennt wird nach dem Namen: der eigene Name (public_host) ist der Tunnel, alles andere HTTP/3.
// Laeuft nach startTunnel.
func (s *Server) listenUDP443() {
	t := s.term
	if s.cfg.ListenHTTPS == "" || (t.h3 == nil && s.tun == nil) {
		return
	}
	h3conf := http3.ConfigureTLSConfig(&tls.Config{MinVersion: tls.VersionTLS13, GetCertificate: s.termCert})
	conf := &tls.Config{MinVersion: tls.VersionTLS13, GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if s.tun != nil && s.isPublicName(hello.ServerName) {
			c := s.tlsConf.Clone()
			c.MinVersion, c.NextProtos = tls.VersionTLS13, []string{tunnel.ALPN}
			return c, nil
		}
		if t.h3 == nil {
			return nil, errors.New("http3 off")
		}
		return h3conf, nil
	}}
	qc := tunnel.QUICConfig()
	qc.MaxIncomingStreams = 200 // Besucher (HTTP/3) und Tunnel teilen sich den Port; die Node oeffnet nur den Steuer-Stream
	qc.KeepAlivePeriod = 0      // die Node haelt ihren Tunnel selbst wach
	gq := newQUICGate(s.guard)
	qc.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) { // Sperrliste und Limits je IP vor dem Handschlag
		if !gq.admit(info.RemoteAddr) {
			return nil, errors.New("rejected")
		}
		return nil, nil
	}
	ln, err := quic.ListenAddr(s.cfg.ListenHTTPS, conf, qc)
	if err != nil {
		s.log.Warn("udp 443 not available (http3, tunnel)", "err", err)
		return
	}
	t.udp = ln
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			gq.hold(c)
			switch c.ConnectionState().TLS.NegotiatedProtocol {
			case tunnel.ALPN:
				s.tun.ServeQUICConn(c)
			case http3.NextProtoH3:
				if t.h3 != nil {
					go func() { _ = t.h3.ServeQUICConn(c) }()
					continue
				}
				fallthrough
			default:
				_ = c.CloseWithError(0, "")
			}
		}
	}()
}

// quicGate: der grobe Schutz (guard) fuer QUIC auf 443 - beim ersten Paket (vor TLS) zaehlt die Verbindung, frei
// wird sie mit ihrem Ende; kommt kein Handschlag zustande, nach 15 s.
type quicGate struct {
	g   *guard
	mu  sync.Mutex
	rel map[string]func()
}

func newQUICGate(g *guard) *quicGate { return &quicGate{g: g, rel: map[string]func(){}} }

func (q *quicGate) admit(a net.Addr) bool {
	release, why := q.g.admit(addrOf(a))
	if why != "" {
		return false
	}
	k := a.String()
	q.mu.Lock()
	if old := q.rel[k]; old != nil {
		old()
	}
	q.rel[k] = release
	q.mu.Unlock()
	time.AfterFunc(15*time.Second, func() { q.take(k, nil) })
	return true
}

// take: Platz der Adresse holen (nil = freigeben, wenn ihn noch niemand genommen hat).
func (q *quicGate) take(k string, keep *func()) {
	q.mu.Lock()
	r := q.rel[k]
	delete(q.rel, k)
	q.mu.Unlock()
	if r == nil {
		return
	}
	if keep != nil {
		*keep = r
		return
	}
	r()
}

// hold: angenommene Verbindung haelt ihren Platz bis zum Ende.
func (q *quicGate) hold(c *quic.Conn) {
	var r func()
	q.take(c.RemoteAddr().String(), &r)
	if r != nil {
		go func() { <-c.Context().Done(); r() }()
	}
}

// isPublicName: der eigene Name des Servers (Tunnel auf 443 statt Besucher).
func (s *Server) isPublicName(n string) bool {
	return s.cfg.PublicHost != "" && normName(n) == normName(s.cfg.PublicHost)
}

func (s *Server) termClose(ctx context.Context) {
	t := s.term
	if t == nil {
		return
	}
	_ = t.tls.Close()
	_ = t.http.Close()
	if t.h3 != nil {
		_ = t.h3.Close()
	}
	if t.udp != nil {
		_ = t.udp.Close()
	}
	var wg sync.WaitGroup
	for _, srv := range t.srvs {
		wg.Add(1)
		go func() { defer wg.Done(); _ = srv.Shutdown(ctx) }()
	}
	wg.Wait()
}

// termCert: Zertifikat fuer den SNI-Namen (nur Modus-2-Namen mit Zertifikat).
func (s *Server) termCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	re := s.routes.Load().lookup(hello.ServerName)
	if re == nil || re.Mode != 2 {
		return nil, errors.New("unknown name")
	}
	if c := s.certs.get(re.Name); c != nil {
		return c, nil
	}
	return nil, errors.New("no certificate yet")
}

// serveTerm: eine Anfrage nach Modus 2 - pruefen, begrenzen, an die Node.
func (s *Server) serveTerm(w http.ResponseWriter, r *http.Request) {
	ap, aerr := netip.ParseAddrPort(r.RemoteAddr)
	if aerr == nil && r.ProtoMajor == 3 && s.guard.set.Load().Has(ap.Addr().Unmap()) { // TCP prueft schon acceptLoop
		s.guard.rejected.Add(1)
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	host := hostOnly(r.Host)
	rs := s.routes.Load()
	re := rs.lookup(host)
	if re == nil || re.Mode != 2 || (r.TLS != nil && r.TLS.ServerName != "" && rs.lookup(r.TLS.ServerName) != re) {
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	st := s.stats.of(re.Name)
	if aerr == nil && !s.term.rl.allow(ap.Addr()) {
		st.Rejected.Add(1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if re.Blocked != "" {
		termPage(w, http.StatusServiceUnavailable, host, "Dieser Dienst ist vorübergehend nicht verfügbar.", "This service is temporarily unavailable.")
		return
	}
	if s.term.h3 != nil && r.ProtoMajor < 3 {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}
	st.Requests.Add(1)
	ctx := context.WithValue(r.Context(), termCtxKey{}, &termReq{re: re, host: host, client: r.RemoteAddr})
	s.term.proxy.ServeHTTP(w, r.WithContext(ctx))
}

// termDial: ein Stream zur Node je Anfrage (eigener Tunnel, sonst ueber den Nachbarn).
func (s *Server) termDial(ctx context.Context, _, _ string) (net.Conn, error) {
	tq, _ := ctx.Value(termCtxKey{}).(*termReq)
	if tq == nil {
		return nil, errors.New("no route")
	}
	st := s.stats.of(tq.re.Name)
	if p := s.peerFor(tq.re.Tunnels); p != nil {
		ts, err := s.openPeer(ctx, p, tunnel.Header{Kind: tunnel.KindHTTP, Client: tq.client, Host: tq.host, Port: 443})
		if err != nil {
			st.NoTunnel.Add(1)
			return nil, err
		}
		st.Conns.Add(1)
		return &termConn{Conn: ts, st: st, bw: s.bw, uid: tq.re.UserID}, nil
	}
	if pc := s.dialPeer(ctx, tunnel.KindHTTP, tq.host, 443, tq.client, nil); pc != nil { // der Nachbar zaehlt
		st.ViaPeer.Add(1)
		return pc, nil
	}
	st.NoTunnel.Add(1)
	return nil, errNoTunnel
}

var errNoTunnel = errors.New("node not connected")

// termError: Node nicht erreichbar (E4) - verstaendliche Seite statt Verbindungsfehler.
func (s *Server) termError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return // Besucher hat abgebrochen
	}
	termPage(w, http.StatusBadGateway, hostOnly(r.Host), "Der Server hinter dieser Adresse ist gerade nicht erreichbar. Bitte später noch einmal versuchen.",
		"The server behind this address is not reachable right now. Please try again later.")
}

// termRedirect: Port 80 eines Modus-2-Namens -> HTTPS.
func termRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	http.Redirect(w, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// termPage: kleine Seite fuer Fehler (Deutsch und Englisch, ohne externe Quellen).
func termPage(w http.ResponseWriter, code int, host, de, en string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%d</title><style>body{font-family:system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem;color:#222}@media(prefers-color-scheme:dark){body{background:#111;color:#ddd}}small{color:#888}</style></head>
<body><h1>%d</h1><p>%s</p><p>%s</p><p><small>%s · CDN64</small></p></body></html>`, code, code, html.EscapeString(de), html.EscapeString(en), html.EscapeString(host))
}

func hostOnly(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return normName(h)
}

// termConn zaehlt beide Richtungen eines Streams und haelt das Bandbreiten-Limit des Accounts ein.
type termConn struct {
	net.Conn
	st  *hostStat
	bw  *bandwidth
	uid int
}

func (c *termConn) Read(p []byte) (int, error) { // Node -> Besucher
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.st.BytesOut.Add(int64(n))
		c.bw.take(c.uid, n)
	}
	return n, err
}

func (c *termConn) Write(p []byte) (int, error) { // Besucher -> Node
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.st.BytesIn.Add(int64(n))
		c.bw.take(c.uid, n)
	}
	return n, err
}

// ---------------------------------------------------------------- Anfrage-Limit

// reqLimiter: Anfragen je Sekunde je IP (IPv6 je /64), kurzzeitig das Zehnfache.
type reqLimiter struct {
	rate, burst float64
	mu          sync.Mutex
	ips         map[netip.Addr]*gstate
	last        atomic.Int64 // letzte Aufraeumung (Unix)
	now         func() time.Time
}

func newReqLimiter(rate int) *reqLimiter {
	switch {
	case rate == 0:
		rate = 50
	case rate < 0:
		rate = 0
	}
	return &reqLimiter{rate: float64(rate), burst: float64(rate) * 10, ips: map[netip.Addr]*gstate{}, now: time.Now}
}

func (l *reqLimiter) allow(a netip.Addr) bool {
	if l.rate == 0 {
		return true
	}
	k, now := gkey(a), l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Unix()-l.last.Load() > 60 { // ruhige Adressen wegraeumen
		for ip, st := range l.ips {
			if now.Sub(st.at) > 2*time.Minute {
				delete(l.ips, ip)
			}
		}
		l.last.Store(now.Unix())
	}
	st := l.ips[k]
	if st == nil {
		st = &gstate{tok: l.burst, at: now}
		l.ips[k] = st
	} else if dt := now.Sub(st.at).Seconds(); dt > 0 {
		st.tok = min(st.tok+dt*l.rate, l.burst)
		st.at = now
	}
	if st.tok < 1 {
		return false
	}
	st.tok--
	return true
}
