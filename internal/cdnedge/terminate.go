package cdnedge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/ipv64net/node64/internal/httpcompress"
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
	ip     netip.Addr // Besucher (conns_v4)
}

type terminator struct {
	tls    *chanListener          // Modus-2-Verbindungen auf 443 (nach SNI) an den eigenen HTTPS-Server
	http   *chanListener          // Port 80 fuer Modus-2-Namen: Umleitung auf HTTPS
	plain  *chanListener          // Port 80 fuer Modus-3-Namen mit "nur HTTP" (bzw. bis das Zertifikat da ist)
	refuse *chanListener          // Port 80 fuer Modus-3-Namen mit "nur HTTPS"
	direct *httputil.ReverseProxy // Modus 3: zum Ziel
	dirC   http.Handler           // Modus 3 mit Komprimierung (compress.go), sonst direct
	srvs   []*http.Server
	h3     *http3.Server
	udp    *quic.Listener // UDP 443: HTTP/3 und Tunnel (ALPN), gemeinsam
	qd     *quicDemux     // davor: QUIC fuer Modus-1-Namen roh in den Tunnel (quicpass.go)
	qtr    *quic.Transport
	proxy  *httputil.ReverseProxy
	rl     *reqLimiter
}

func (s *Server) termInit() {
	t := &terminator{tls: newChanListener(&net.TCPAddr{}), http: newChanListener(&net.TCPAddr{}), plain: newChanListener(&net.TCPAddr{}),
		refuse: newChanListener(&net.TCPAddr{}), rl: newReqLimiter(s.cfg.Shield.ReqRate), direct: s.directInit()}
	t.dirC = t.direct
	if s.compressOn() {
		t.dirC = httpcompress.Handler(t.direct, httpcompress.Options{Static: staticCached})
	}
	discard := log.New(io.Discard, "", 0)
	tr := &http.Transport{DialContext: s.termDial, DisableKeepAlives: true, MaxResponseHeaderBytes: 1 << 20, ExpectContinueTimeout: time.Second}
	t.proxy = &httputil.ReverseProxy{Transport: tr, FlushInterval: -1, ErrorLog: discard, ErrorHandler: s.termError,
		ModifyResponse: originErrorPage, // 5xx der Node: Fehlerseite fuer Browser (errorpage.go)
		Rewrite: func(pr *httputil.ProxyRequest) { // X-Forwarded-* und Forwarded entfernt Rewrite schon
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = "http", pr.In.Host, pr.In.Host
			pr.Out.Header.Del("X-Real-Ip")
			pr.Out.Header.Set("X-Forwarded-Proto", "https")
		}}
	hs := &http.Server{Handler: http.HandlerFunc(s.serveTerm), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: discard,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: s.termCert}}
	redir := &http.Server{Handler: http.HandlerFunc(s.termRedirect), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: discard}
	plain := &http.Server{Handler: http.HandlerFunc(s.serveTerm), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 64 << 10, ErrorLog: discard}
	refuse := &http.Server{Handler: http.HandlerFunc(s.refuseHTTP), ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: discard}
	refuse.SetKeepAlivesEnabled(false)
	go func() { _ = hs.ServeTLS(t.tls, "", "") }()
	go func() { _ = redir.Serve(t.http) }()
	go func() { _ = plain.Serve(t.plain) }()
	go func() { _ = refuse.Serve(t.refuse) }()
	t.srvs = []*http.Server{hs, redir, plain, refuse}
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
	conn := qc.Clone()                                                          // nil wuerde quic-go die Standardwerte nehmen lassen (Streams, Fristen)
	qc.GetConfigForClient = func(info *quic.ClientInfo) (*quic.Config, error) { // Sperrliste und Limits vor dem Handschlag
		if !gq.admit(info.RemoteAddr, info.AddrVerified) {
			return nil, errors.New("rejected")
		}
		return conn, nil
	}
	ua, err := net.ResolveUDPAddr("udp", s.cfg.ListenHTTPS)
	var uc *net.UDPConn
	if err == nil {
		uc, err = net.ListenUDP("udp", ua)
	}
	if err != nil {
		s.log.Warn("udp 443 not available (http3, tunnel)", "err", err)
		return
	}
	t.qd = newQUICDemux(s, uc)
	s.qd.Store(t.qd)
	t.qtr = &quic.Transport{Conn: t.qd, VerifySourceAddress: gq.verify} // unter Last erst Retry (Adresse nachweisen)
	ln, err := t.qtr.Listen(conf, qc)
	if err != nil {
		_ = uc.Close()
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
			if !gq.hold(c) {
				_ = c.CloseWithError(0, "")
				continue
			}
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

// quicGate: der grobe Schutz (guard) fuer QUIC auf 443. Beim ersten Paket (vor TLS) ist die Absender-Adresse noch
// nicht nachgewiesen (gefaelscht moeglich): sie zaehlt dann nur im kleineren UDP-Budget (guard.admitUDP), nicht bei
// den Verbindungen je IP und insgesamt. Mit nachgewiesener Adresse (Token aus Retry bzw. NEW_TOKEN, oder fertiger
// Handschlag) zaehlt sie wie eine TCP-Verbindung bis zu ihrem Ende. Kommt kein Handschlag zustande, frei nach 15 s.
// Warten viele Handschlaege, verlangt quic-go erst ein Retry (verify).
type quicGate struct {
	g    *guard
	mu   sync.Mutex
	rel  map[string]qgSlot
	pend atomic.Int64 // Handschlaege ohne nachgewiesene Adresse
}

type qgSlot struct {
	release  func()
	verified bool // Platz im guard (sonst im UDP-Budget)
}

// qgRetryAt: ab so vielen offenen Handschlaegen ohne Nachweis muessen neue Besucher ihre Adresse per Retry belegen.
const qgRetryAt = 64

func newQUICGate(g *guard) *quicGate { return &quicGate{g: g, rel: map[string]qgSlot{}} }

// verify (Transport.VerifySourceAddress): Retry verlangen?
func (q *quicGate) verify(net.Addr) bool { return q.pend.Load() >= qgRetryAt }

func (q *quicGate) admit(a net.Addr, verified bool) bool {
	var slot qgSlot
	if verified {
		release, why := q.g.admit(addrOf(a))
		if why != "" {
			return false
		}
		slot = qgSlot{release: release, verified: true}
	} else {
		release, why := q.g.admitUDP(addrOf(a), nil)
		if why != "" {
			return false
		}
		q.pend.Add(1)
		var once sync.Once
		slot = qgSlot{release: func() { once.Do(func() { q.pend.Add(-1); release() }) }}
	}
	k := a.String()
	q.mu.Lock()
	old := q.rel[k]
	q.rel[k] = slot
	q.mu.Unlock()
	if old.release != nil {
		old.release()
	}
	time.AfterFunc(15*time.Second, func() { q.take(k, nil) })
	return true
}

// take: Platz der Adresse holen (nil = freigeben, wenn ihn noch niemand genommen hat).
func (q *quicGate) take(k string, keep *qgSlot) {
	q.mu.Lock()
	r := q.rel[k]
	delete(q.rel, k)
	q.mu.Unlock()
	if r.release == nil {
		return
	}
	if keep != nil {
		*keep = r
		return
	}
	r.release()
}

// hold: angenommene Verbindung haelt ihren Platz bis zum Ende. Der Handschlag hat die Adresse nachgewiesen: ein Platz
// im UDP-Budget (oder keiner mehr) wird zu einem im guard; false = abgewiesen (Grenzen je IP bzw. insgesamt).
func (q *quicGate) hold(c *quic.Conn) bool {
	var r qgSlot
	q.take(c.RemoteAddr().String(), &r)
	if !r.verified {
		if r.release != nil {
			r.release()
		}
		release, why := q.g.admit(addrOf(c.RemoteAddr()))
		if why != "" {
			return false
		}
		r.release = release
	}
	go func() { <-c.Context().Done(); r.release() }()
	return true
}

// isPublicName: der eigene Name des Servers (Tunnel auf 443 statt Besucher).
func (s *Server) isPublicName(n string) bool {
	return s.cfg.PublicHost != "" && normName(n) == normName(s.cfg.PublicHost)
}

func (s *Server) termClose(ctx context.Context) {
	if s.ownSrv != nil {
		_ = s.ownSrv.Close()
	}
	t := s.term
	if t == nil {
		return
	}
	_ = t.tls.Close()
	_ = t.http.Close()
	_ = t.plain.Close()
	_ = t.refuse.Close()
	if t.h3 != nil {
		_ = t.h3.Close()
	}
	if t.udp != nil {
		_ = t.udp.Close()
		_ = t.qtr.Close()
		_ = t.qd.Close()
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
	if re == nil || (re.Mode != 2 && re.Mode != 3) {
		return nil, errors.New("unknown name")
	}
	if c := s.certs.get(re.Name); c != nil {
		if !s.certs.covers(re.Name, hello.ServerName) { // Unternamen ohne *.name im Zertifikat (HTTP-01-Ausweg)
			return nil, errors.New("certificate does not cover the name")
		}
		return c, nil
	}
	return nil, errors.New("no certificate yet")
}

// serveTerm: eine Anfrage nach Modus 2 - pruefen, begrenzen, an die Node.
func (s *Server) serveTerm(w http.ResponseWriter, r *http.Request) {
	ap, aerr := netip.ParseAddrPort(r.RemoteAddr)
	host := hostOnly(r.Host)
	rs := s.routes.Load()
	re := rs.lookup(host)
	if aerr == nil && r.ProtoMajor == 3 && s.guard.set.Load().Has(ap.Addr().Unmap()) { // TCP prueft schon acceptLoop
		s.guard.reject("blocklist")
		s.mx.termReject("blocklist")
		if re != nil {
			s.stats.of(re.Name).block(bList, ap.Addr())
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if re == nil || (re.Mode != 2 && re.Mode != 3) || (r.TLS != nil && r.TLS.ServerName != "" && rs.lookup(r.TLS.ServerName) != re) ||
		(r.TLS == nil && re.Mode != 3) {
		s.mx.termReject("misdirected")
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	if r.TLS == nil { // Port 80 mit Keep-Alive: jede Anfrage nach der Stufe ihres Namens (wie handle80)
		switch frontendPlain(re.Target, s.certs.covers(re.Name, host)) {
		case "serve":
		case "redirect":
			s.termRedirect(w, r)
			return
		case "off":
			s.mx.termReject("misdirected")
			w.Header().Set("Connection", "close")
			http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
			return
		default:
			w.Header().Set("Connection", "close")
			s.refuseHTTP(w, r)
			return
		}
	}
	st := s.stats.of(re.Name)
	if aerr == nil && !s.term.rl.allow(ap.Addr()) {
		st.block(bLimit, ap.Addr())
		s.mx.termReject("req_rate")
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	if aerr == nil && !re.allows(ap.Addr()) {
		st.block(bACL, ap.Addr())
		s.mx.termReject("acl")
		termPage(w, r, http.StatusForbidden, host, "Zugriff von dieser Adresse nicht erlaubt.", "Access from this address is not allowed.")
		return
	}
	if re.Blocked != "" {
		s.mx.termReject("blocked")
		termPage(w, r, http.StatusServiceUnavailable, host, "Dieser Dienst ist vorübergehend nicht verfügbar.", "This service is temporarily unavailable.")
		return
	}
	if re.WAF && wafHit(r) { // Muster-WAF (waf.go)
		st.block(bWAF, ap.Addr())
		s.mx.termReject("waf")
		termPage(w, r, http.StatusForbidden, host, "Diese Anfrage wurde von der CDN64-WAF blockiert.", "This request was blocked by the CDN64 WAF.")
		return
	}
	if s.term.h3 != nil && r.ProtoMajor < 3 {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	}
	st.Requests.Add(1)
	rec := &statusRec{ResponseWriter: w}
	w = rec
	defer func() { s.mx.countRequest(re.Mode, rec.status, r.ProtoMajor) }()
	cctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	defer s.track(re.Name, re.Mode, ap.Addr(), cancel)()
	ctx := context.WithValue(cctx, termCtxKey{}, &termReq{re: re, host: host, client: r.RemoteAddr, ip: ap.Addr()})
	if re.Mode == 3 { // Traffic: was zum Besucher geht (komprimiert bzw. aus dem Cache), nicht was vom Ziel kommt
		s.serveCached(&outCounter{ResponseWriter: w, st: st, bw: s.bw, uid: re.UserID}, r.WithContext(ctx), re, s.term.dirC)
		return
	}
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
		st.conn(tq.ip)
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
	termPage(w, r, http.StatusBadGateway, hostOnly(r.Host), "Der Server hinter dieser Adresse ist gerade nicht erreichbar. Bitte später noch einmal versuchen.",
		"The server behind this address is not reachable right now. Please try again later.")
}

// termRedirect: Port 80 eines Modus-2/3-Namens -> HTTPS. Nur auf eigene Namen: bei einer Anfrage in absoluter Form
// (GET http://andere.example/ ...) ist r.Host der Name aus der URL, nicht der, nach dem die Verbindung kam - sonst
// leitete der Server auf beliebige Ziele weiter (Test 2026-10-29).
func (s *Server) termRedirect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Connection", "close")
	if re := s.routes.Load().lookup(hostOnly(r.Host)); re == nil || (re.Mode != 2 && re.Mode != 3) {
		s.mx.termReject("misdirected")
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		return
	}
	http.Redirect(w, r, "https://"+hostOnly(r.Host)+r.URL.RequestURI(), http.StatusMovedPermanently)
}

// prefersGerman: steht Deutsch im Accept-Language vorn (hoechstes q, bei Gleichstand das erste)? Sonst Englisch.
func prefersGerman(h string) bool {
	best, bestQ := "", -1.0
	for _, part := range strings.Split(h, ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				q = f
			}
		}
		if tag != "" && tag != "*" && q > bestQ {
			best, bestQ = strings.ToLower(tag), q
		}
	}
	return best == "de" || strings.HasPrefix(best, "de-")
}

func hostOnly(h string) string {
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	return normName(h)
}

// termConn zaehlt beide Richtungen eines Streams und haelt das Bandbreiten-Limit des Accounts ein. noOut (Modus 3):
// die Antwort zaehlt outCounter beim Besucher.
type termConn struct {
	net.Conn
	st    *hostStat
	bw    *bandwidth
	uid   int
	noOut bool
}

func (c *termConn) Read(p []byte) (int, error) { // Node -> Besucher
	n, err := c.Conn.Read(p)
	if n > 0 && !c.noOut {
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

// outCounter (Modus 3) zaehlt die Bytes, die wirklich zum Besucher gehen - nach der Komprimierung und auch bei
// Treffern aus dem Cache - und haelt dabei das Bandbreiten-Limit ein. WebSockets zaehlen nach Hijack weiter.
type outCounter struct {
	http.ResponseWriter
	st  *hostStat
	bw  *bandwidth
	uid int
}

func (w *outCounter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.count(n)
	return n, err
}

func (w *outCounter) count(n int) {
	if n > 0 {
		w.st.BytesOut.Add(int64(n))
		w.bw.take(w.uid, n)
	}
}

func (w *outCounter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *outCounter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *outCounter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, brw, err := http.NewResponseController(w.ResponseWriter).Hijack()
	if err != nil {
		return nil, nil, err
	}
	return &outConn{Conn: c, w: w}, brw, nil
}

type outConn struct {
	net.Conn
	w *outCounter
}

func (c *outConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.w.count(n)
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
