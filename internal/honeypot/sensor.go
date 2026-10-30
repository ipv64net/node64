package honeypot

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"
)

// Sensor oeffnet und schliesst die Fallen-Dienste nach einer Config und gibt jedes Ereignis an die Sink.
//
// Vertrag:
//   - NewSensor(log, dir): dir ist das Datenverzeichnis des Moduls (z. B. /data/honeypot) fuer den SSH-Host-Schluessel
//     und das selbst signierte TLS-Zertifikat (beide beim ersten Start erzeugt, danach wiederverwendet).
//   - Apply(ctx, cfg, sink): bringt die offenen Ports auf den Stand von cfg (idempotent; unveraenderte Dienste bleiben
//     offen, entfernte werden geschlossen). Liefert den Zustand je Dienst. Ein Port, der nicht geht (belegt, keine
//     Rechte), ist kein Fehler fuer die anderen.
//   - Stop(): schliesst alles und wartet auf laufende Verbindungen (mit kurzem Zeitlimit).
//   - Status(): Zustand je Dienst; Counters(): Zaehler seit dem Start.
//   - SetPortCheck(f): optional; f(service, port) wird vor dem Oeffnen gefragt (Port-Verwaltung der Node), ein Fehler
//     laesst den Dienst zu (Listen=false, Error=...).
//
// Grenzen: gleichzeitig hoechstens MaxConnsPerIP je Quelle und MaxConnsTotal insgesamt (abgewiesen = Dropped), je
// Verbindung ein festes Zeitlimit und eine Obergrenze fuer gelesene Bytes. Keine ausgehenden Verbindungen.
type Sensor struct {
	log      *slog.Logger
	dir      string
	counters Counters

	applyMu sync.Mutex // Apply/Stop nacheinander
	mu      sync.Mutex // svcs, order, check
	svcs    map[sensorKey]*trapService
	order   []sensorKey
	bad     []ServiceStatus // ungueltige Eintraege der Config (nur Status)
	check   func(service string, port int) error

	sink   atomic.Pointer[Sink]
	perIP  atomic.Int64
	total  atomic.Int64
	scanOn atomic.Bool
	plain  atomic.Bool // Startseite der Web-Falle schlicht statt Gateway-Terminal (Config.StartPage)
	scan   sensorScan

	connMu sync.Mutex
	conns  map[netip.Addr]int
	nconns int

	keyMu   sync.Mutex
	signer  ssh.Signer
	sshKeys *sensorSSHKeys // Host-Schluessel wie OpenSSH (RSA, ECDSA, Ed25519)
	cert    *tls.Certificate
	certs   map[string]*tls.Certificate // Zertifikate je Profil (sensor_keys.go)

	seed    string                         // Seed ohne Config.Seed (zufaellig, nur im Speicher)
	persona atomic.Pointer[sensorPersonas] // Dienst-Profile (sensor_persona.go)

	certSrc atomic.Pointer[func(int64) *tls.Certificate] // Zertifikate der Verwaltung (sensor_cert.go), nil = keine
	certCfg atomic.Pointer[sensorCertCfg]                // Zuweisung nach dem letzten Apply

	wg sync.WaitGroup
}

// Grenzen und Zeitlimits der Fallen-Dienste.
const (
	sensorDefPerIP  = 8
	sensorDefTotal  = 512
	sensorStopWait  = 3 * time.Second
	sensorSSHBudget = 64 << 10 // gelesene Bytes je Verbindung
	sensorTelBudget = 4 << 10
	sensorWebBudget = 64 << 10
	sensorTCPBudget = 4 << 10
)

// sensorKey kennzeichnet einen Dienst; Apply vergleicht danach.
type sensorKey struct {
	Service string
	Port    int
	Page    string
}

// NewSensor legt den Sensor an (noch ohne offene Ports).
func NewSensor(log *slog.Logger, dir string) *Sensor {
	if log == nil {
		log = slog.Default()
	}
	s := &Sensor{log: log.With("module", Name), dir: dir, svcs: map[sensorKey]*trapService{}, conns: map[netip.Addr]int{}, seed: sensorRandomSeed()}
	s.perIP.Store(sensorDefPerIP)
	s.total.Store(sensorDefTotal)
	return s
}

// SetPortCheck setzt die Pruefung vor dem Oeffnen eines Ports (nil = keine).
func (s *Sensor) SetPortCheck(f func(service string, port int) error) {
	s.mu.Lock()
	s.check = f
	s.mu.Unlock()
}

// Apply bringt die Dienste auf den Stand von cfg.
func (s *Sensor) Apply(ctx context.Context, cfg Config, sink Sink) []ServiceStatus {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	if sink != nil {
		s.sink.Store(&sink)
	} else {
		s.sink.Store(nil)
	}
	per, total := cfg.MaxConnsPerIP, cfg.MaxConnsTotal
	if per <= 0 {
		per = sensorDefPerIP
	}
	if total <= 0 {
		total = sensorDefTotal
	}
	s.perIP.Store(int64(per))
	s.total.Store(int64(total))
	s.scanOn.Store(cfg.Scan)
	s.plain.Store(cfg.StartPage == StartNeutral)
	seed := cfg.Seed
	if seed == "" && s.dir != "" { // Modus ohne Oberflaeche: Sensor-Kennung aus <dir>/sensor_id (wie die Meldung)
		seed, _ = SensorIDFromFile(s.dir)
	}
	if seed == "" {
		seed = s.seed
	}
	s.persona.Store(newSensorPersonas(seed, cfg.Hostname, cfg.Personas, cfg.Vulnerable)) // gilt ab der naechsten Verbindung
	s.certCfg.Store(&sensorCertCfg{id: cfg.CertID, ports: slices.Clone(cfg.CertPorts)})
	if !cfg.Scan {
		s.scan.reset()
	}

	// gewuenschte Dienste (doppelte nur einmal), ungueltige nur im Status
	var want []sensorKey
	var bad []ServiceStatus
	seen := map[sensorKey]bool{}
	for _, sv := range cfg.Services {
		k := sensorKey{Service: sv.Service, Port: sv.Port, Page: sv.Page}
		if k.Service != SvcHTTP && k.Service != SvcHTTPS {
			k.Page = ""
		}
		var msg string
		switch {
		case k.Service == SvcScan:
			continue // Port-Scan-Erkennung ist cfg.Scan
		case !sensorValidService(k.Service):
			msg = "unknown service"
		case k.Port < 1 || k.Port > 65535:
			msg = "invalid port"
		case k.Page != "" && !sensorValidPage(k.Page):
			msg = "unknown page"
		}
		if msg != "" {
			bad = append(bad, ServiceStatus{Service: k.Service, Port: k.Port, Error: msg})
			continue
		}
		if !seen[k] {
			seen[k] = true
			want = append(want, k)
		}
	}

	s.mu.Lock()
	old, check := s.svcs, s.check
	s.mu.Unlock()

	// zuerst schliessen, was wegfaellt (gibt den Port fuer einen geaenderten Dienst frei)
	for k, t := range old {
		if !seen[k] {
			s.closeService(t)
		}
	}
	next := make(map[sensorKey]*trapService, len(want))
	for _, k := range want {
		t := old[k]
		if t == nil {
			t = &trapService{key: k}
		}
		if t.ln == nil && t.pc == nil {
			s.openService(ctx, t, check)
		}
		next[k] = t
	}
	s.mu.Lock()
	s.svcs, s.order, s.bad = next, want, bad
	s.mu.Unlock()
	return s.Status()
}

// Stop schliesst alle Dienste.
func (s *Sensor) Stop() {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	s.mu.Lock()
	old := s.svcs
	s.svcs, s.order, s.bad = map[sensorKey]*trapService{}, nil, nil
	s.mu.Unlock()
	for _, t := range old {
		s.closeService(t)
	}
	s.scan.reset()
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(sensorStopWait):
		s.log.Warn("honeypot connections did not end in time")
	}
}

// Status liefert den Zustand je Dienst.
func (s *Sensor) Status() []ServiceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ServiceStatus, 0, len(s.order)+len(s.bad))
	for _, k := range s.order {
		t := s.svcs[k]
		if t == nil {
			continue
		}
		out = append(out, ServiceStatus{Service: k.Service, Port: k.Port, Listen: t.ln != nil || t.pc != nil, Error: t.err, Conns: t.conns.Load()})
	}
	return append(out, s.bad...)
}

// Counters liefert die Zaehler seit dem Start.
func (s *Sensor) Counters() *Counters { return &s.counters }

func sensorValidService(v string) bool {
	switch v {
	case SvcSSH, SvcTelnet, SvcHTTP, SvcHTTPS, SvcTCP:
		return true
	}
	return ProtoKnown(v)
}

func sensorValidPage(p string) bool {
	for _, x := range Pages {
		if x == p {
			return true
		}
	}
	return false
}

// trapService ist ein offener (oder gescheiterter) Fallen-Dienst.
type trapService struct {
	key   sensorKey
	ln    net.Listener   // nil = nicht offen; geschrieben nur in Apply/Stop unter Sensor.mu
	pc    net.PacketConn // UDP-Dienste (sensor_proto.go) statt ln
	err   string
	srv   *http.Server // HTTP/HTTPS
	conns atomic.Int64 // angenommene Verbindungen seit dem Start

	mu     sync.Mutex
	active map[*trapConn]struct{}
	closed bool
}

// openService oeffnet den Port und startet den Dienst; Fehler landen in t.err.
func (s *Sensor) openService(ctx context.Context, t *trapService, check func(string, int) error) {
	k := t.key
	fail := func(msg string) {
		s.mu.Lock()
		t.err = msg
		s.mu.Unlock()
		s.log.Warn("honeypot service not opened", "service", k.Service, "port", k.Port, "err", msg)
	}
	if check != nil {
		if err := check(k.Service, k.Port); err != nil {
			fail(err.Error())
			return
		}
	}
	if p := udpProtos[k.Service]; p != nil {
		var lc net.ListenConfig
		pc, err := lc.ListenPacket(ctx, "udp", ":"+strconv.Itoa(k.Port))
		if err != nil {
			fail(sensorListenErr(err))
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for s.serveUDP(t, p, pc) { // nach einer Panik weiter lesen, bis pc geschlossen wird
			}
		}()
		s.mu.Lock()
		t.pc, t.err = pc, ""
		s.mu.Unlock()
		s.log.Info("honeypot service open", "service", k.Service, "port", k.Port, "proto", "udp")
		return
	}
	var keys *sensorSSHKeys
	var cert *tls.Certificate
	var err error
	switch k.Service {
	case SvcSSH:
		keys, err = s.sshHostKeys()
	case SvcHTTPS:
		cert, err = s.httpsCert(k)
	default:
		if p := tcpProtos[k.Service]; p != nil && p.TLS {
			if certMail(k.Service) { // wie ein Mailserver mit Snakeoil-Zertifikat (CN = Hostname)
				cert, err = s.personaCert(certGeneric, s.personas().id)
			} else {
				cert, err = s.tlsCert()
			}
		}
	}
	if err != nil {
		fail(err.Error())
		return
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", ":"+strconv.Itoa(k.Port))
	if err != nil {
		fail(sensorListenErr(err))
		return
	}
	t.mu.Lock()
	t.active, t.closed = map[*trapConn]struct{}{}, false
	t.mu.Unlock()
	tl := &trapListener{Listener: ln, s: s, t: t}
	switch k.Service {
	case SvcSSH:
		s.serveLoop(tl, func(c *trapConn) { s.handleSSH(c, keys) })
	case SvcTelnet:
		s.serveLoop(tl, s.handleTelnet)
	case SvcTCP:
		s.serveLoop(tl, s.handleTCP)
	default:
		if p := tcpProtos[k.Service]; p != nil {
			s.serveLoop(tl, func(c *trapConn) {
				if p.TLS {
					s.serveProtoTLS(c, cert, p)
					return
				}
				p.Handle(s, c)
			})
		}
	case SvcHTTP, SvcHTTPS:
		t.srv = s.httpServer(t, cert)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			if cert != nil {
				_ = t.srv.ServeTLS(tl, "", "")
			} else {
				_ = t.srv.Serve(tl)
			}
		}()
	}
	s.mu.Lock()
	t.ln, t.err = ln, ""
	s.mu.Unlock()
	s.log.Info("honeypot service open", "service", k.Service, "port", k.Port)
}

// closeService schliesst Port und laufende Verbindungen eines Dienstes.
func (s *Sensor) closeService(t *trapService) {
	t.mu.Lock()
	t.closed = true
	list := make([]*trapConn, 0, len(t.active))
	for c := range t.active {
		list = append(list, c)
	}
	t.mu.Unlock()
	if t.srv != nil {
		_ = t.srv.Close()
	}
	if t.ln != nil {
		_ = t.ln.Close()
		s.log.Info("honeypot service closed", "service", t.key.Service, "port", t.key.Port)
	}
	if t.pc != nil {
		_ = t.pc.Close()
		s.log.Info("honeypot service closed", "service", t.key.Service, "port", t.key.Port, "proto", "udp")
	}
	for _, c := range list {
		_ = c.Close()
	}
	s.mu.Lock()
	t.ln, t.srv, t.pc = nil, nil, nil
	s.mu.Unlock()
}

// serveLoop nimmt Verbindungen an und bearbeitet jede in einer eigenen Goroutine (Zahl begrenzt durch die Limits).
func (s *Sensor) serveLoop(tl *trapListener, handle func(*trapConn)) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				tc := c.(*trapConn)
				defer tc.Close()
				defer s.recoverPanic(tl.t.key.Service) // ein Fehler im Parser darf nicht den ganzen Prozess beenden
				handle(tc)
			}()
		}
	}()
}

// serveUDP fuehrt den UDP-Dienst aus; true, wenn er mit einer Panik endete (ein Fehler im Parser darf nicht den
// ganzen Prozess beenden, der Dienst laeuft danach weiter).
func (s *Sensor) serveUDP(t *trapService, p *UDPProto, pc net.PacketConn) (panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("honeypot service failed", "service", t.key.Service, "port", t.key.Port, "proto", "udp", "panic", r)
			panicked = true
		}
	}()
	p.Handle(s, t, pc)
	return false
}

// recoverPanic faengt eine Panik in der Bearbeitung einer Verbindung ab und protokolliert sie (nur per defer nutzen);
// die Verbindung schliesst der Aufrufer.
func (s *Sensor) recoverPanic(service string) {
	if r := recover(); r != nil {
		s.log.Error("honeypot connection failed", "service", service, "panic", r)
	}
}

// sensorListenErr kuerzt den Fehler auf den Kern (z. B. "bind: address already in use").
func sensorListenErr(err error) string {
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

// trapListener prueft jede angenommene Verbindung gegen die Limits und zaehlt sie.
type trapListener struct {
	net.Listener
	s *Sensor
	t *trapService
}

// Accept liefert die naechste zugelassene Verbindung; abgewiesene werden sofort geschlossen. Nur ein geschlossener
// Port beendet die Schleife (voruebergehende Fehler wie EMFILE: kurz warten).
func (l *trapListener) Accept() (net.Conn, error) {
	delay := 5 * time.Millisecond
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			l.t.mu.Lock()
			closed := l.t.closed
			l.t.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil, err
			}
			time.Sleep(delay)
			delay = min(2*delay, time.Second)
			continue
		}
		delay = 5 * time.Millisecond
		if tc := l.s.admit(l.t, c); tc != nil {
			return tc, nil
		}
	}
}

// admit wendet Port-Scan-Erkennung und Limits an.
func (s *Sensor) admit(t *trapService, c net.Conn) *trapConn {
	src, srcPort := sensorAddr(c.RemoteAddr())
	s.scanTouch(t, src)
	if !s.acquire(src) {
		s.counters.Dropped.Add(1)
		_ = c.Close()
		return nil
	}
	s.counters.Connections.Add(1)
	t.conns.Add(1)
	tc := &trapConn{Conn: c, raw: c, s: s, t: t, src: src, srcPort: srcPort}
	switch t.key.Service {
	case SvcSSH:
		tc.left.Store(sensorSSHBudget)
		tc.fp = &sensorFPCap{} // HASSH (sensor_fp.go)
	case SvcTelnet:
		tc.left.Store(sensorTelBudget)
	case SvcHTTP, SvcHTTPS:
		tc.left.Store(sensorWebBudget)
		if t.key.Service == SvcHTTPS {
			tc.fp = &sensorFPCap{} // JA4 (sensor_fp.go)
		}
	default:
		if p := tcpProtos[t.key.Service]; p != nil && p.Budget > 0 {
			tc.left.Store(p.Budget)
		} else {
			tc.left.Store(sensorTCPBudget)
		}
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		_ = tc.Close()
		return nil
	}
	t.active[tc] = struct{}{}
	t.mu.Unlock()
	return tc
}

func (s *Sensor) acquire(src netip.Addr) bool {
	src = sensorLimitKey(src)
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if int64(s.nconns) >= s.total.Load() || int64(s.conns[src]) >= s.perIP.Load() {
		return false
	}
	s.conns[src]++
	s.nconns++
	return true
}

func (s *Sensor) release(src netip.Addr) {
	src = sensorLimitKey(src)
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if n := s.conns[src]; n <= 1 {
		delete(s.conns, src)
	} else {
		s.conns[src] = n - 1
	}
	s.nconns--
}

// sensorLimitKey ist der Schluessel fuer das Limit je Quelle: IPv4 die Adresse, IPv6 das /64 (sonst fuellt ein
// einziger Anschluss mit wechselnden Adressen alle Plaetze).
func sensorLimitKey(a netip.Addr) netip.Addr {
	if a.Is6() && !a.Is4In6() {
		if p, err := a.Prefix(64); err == nil {
			return p.Addr()
		}
	}
	return a
}

// sensorAddr liefert Quelle (IPv4 ohne ::ffff:) und Port.
func sensorAddr(a net.Addr) (netip.Addr, int) {
	if ta, ok := a.(*net.TCPAddr); ok {
		ap := ta.AddrPort()
		return ap.Addr().Unmap(), int(ap.Port())
	}
	if a == nil {
		return netip.Addr{}, 0
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, 0
	}
	return ap.Addr().Unmap(), int(ap.Port())
}

// trapConn ist eine zugelassene Verbindung mit Byte-Budget; Close gibt das Limit frei.
type trapConn struct {
	net.Conn
	raw     net.Conn // die angenommene Verbindung; Conn kann ein TLS-Dienst ersetzen, Close nutzt nur raw (kein Wettlauf)
	s       *Sensor
	t       *trapService
	src     netip.Addr
	srcPort int
	left    atomic.Int64 // noch erlaubte Bytes zum Lesen
	handled atomic.Bool  // HTTP: mindestens eine Anfrage bearbeitet
	once    sync.Once
	fp      *sensorFPCap // Mitschnitt fuer JA4/HASSH (nil = keiner)
	sni     string       // TLS-Dienste (sensor_proto.go): angefragter Name (SNI), "" = keiner
}

func (c *trapConn) Read(p []byte) (int, error) {
	left := c.left.Load()
	if left <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > left {
		p = p[:left]
	}
	n, err := c.Conn.Read(p)
	c.left.Add(-int64(n))
	if c.fp != nil && n > 0 {
		c.fp.feed(p[:n])
	}
	return n, err
}

func (c *trapConn) Close() error {
	var err error
	c.once.Do(func() {
		raw := c.raw
		if raw == nil { // nur in Tests ohne admit
			raw = c.Conn
		}
		err = raw.Close()
		c.t.mu.Lock()
		delete(c.t.active, c)
		c.t.mu.Unlock()
		c.s.release(c.src)
	})
	return err
}

// event liefert ein vorbelegtes Ereignis dieser Verbindung.
func (c *trapConn) event(kind string) Event {
	return Event{Time: time.Now(), Service: c.t.key.Service, Port: c.t.key.Port, Kind: kind, Src: c.src, SrcPort: c.srcPort, Fingerprint: c.fp.get(), Host: c.sni}
}

// emit gibt ein Ereignis an die Sink (gekuerzt, Payload kopiert) und zaehlt es.
func (s *Sensor) emit(e Event) {
	p := s.sink.Load()
	if p == nil || *p == nil {
		return
	}
	s.counters.Events.Add(1)
	(*p)(storeSanitize(e))
}

// login zaehlt einen Login-Versuch und meldet ihn.
func (s *Sensor) login(e Event) {
	s.counters.Logins.Add(1)
	s.emit(e)
}
