package cdn64

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
)

// Streams: ein Port (TCP und/oder UDP) wird roh an ein Ziel weitergereicht, wie die Streams im NPM; bei TCP
// optional mit TLS-Abschluss hier. Jeder Stream belegt seinen Port in der Port-Verwaltung; ein Port, den ein
// anderer Teil schon offen hat, wird nicht geoeffnet und der Grund angezeigt.

const (
	udpIdle        = 60 * time.Second
	udpMaxSessions = 1024
	tcpDialTimeout = 10 * time.Second
)

// Stream ist ein weitergereichter Port.
type Stream struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Enabled    bool      `json:"enabled"`
	ListenPort int       `json:"listen_port"`
	TCP        bool      `json:"tcp"`
	UDP        bool      `json:"udp"`
	TargetHost string    `json:"target_host"`
	TargetPort int       `json:"target_port"`
	TLSCertID  int64     `json:"tls_cert_id"` // TCP: TLS hier beenden mit diesem Zertifikat (0 = nein)
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// CDN64 (Portmapper Modus 1/2): ueber diesen Namen der Node auch aus dem Internet erreichbar ("" = nur hier)
	OnlineName string `json:"online_name,omitempty"`

	// Laendersperre wie bei Hosts (geo.go): "" = aus, block, allow; aendern startet den Stream nicht neu
	GeoMode      string   `json:"geo_mode,omitempty"`
	GeoCountries []string `json:"geo_countries,omitempty"`

	// Bandbreite (bandwidth.go) in Mbit/s, 0 = unbegrenzt; aendern startet den Stream nicht neu
	BWDownMbit int `json:"bw_down_mbit,omitempty"` // zum Besucher
	BWUpMbit   int `json:"bw_up_mbit,omitempty"`   // vom Besucher
}

func (s *Stream) target() string { return net.JoinHostPort(s.TargetHost, strconv.Itoa(s.TargetPort)) }

// key: alles, was einen Neustart des Streams verlangt.
func (s *Stream) key() string {
	return fmt.Sprintf("%d|%v|%v|%s|%d", s.ListenPort, s.TCP, s.UDP, s.target(), s.TLSCertID)
}

func newStream() *Stream { return &Stream{Enabled: true, TCP: true} }

func (s *Stream) normalize() error {
	s.Name = strings.TrimSpace(s.Name)
	if len(s.Name) > 100 {
		return ferr("name", "cdn64.err.stream_name")
	}
	if s.ListenPort < 1 || s.ListenPort > 65535 {
		return ferr("listen_port", "cdn64.err.port")
	}
	if !s.TCP && !s.UDP {
		return ferr("tcp", "cdn64.err.stream_proto")
	}
	t := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s.TargetHost), "["), "]")
	if a, err := netip.ParseAddr(t); err == nil {
		t = a.String()
	} else if nn, err := edge.NormalizeName(t); err == nil && !strings.HasPrefix(nn, "*") {
		t = nn
	} else if !isSingleLabel(t) {
		return ferr("target_host", "cdn64.err.target_host")
	}
	s.TargetHost = strings.ToLower(t)
	if s.TargetPort < 1 || s.TargetPort > 65535 {
		return ferr("target_port", "cdn64.err.port")
	}
	if s.TLSCertID < 0 || (s.TLSCertID > 0 && !s.TCP) {
		return ferr("tls_cert_id", "cdn64.err.stream_tls")
	}
	if s.BWDownMbit < 0 || s.BWDownMbit > bwMaxMbit || s.BWUpMbit < 0 || s.BWUpMbit > bwMaxMbit {
		return ferr("bw", "cdn64.err.bandwidth")
	}
	return normalizeGeo(&s.GeoMode, &s.GeoCountries)
}

// claims: die Ports eines Streams.
func (s *Stream) claims(active map[string]bool) []ports.Claim {
	purpose := "Stream"
	if s.Name != "" {
		purpose += " " + s.Name
	}
	var out []ports.Claim
	if s.TCP {
		out = append(out, ports.Claim{Owner: Name, Purpose: purpose, Proto: ports.TCP, Port: s.ListenPort, Active: active["tcp"]})
	}
	if s.UDP {
		out = append(out, ports.Claim{Owner: Name, Purpose: purpose, Proto: ports.UDP, Port: s.ListenPort, Active: active["udp"]})
	}
	return out
}

// ---------------------------------------------------------------- Datenbank

const streamCols = `id, name, enabled, listen_port, tcp, udp, target_host, target_port, tls_cert_id, created_at, updated_at, geo_mode, geo_countries, online_name,
	bw_down_mbit, bw_up_mbit`

func scanStream(row interface{ Scan(...any) error }) (*Stream, error) {
	var s Stream
	var ca, ua, geo string
	if err := row.Scan(&s.ID, &s.Name, &s.Enabled, &s.ListenPort, &s.TCP, &s.UDP, &s.TargetHost, &s.TargetPort, &s.TLSCertID, &ca, &ua, &s.GeoMode, &geo, &s.OnlineName,
		&s.BWDownMbit, &s.BWUpMbit); err != nil {
		return nil, err
	}
	if geo != "" {
		s.GeoCountries = strings.Split(geo, ",")
	}
	s.CreatedAt, s.UpdatedAt = store.ParseTime(ca), store.ParseTime(ua)
	return &s, nil
}

func (m *Module) streams(ctx context.Context) ([]*Stream, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT `+streamCols+` FROM cdn_streams ORDER BY listen_port`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Stream
	for rows.Next() {
		s, err := scanStream(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (m *Module) stream(ctx context.Context, id int64) (*Stream, error) {
	s, err := scanStream(m.core.Reader().QueryRowContext(ctx, `SELECT `+streamCols+` FROM cdn_streams WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errNotFound
	}
	return s, err
}

func (m *Module) saveStream(ctx context.Context, s *Stream) error {
	if err := s.normalize(); err != nil {
		return err
	}
	if s.TLSCertID > 0 && m.certs != nil {
		if _, err := m.certs.Get(ctx, s.TLSCertID); err != nil {
			return ferr("tls_cert_id", "cdn64.err.cert")
		}
	}
	list, err := m.streams(ctx)
	if err != nil {
		return err
	}
	for _, o := range list {
		if o.ID != s.ID && o.ListenPort == s.ListenPort && ((o.TCP && s.TCP) || (o.UDP && s.UDP)) {
			return &FieldError{Field: "listen_port", Key: "cdn64.err.stream_port_taken", Name: strconv.Itoa(s.ListenPort)}
		}
	}
	if m.edge != nil { // die Ports des gemeinsamen Eingangs bleiben frei, auch wenn er gerade zu ist
		c := m.edge.Config()
		if s.TCP && (s.ListenPort == c.HTTPPort || s.ListenPort == c.HTTPSPort) || s.UDP && c.HTTP3 && s.ListenPort == c.HTTPSPort {
			return &FieldError{Field: "listen_port", Key: "cdn64.err.stream_port_edge", Name: strconv.Itoa(s.ListenPort)}
		}
	}
	now := store.Now()
	w := m.core.Writer()
	args := []any{s.Name, s.Enabled, s.ListenPort, s.TCP, s.UDP, s.TargetHost, s.TargetPort, s.TLSCertID, s.GeoMode, strings.Join(s.GeoCountries, ","), s.OnlineName,
		s.BWDownMbit, s.BWUpMbit}
	if s.ID == 0 {
		res, err := w.ExecContext(ctx, `INSERT INTO cdn_streams (name, enabled, listen_port, tcp, udp, target_host, target_port, tls_cert_id, geo_mode, geo_countries,
			online_name, bw_down_mbit, bw_up_mbit, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, append(args, now, now)...)
		if err != nil {
			return err
		}
		s.ID, _ = res.LastInsertId()
	} else {
		res, err := w.ExecContext(ctx, `UPDATE cdn_streams SET name = ?, enabled = ?, listen_port = ?, tcp = ?, udp = ?, target_host = ?, target_port = ?,
			tls_cert_id = ?, geo_mode = ?, geo_countries = ?, online_name = ?, bw_down_mbit = ?, bw_up_mbit = ?, updated_at = ? WHERE id = ?`, append(args, now, s.ID)...)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return errNotFound
		}
	}
	m.applyStreams(ctx)
	m.onlinePortsNow(ctx)
	m.checkSoon(0) // Ziel gleich pruefen
	return nil
}

func (m *Module) setStreamEnabled(ctx context.Context, id int64, on bool) error {
	res, err := m.core.Writer().ExecContext(ctx, `UPDATE cdn_streams SET enabled = ?, updated_at = ? WHERE id = ?`, on, store.Now(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	m.applyStreams(ctx)
	m.onlinePortsNow(ctx)
	return nil
}

func (m *Module) deleteStream(ctx context.Context, id int64) error {
	res, err := m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_streams WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	m.applyStreams(ctx)
	m.onlinePortsNow(ctx)
	m.sreach.forget(id)
	return nil
}

// ---------------------------------------------------------------- Betrieb

type streamStats struct {
	conns   atomic.Int64 // TCP-Verbindungen bzw. UDP-Sitzungen
	active  atomic.Int64
	bytesIn atomic.Int64 // vom Client
	bytesUp atomic.Int64 // vom Ziel
}

type streamRun struct {
	key    string
	target string       // Ziel host:port (auch fuer Verbindungen aus dem CDN64-Tunnel)
	tlsc   *tls.Config  // TLS hier beenden (nil = nein)
	tunTCP atomic.Int64 // offene Verbindungen aus dem CDN64-Tunnel (Grenze tunMaxTCP)
	tunUDP atomic.Int64 // offene UDP-Sitzungen aus dem CDN64-Tunnel (Grenze udpMaxSessions)
	tcp    net.Listener
	udp    net.PacketConn
	errs   map[string]string // tcp/udp -> Fehler beim Oeffnen
	stats  *streamStats
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup

	geo atomic.Pointer[Stream] // Laendersperre (GeoMode, GeoCountries), bei jedem Abgleich neu gesetzt
	bw  atomic.Pointer[bwPair] // Bandbreite (nil = unbegrenzt), bei jedem Abgleich neu gesetzt
}

// streamGeoBlocked: Laendersperre des Streams; abgewiesen wird mit Statistik wie bei den Blocklisten.
func (m *Module) streamGeoBlocked(r *streamRun, ip netip.Addr, where string) bool {
	s := r.geo.Load()
	if s == nil || !m.geoBlockedBy(s.GeoMode, s.GeoCountries, ip) {
		return false
	}
	m.rejectConn(ip, rejGeo, where)
	return true
}

func (r *streamRun) track(c net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return false
	}
	r.conns[c] = struct{}{}
	return true
}

func (r *streamRun) untrack(c net.Conn) {
	r.mu.Lock()
	delete(r.conns, c)
	r.mu.Unlock()
}

func (r *streamRun) stop() {
	r.mu.Lock()
	r.closed = true
	if r.tcp != nil {
		_ = r.tcp.Close()
	}
	if r.udp != nil {
		_ = r.udp.Close()
	}
	for c := range r.conns {
		_ = c.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}

func (m *Module) streamStatsOf(id int64) *streamStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.sstats[id]
	if st == nil {
		st = &streamStats{}
		m.sstats[id] = st
	}
	return st
}

// applyStreams oeffnet und schliesst Streams nach der Datenbank (nur, solange das Modul laeuft). m.smu wird nur
// kurz gehalten: die Pruefung der Ports fragt andere Teile, und der Eingang fragt dabei ueber die
// Port-Verwaltung die Streams (Claims) ab.
func (m *Module) applyStreams(ctx context.Context) {
	m.sapply.Lock()
	defer m.sapply.Unlock()
	m.mu.Lock()
	on := m.running
	m.mu.Unlock()
	want := map[int64]*Stream{}
	if on {
		list, err := m.streams(ctx)
		if err != nil {
			m.log.Error("streams not readable", "err", err)
			return
		}
		var active []*Stream
		for _, s := range list {
			if s.Enabled {
				want[s.ID] = s
				active = append(active, s)
			}
		}
		m.geoNeedStreams(active)
	}
	ids := make(map[int64]bool, len(want))
	for id := range want {
		ids[id] = true
	}
	m.sbw.keepIDs(ids)
	m.smu.Lock()
	for id, r := range m.runs { // Laendersperre und Bandbreite gelten ohne Neustart
		if s, ok := want[id]; ok {
			r.geo.Store(s)
			r.bw.Store(m.sbw.of(id, s.BWDownMbit, s.BWUpMbit))
		}
	}
	var stop []*streamRun
	type retryRun struct {
		r *streamRun
		s *Stream
	}
	var retry []retryRun
	for id, r := range m.runs {
		if s, ok := want[id]; !ok || s.key() != r.key {
			stop = append(stop, r)
			delete(m.runs, id)
		} else if len(r.errs) > 0 { // Port war belegt: nur das fehlende Protokoll noch einmal versuchen
			retry = append(retry, retryRun{r, s})
		}
	}
	var start []*Stream
	for id, s := range want {
		if _, ok := m.runs[id]; !ok {
			start = append(start, s)
		}
	}
	m.smu.Unlock()
	for _, r := range stop {
		r.stop()
	}
	for _, x := range retry {
		m.openStream(ctx, x.r, x.s)
	}
	for _, s := range start {
		r := m.startStream(ctx, s)
		r.bw.Store(m.sbw.of(s.ID, s.BWDownMbit, s.BWUpMbit))
		m.smu.Lock()
		m.runs[s.ID] = r
		m.smu.Unlock()
	}
}

// startStream oeffnet die Ports eines Streams (Fehler je Protokoll, der Rest laeuft).
func (m *Module) startStream(ctx context.Context, s *Stream) *streamRun {
	r := &streamRun{key: s.key(), target: s.target(), errs: map[string]string{}, stats: m.streamStatsOf(s.ID), conns: map[net.Conn]struct{}{}}
	r.geo.Store(s)
	if s.TLSCertID > 0 && m.certs != nil {
		id := s.TLSCertID
		r.tlsc = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			if c := m.certs.ByID(id); c != nil {
				return c, nil
			}
			return nil, errors.New("certificate not available")
		}}
	}
	m.openStream(ctx, r, s)
	return r
}

// openStream oeffnet die noch nicht offenen Ports eines Streams (m.sapply gehalten). Beim erneuten Versuch (Port
// war belegt) bleiben das offene Protokoll und seine Verbindungen unberuehrt; r.tcp, r.udp und r.errs werden unter
// m.smu gesetzt (Claims, Anzeige).
func (m *Module) openStream(ctx context.Context, r *streamRun, s *Stream) {
	addr := ":" + strconv.Itoa(s.ListenPort)
	check := func(p ports.Proto) error {
		if m.ports == nil {
			return nil
		}
		return m.ports.Check(ctx, Name, []ports.Claim{{Owner: Name, Purpose: "Stream", Proto: p, Port: s.ListenPort, Active: true}})
	}
	errs := map[string]string{}
	var tl net.Listener
	var ul net.PacketConn
	if s.TCP && r.tcp == nil {
		if err := check(ports.TCP); err != nil {
			errs["tcp"] = err.Error()
		} else if ln, err := net.Listen("tcp", addr); err != nil {
			errs["tcp"] = err.Error()
		} else {
			if r.tlsc != nil {
				ln = tls.NewListener(ln, r.tlsc)
			}
			tl = ln
		}
	}
	if s.UDP && r.udp == nil {
		if err := check(ports.UDP); err != nil {
			errs["udp"] = err.Error()
		} else if pc, err := net.ListenPacket("udp", addr); err != nil {
			errs["udp"] = err.Error()
		} else {
			ul = pc
		}
	}
	m.smu.Lock()
	r.errs = errs
	if tl != nil {
		r.tcp = tl
	}
	if ul != nil {
		r.udp = ul
	}
	m.smu.Unlock()
	if tl != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); m.serveTCP(r, s.target()) }()
	}
	if ul != nil {
		r.wg.Add(1)
		go func() { defer r.wg.Done(); m.serveUDP(r, s.target()) }()
	}
	for p, e := range errs {
		m.log.Warn("stream port not opened", "port", s.ListenPort, "proto", p, "err", e)
	}
}

func (m *Module) serveTCP(r *streamRun, target string) {
	for {
		c, err := r.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		_, lport, _ := net.SplitHostPort(c.LocalAddr().String())
		where := "stream :" + lport
		if ip := netAddr(c.RemoteAddr()); m.connBlocked(ip, where) || m.streamGeoBlocked(r, ip, where) { // ipv64-Blocklisten, Sperre, Laender
			_ = c.Close()
			continue
		}
		release, ok := m.connOpen(netAddr(c.RemoteAddr()), where) // Limits je IP
		if !ok {
			_ = c.Close()
			continue
		}
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			m.streamPipe(r, c, target, release)
		}()
	}
}

// streamPipe: eine TCP-Verbindung ans Ziel weiterreichen (vom Port des Streams oder aus dem CDN64-Tunnel).
func (m *Module) streamPipe(r *streamRun, c net.Conn, target string, release func()) {
	if release != nil {
		defer release()
	}
	up, err := net.DialTimeout("tcp", target, tcpDialTimeout)
	if err != nil {
		_ = c.Close()
		return
	}
	if !r.track(c) || !r.track(up) {
		_ = c.Close()
		_ = up.Close()
		return
	}
	r.stats.conns.Add(1)
	r.stats.active.Add(1)
	if bw := r.bw.Load(); bw != nil { // mit Grenze gebremst kopieren (ohne Grenze roh wie bisher)
		c = &bwConn{Conn: c, bw: bw}
	}
	in, out := edge.Pipe(c, up)
	r.stats.active.Add(-1)
	r.stats.bytesIn.Add(in)
	r.stats.bytesUp.Add(out)
	r.untrack(c)
	r.untrack(up)
}

// serveUDP: je Client eine Sitzung mit eigenem Socket zum Ziel; nach 60 s ohne Pakete faellt sie weg.
func (m *Module) serveUDP(r *streamRun, target string) {
	type session struct {
		up   net.Conn
		last atomic.Int64
	}
	var mu sync.Mutex
	sessions := map[string]*session{}
	done := make(chan struct{})
	defer close(done)
	r.wg.Add(1)
	go func() { // aufraeumen
		defer r.wg.Done()
		t := time.NewTicker(udpIdle / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				mu.Lock()
				for k, s := range sessions {
					_ = s.up.Close()
					delete(sessions, k)
				}
				mu.Unlock()
				return
			case <-t.C:
				limit := time.Now().Add(-udpIdle).UnixNano()
				mu.Lock()
				for k, s := range sessions {
					if s.last.Load() < limit {
						_ = s.up.Close()
						delete(sessions, k)
					}
				}
				mu.Unlock()
			}
		}
	}()
	buf := make([]byte, 64<<10)
	for {
		n, addr, err := r.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		key := addr.String()
		mu.Lock()
		s := sessions[key]
		if where := "stream udp " + r.udp.LocalAddr().String()[strings.LastIndex(r.udp.LocalAddr().String(), ":"):]; s == nil &&
			(m.connBlocked(netAddr(addr), where) || m.streamGeoBlocked(r, netAddr(addr), where)) { // ipv64-Blocklisten, Sperre, Laender: keine Sitzung
			mu.Unlock()
			continue
		}
		if s == nil {
			if len(sessions) >= udpMaxSessions {
				mu.Unlock()
				continue
			}
			up, err := net.Dial("udp", target)
			if err != nil {
				mu.Unlock()
				continue
			}
			s = &session{up: up}
			sessions[key] = s
			r.stats.conns.Add(1)
			r.stats.active.Add(1)
			r.wg.Add(1)
			go func(s *session, client net.Addr) { // Antworten des Ziels zurueck
				defer r.wg.Done()
				defer r.stats.active.Add(-1)
				b := make([]byte, 64<<10)
				for {
					k, err := s.up.Read(b)
					if err != nil {
						return
					}
					s.last.Store(time.Now().UnixNano())
					r.stats.bytesUp.Add(int64(k))
					if bw := r.bw.Load(); bw != nil {
						_ = bwWait(context.Background(), bw.down, k) // gebremst: weitere Antworten warten im Socket zum Ziel
					}
					if _, err := r.udp.WriteTo(b[:k], client); err != nil {
						return
					}
				}
			}(s, addr)
		}
		mu.Unlock()
		s.last.Store(time.Now().UnixNano())
		r.stats.bytesIn.Add(int64(n))
		if bw := r.bw.Load(); bw != nil {
			_ = bwWait(context.Background(), bw.up, n) // gebremst: weitere Pakete warten im Puffer des Ports
		}
		_, _ = s.up.Write(buf[:n])
	}
}

// stopStreams schliesst alle Streams (Modul aus).
func (m *Module) stopStreams() {
	m.sapply.Lock()
	defer m.sapply.Unlock()
	m.smu.Lock()
	runs := m.runs
	m.runs = map[int64]*streamRun{}
	m.smu.Unlock()
	for _, r := range runs {
		r.stop()
	}
}

// Claims: Ports der Streams fuer die Port-Verwaltung (nur bei laufendem Modul).
func (m *Module) Claims(ctx context.Context) []ports.Claim {
	m.mu.Lock()
	on := m.running
	m.mu.Unlock()
	if !on {
		return nil
	}
	list, err := m.streams(ctx)
	if err != nil {
		return nil
	}
	m.smu.Lock()
	defer m.smu.Unlock()
	var out []ports.Claim
	for _, s := range list {
		if !s.Enabled {
			continue
		}
		active := map[string]bool{}
		r := m.runs[s.ID]
		if r != nil {
			active["tcp"], active["udp"] = r.tcp != nil, r.udp != nil
		}
		for _, c := range s.claims(active) {
			if r != nil && !c.Active {
				c.Error = r.errs[string(c.Proto)] // z. B. "address already in use" (Anzeige in der Port-Uebersicht)
			}
			out = append(out, c)
		}
	}
	return out
}

// OutboundClaims: Tunnel von CDN64 online zu den Servern fuer die Port-Uebersicht (ausgehend, nur Anzeige: Port
// und Bind sind die Gegenstelle, z. B. 7844/udp bei srv07.cdn64.de). Leer, solange Modul oder Tunnel aus sind.
func (m *Module) OutboundClaims(ctx context.Context) []ports.Claim {
	m.mu.Lock()
	on := m.running
	m.mu.Unlock()
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	if !on || cl == nil {
		return nil
	}
	conf := map[string]int{} // eingestellter Port je Server (solange nicht verbunden)
	if c, _, err := m.onlineConf(ctx); err == nil && c != nil {
		for _, e := range c.Edges {
			conf[e.Name] = e.Port
		}
	}
	var out []ports.Claim
	for _, e := range cl.Status() {
		c := ports.Claim{Owner: Name, Purpose: "CDN64 online " + e.Name, Proto: ports.UDP, Port: conf[e.Name], Bind: e.Host, Active: e.Connected, Error: e.LastError}
		if c.Port == 0 {
			c.Port = 7844 // Standard des Tunnels (tunnel.Client)
		}
		if _, p, err := net.SplitHostPort(e.Addr); err == nil && e.Connected { // verbunden: tatsaechlicher Weg
			if n, err := strconv.Atoi(p); err == nil {
				c.Port = n
			}
			if e.Transport == "tcp" {
				c.Proto = ports.TCP
			}
		}
		out = append(out, c)
	}
	return out
}

// streamErrs: Fehler beim Oeffnen je Stream (Anzeige).
func (m *Module) streamErrs(id int64) map[string]string {
	m.smu.Lock()
	defer m.smu.Unlock()
	if r := m.runs[id]; r != nil && len(r.errs) > 0 {
		out := map[string]string{}
		for k, v := range r.errs {
			out[k] = v
		}
		return out
	}
	return nil
}

// probeStream prueft das Ziel eines TCP-Streams (UDP laesst sich nicht pruefen).
func (m *Module) probeStream(ctx context.Context, s *Stream) Reach {
	if !s.TCP {
		return Reach{State: ReachUnknown}
	}
	cctx, cancel := context.WithTimeout(ctx, reachTimeout)
	defer cancel()
	start := time.Now()
	c, err := (&net.Dialer{}).DialContext(cctx, "tcp", s.target())
	if err != nil {
		return Reach{State: ReachDown, Error: shortErr(err), Checked: time.Now()}
	}
	_ = c.Close()
	d := time.Since(start)
	st := Reach{State: ReachUp, Ms: d.Milliseconds(), Checked: time.Now()}
	if d > reachSlow {
		st.State = ReachSlow
	}
	return st
}
