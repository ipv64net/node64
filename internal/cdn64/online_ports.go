package cdn64

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/tunnel"
)

// Portmapper Modus 1/2: Ein Stream (Port -> Ziel im Heimnetz) kann ueber einen CDN64-Namen der Node aus dem Internet
// erreichbar sein. Die Node meldet je Protokoll ein Mapping bei ipv64 an (Ziel-Port = Port des Streams); srv07/srv08
// oeffnen dafuer einen Port aus ihrem Bereich und reichen Verbindungen durch den verschluesselten Tunnel (Stream tcp
// bzw. udp). Hier landen sie im Stream wie eine Verbindung auf seinem Port - mit Blocklisten, Grenzen je IP und
// Laendersperre nach der echten Besucher-Adresse. Zu Hause muss dafuer kein Port offen sein.

// tunMaxTCP: hoechstens so viele Verbindungen aus dem Tunnel je Stream (die Server begrenzen je IP und insgesamt,
// das hier schuetzt die Node, wenn viele Adressen gleichzeitig kommen). UDP: udpMaxSessions wie am Port des Streams.
const tunMaxTCP = 4096

// portKey: Stream fuer einen Portmapper-Stream aus dem Tunnel.
type portKey struct {
	udp  bool
	name string // CDN64-Name (klein)
	port int    // Port des Streams (Ziel-Port des Mappings)
}

// onlinePort: ein bei ipv64 angemeldetes Mapping eines Streams.
type onlinePort struct {
	StreamID   int64
	Transport  string // tcp, udp
	Name       string
	RemoteID   int64
	MappingID  int64
	ListenPort int // Port der Server
	TargetPort int // Port des Streams beim Anlegen
}

func (m *Module) onlinePortRows(ctx context.Context) ([]onlinePort, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT stream_id, transport, name, remote_id, mapping_id, listen_port, target_port
		FROM cdn_online_ports ORDER BY stream_id, transport`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []onlinePort
	for rows.Next() {
		var p onlinePort
		if err := rows.Scan(&p.StreamID, &p.Transport, &p.Name, &p.RemoteID, &p.MappingID, &p.ListenPort, &p.TargetPort); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// onlinePortsIndex: Zuordnung fuer eingehende Portmapper-Streams neu einlesen.
func (m *Module) onlinePortsIndex(ctx context.Context) {
	rows, err := m.onlinePortRows(ctx)
	if err != nil {
		return
	}
	idx := make(map[portKey]int64, len(rows))
	for _, p := range rows {
		idx[portKey{udp: p.Transport == "udp", name: strings.ToLower(p.Name), port: p.TargetPort}] = p.StreamID
	}
	m.online.portIdx.Store(&idx)
}

// onlinePortsNow: nach Aenderungen an Streams gleich abgleichen (ohne neuen Stand von ipv64).
func (m *Module) onlinePortsNow(ctx context.Context) {
	if m.online.api == nil {
		return
	}
	m.online.op.Lock()
	defer m.online.op.Unlock()
	m.onlinePortsApply(ctx, nil)
}

// onlinePortsApply gleicht die Mappings mit den Streams ab (m.online.op gehalten): fehlende anmelden, ueberzaehlige
// bzw. geaenderte (Name, Port) austragen. ov = frischer Stand von ipv64: dort fehlende Mappings (z. B. auf der
// Webseite entfernt oder mit dem Namen ausgeschaltet) gelten als weg und werden neu angemeldet.
func (m *Module) onlinePortsApply(ctx context.Context, ov *ipv64api.CDN64Overview) {
	defer m.onlinePortsIndex(ctx)
	rows, err := m.onlinePortRows(ctx)
	if err != nil {
		return
	}
	streams, err := m.streams(ctx)
	if err != nil {
		return
	}
	names := map[string]int64{}
	if list, err := m.onlineNames(ctx); err == nil {
		for _, x := range list {
			names[x.Name] = x.RemoteID
		}
	}
	type key struct {
		id int64
		tr string
	}
	type want struct {
		s   *Stream
		rid int64
	}
	errs := map[int64]string{}
	wants := map[key]want{}
	for _, s := range streams {
		if !s.Enabled || s.OnlineName == "" {
			continue
		}
		rid, ok := names[strings.ToLower(s.OnlineName)]
		if !ok {
			errs[s.ID] = "port_name_off"
			continue
		}
		if s.TCP {
			wants[key{s.ID, "tcp"}] = want{s, rid}
		}
		if s.UDP {
			wants[key{s.ID, "udp"}] = want{s, rid}
		}
	}
	remote := map[int64]map[int64]ipv64api.CDN64Mapping{}
	if ov != nil {
		for _, h := range ov.Hosts {
			mm := map[int64]ipv64api.CDN64Mapping{}
			for _, x := range h.Mappings {
				mm[x.ID] = x
			}
			remote[h.ID] = mm
		}
	}
	a := m.online.api
	ready := a != nil && a.Ready(ctx)
	w := m.core.Writer()
	drop := func(p onlinePort) {
		_, _ = w.ExecContext(ctx, `DELETE FROM cdn_online_ports WHERE stream_id = ? AND transport = ?`, p.StreamID, p.Transport)
	}
	have := map[key]bool{}
	pending := map[key]bool{} // altes Mapping noch nicht ausgetragen: kein neues, sonst ginge seine ID verloren
	for _, p := range rows {
		k := key{p.StreamID, p.Transport}
		x, ok := wants[k]
		_, there := remote[p.RemoteID][p.MappingID]
		gone := ov != nil && !there
		if ok && !gone && x.rid == p.RemoteID && x.s.ListenPort == p.TargetPort && strings.EqualFold(x.s.OnlineName, p.Name) {
			have[k] = true
			continue
		}
		if !gone {
			if !ready {
				pending[k] = true
				continue // spaeter austragen
			}
			if err := a.DeleteMapping(ctx, p.RemoteID, p.MappingID); err != nil && !isNotFound(err) {
				m.log.Warn("cdn64 online: port mapping not removed", "stream", p.StreamID, "port", p.ListenPort, "err", err)
				pending[k] = true
				continue
			}
		}
		drop(p)
	}
	for k, x := range wants {
		if have[k] {
			continue
		}
		if !ready {
			errs[k.id] = "no_api_key"
			continue
		}
		if pending[k] { // beim naechsten Abgleich erst austragen, dann neu anmelden
			continue
		}
		list, err := a.AddMapping(ctx, x.rid, mappingName(x.s), k.tr, x.s.ListenPort)
		if onlineCode(err) == "mapping_exists" { // schon angemeldet (z. B. Eintrag hier verloren): uebernehmen
			if ov2, err2 := a.Overview(ctx); err2 == nil {
				for _, h := range ov2.Hosts {
					if h.ID == x.rid {
						list, err = h.Mappings, nil
					}
				}
			}
		}
		if err != nil {
			errs[k.id] = onlineCode(err)
			continue
		}
		for _, mp := range list {
			if mp.Transport == k.tr && mp.TargetPort == x.s.ListenPort {
				_, _ = w.ExecContext(ctx, `INSERT OR REPLACE INTO cdn_online_ports (stream_id, transport, name, remote_id, mapping_id, listen_port, target_port, created_at)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, k.id, k.tr, strings.ToLower(x.s.OnlineName), x.rid, mp.ID, mp.ListenPort, mp.TargetPort, store.Now())
			}
		}
	}
	m.online.portMu.Lock()
	m.online.portErr = errs
	m.online.portMu.Unlock()
}

func isNotFound(err error) bool {
	var ae *ipv64api.APIError
	return errors.As(err, &ae) && ae.Status == 404
}

// mappingName: Anzeige bei ipv64 (Name des Streams, sonst der Port).
func mappingName(s *Stream) string {
	if n := strings.TrimSpace(s.Name); n != "" {
		if len(n) > 64 {
			n = n[:64]
		}
		return n
	}
	return "Stream " + strconv.Itoa(s.ListenPort)
}

// onlinePortsOf: angemeldete Mappings und Fehler eines Streams (Liste der Streams).
func (m *Module) onlinePortsOf(ctx context.Context) (map[int64][]onlinePort, map[int64]string) {
	out := map[int64][]onlinePort{}
	if rows, err := m.onlinePortRows(ctx); err == nil {
		for _, p := range rows {
			out[p.StreamID] = append(out[p.StreamID], p)
		}
	}
	m.online.portMu.Lock()
	errs := m.online.portErr
	m.online.portMu.Unlock()
	return out, errs
}

// ---------------------------------------------------------------- Verbindungen aus dem Tunnel

// onlinePortStream: Verbindung eines Besuchers aus dem Tunnel (Stream tcp bzw. udp) an den angemeldeten Stream.
func (m *Module) onlinePortStream(c net.Conn, h tunnel.Header) {
	var sid int64
	ok := false
	if idx := m.online.portIdx.Load(); idx != nil {
		sid, ok = (*idx)[portKey{udp: h.Kind == tunnel.KindUDP, name: strings.ToLower(h.Host), port: h.Port}]
	}
	m.smu.Lock()
	r := m.runs[sid]
	m.smu.Unlock()
	if !ok || r == nil {
		_ = c.Close()
		return
	}
	ip := netAddr(c.RemoteAddr())
	where := "cdn64 stream :" + strconv.Itoa(h.Port)
	if m.connBlocked(ip, where) || m.streamGeoBlocked(r, ip, where) { // ipv64-Blocklisten, Sperre, Laender
		_ = c.Close()
		return
	}
	if h.Kind == tunnel.KindUDP {
		if r.tunUDP.Add(1) > udpMaxSessions {
			r.tunUDP.Add(-1)
			_ = c.Close()
			return
		}
		defer r.tunUDP.Add(-1)
		m.streamUDPTunnel(r, c)
		return
	}
	if r.tunTCP.Add(1) > tunMaxTCP {
		r.tunTCP.Add(-1)
		_ = c.Close()
		return
	}
	defer r.tunTCP.Add(-1)
	release, ok := m.connOpen(ip, where) // Limits je IP
	if !ok {
		_ = c.Close()
		return
	}
	if r.tlsc != nil {
		c = tls.Server(c, r.tlsc)
	}
	m.streamPipe(r, c, r.target, release)
}

// streamUDPTunnel: eine UDP-Sitzung eines Besuchers (Datagramme mit Laenge im Stream) mit eigenem Socket zum Ziel;
// nach udpIdle ohne Pakete faellt sie weg.
func (m *Module) streamUDPTunnel(r *streamRun, c net.Conn) {
	up, err := net.Dial("udp", r.target)
	if err != nil {
		_ = c.Close()
		return
	}
	if !r.track(c) || !r.track(up) {
		_ = c.Close()
		_ = up.Close()
		return
	}
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	end := func() { _ = c.Close(); _ = up.Close() }
	defer func() { end(); r.untrack(c); r.untrack(up) }()
	r.stats.conns.Add(1)
	r.stats.active.Add(1)
	defer r.stats.active.Add(-1)
	done := make(chan struct{})
	go func() { // Antworten des Ziels zurueck
		defer close(done)
		defer end()
		b := make([]byte, 64<<10)
		for {
			n, err := up.Read(b)
			if err != nil {
				return
			}
			last.Store(time.Now().UnixNano())
			r.stats.bytesUp.Add(int64(n))
			if bw := r.bw.Load(); bw != nil {
				_ = bwWait(context.Background(), bw.down, n)
			}
			if err := tunnel.WriteDatagram(c, b[:n]); err != nil {
				return
			}
		}
	}()
	go func() { // ruhige Sitzung schliessen
		t := time.NewTicker(udpIdle / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if time.Since(time.Unix(0, last.Load())) > udpIdle {
					end()
					return
				}
			}
		}
	}()
	buf := make([]byte, tunnel.MaxDatagram)
	for {
		n, err := tunnel.ReadDatagram(c, buf)
		if err != nil {
			break
		}
		last.Store(time.Now().UnixNano())
		r.stats.bytesIn.Add(int64(n))
		if bw := r.bw.Load(); bw != nil {
			_ = bwWait(context.Background(), bw.up, n)
		}
		_, _ = up.Write(buf[:n])
	}
	end()
	<-done
}
