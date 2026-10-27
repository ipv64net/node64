package cdnedge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/tunnel"
)

// Steuerung von ipv64 (Abschnitt 8.4 der Planung): Konfiguration alle 10 s holen (ETag, unveraendert = 304),
// zwischenspeichern (faellt ipv64 aus, laeuft alles mit dem letzten Stand weiter), jede Minute Traffic melden.

// apiConfig ist die Antwort von GET /cdn64o/edge/config.
type apiConfig struct {
	Version   string         `json:"version"`
	Tunnels   []apiTunnel    `json:"tunnels"`
	Hosts     []apiHost      `json:"hosts"`
	Bandwidth map[string]int `json:"bandwidth_mbit"` // Account -> Mbit/s
	Edges     []struct {
		Name string   `json:"name"`
		IPs  []string `json:"ips"`
	} `json:"edges"` // die Server selbst (nie Ziel in Modus 3)
}

type apiTunnel struct {
	ID          string `json:"id"`
	TokenSHA256 string `json:"token_sha256"`
	UserID      int    `json:"userid"`
	Blocked     bool   `json:"blocked"`
	Sessions    int    `json:"sessions"` // parallele Verbindungen der Klasse (Business/Company; 0 = eine)
}

type apiHost struct {
	ID       int          `json:"id"`
	Name     string       `json:"name"`
	Wildcard bool         `json:"wildcard"`
	Mode     int          `json:"mode"`
	UserID   int          `json:"userid"`
	Tunnels  []string     `json:"tunnels"`
	Blocked  string       `json:"blocked"`
	Target   *apiTarget   `json:"target,omitempty"`   // Modus 3
	ACL      *apiACL      `json:"acl,omitempty"`      // Erlauben-/Sperrliste (alle Modi)
	Mappings []apiMapping `json:"mappings,omitempty"` // Portmapper (Modus 3 direkt, Modus 1/2 durch den Tunnel)
	WAF      *bool        `json:"waf,omitempty"`      // Muster-WAF in Modus 2/3 (fehlt = an)
	JA4      string       `json:"ja4,omitempty"`      // off | count | block (fehlt = count)
}

type apiState struct {
	mu      sync.Mutex
	etag    string
	lastOK  time.Time
	lastErr string
	sent    map[string][repN]int64 // je Name zuletzt gemeldet (hostStat.counters)
	client  *http.Client
}

func (s *Server) apiCachePath() string { return filepath.Join(s.cfg.DataDir, "config.json") }

// apiLoop: beim Start den Zwischenspeicher, dann alle 10 s von ipv64; Meldungen jede Minute.
func (s *Server) apiLoop(ctx context.Context) {
	if s.cfg.APIURL == "" {
		return
	}
	if b, err := os.ReadFile(s.apiCachePath()); err == nil {
		var c apiConfig
		if json.Unmarshal(b, &c) == nil {
			s.applyConfig(&c)
			s.log.Info("config from cache", "version", c.Version, "hosts", len(c.Hosts))
		}
	}
	fetch := time.NewTicker(10 * time.Second)
	report := time.NewTicker(time.Minute)
	defer fetch.Stop()
	defer report.Stop()
	s.apiFetch(ctx)
	for {
		select {
		case <-ctx.Done():
			s.apiReport(context.Background()) // letzte Zaehler noch melden
			return
		case <-fetch.C:
			s.apiFetch(ctx)
		case <-report.C:
			s.apiReport(ctx)
		}
	}
}

func (s *Server) apiRequest(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimSuffix(s.cfg.APIURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.cfg.APISecret)
	req.Header.Set("User-Agent", "cdn64-edge/"+s.version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	s.apist.mu.Lock()
	if method == http.MethodGet && path == "/cdn64o/edge/config" && s.apist.etag != "" {
		req.Header.Set("If-None-Match", s.apist.etag)
	}
	s.apist.mu.Unlock()
	return s.apist.client.Do(req)
}

func (s *Server) apiFail(err error) {
	s.mx.apiErr.Add(1)
	s.apist.mu.Lock()
	first := s.apist.lastErr == ""
	s.apist.lastErr = err.Error()
	s.apist.mu.Unlock()
	if first {
		s.log.Warn("ipv64 api", "err", err)
	}
}

func (s *Server) apiFetch(ctx context.Context) {
	resp, err := s.apiRequest(ctx, http.MethodGet, "/cdn64o/edge/config", nil)
	if err != nil {
		s.apiFail(err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		s.apiOK()
		return
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		s.apiFail(fmt.Errorf("config: http %d %s", resp.StatusCode, strings.TrimSpace(string(b))))
		return
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		s.apiFail(err)
		return
	}
	var env struct {
		Data apiConfig `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		s.apiFail(fmt.Errorf("config: %w", err))
		return
	}
	s.applyConfig(&env.Data)
	s.apist.mu.Lock()
	s.apist.etag = resp.Header.Get("ETag")
	s.apist.mu.Unlock()
	if b, err := json.Marshal(env.Data); err == nil {
		tmp := s.apiCachePath() + ".tmp"
		if os.WriteFile(tmp, b, 0o640) == nil {
			_ = os.Rename(tmp, s.apiCachePath())
		}
	}
	s.apiOK()
	s.log.Info("config updated", "version", env.Data.Version, "hosts", len(env.Data.Hosts), "tunnels", len(env.Data.Tunnels))
}

func (s *Server) apiOK() {
	s.apist.mu.Lock()
	if s.apist.lastErr != "" {
		s.log.Info("ipv64 api reachable again")
	}
	s.apist.lastOK, s.apist.lastErr = time.Now(), ""
	s.apist.mu.Unlock()
}

// applyConfig: Namen, Tunnels und Bandbreiten uebernehmen; Tunnels, die es nicht mehr gibt oder die gesperrt
// sind, werden getrennt.
func (s *Server) applyConfig(c *apiConfig) {
	s.apiCfg.Store(c)
	rs := newRoutes(s.cfg.Hosts, c)
	s.routes.Store(rs)
	s.forgetGone(rs)
	if n := s.recheckLive(); n > 0 { // gesperrt, entfernt, Liste geaendert: laufende Verbindungen trennen
		s.log.Info("connections closed after config change", "count", n)
	}
	s.pm.apply(c)
	s.certs.kickLoop() // neue Modus-2-Namen: Zertifikat bald
	bw := map[int]int{}
	for k, v := range c.Bandwidth {
		if uid, err := strconv.Atoi(k); err == nil {
			bw[uid] = v
		}
	}
	s.bw.setLimits(bw)
	s.mu.Lock()
	var drop []*tunnel.Peer
	for id, list := range s.peers {
		if !s.tunnelAllowed(id) {
			drop = append(drop, list...)
		}
	}
	s.mu.Unlock()
	for _, p := range drop {
		s.log.Info("tunnel removed or blocked, disconnecting", "tunnel", p.Tunnel)
		_ = p.Session.Close("tunnel removed")
	}
}

// forgetGone vergisst die Zaehler von Namen, die es nicht mehr gibt (bei ipv64 geloescht, z. B. verwaiste Tunnel
// aufgeraeumt) - sonst stuenden sie bis zum Neustart in /health und den Metriken. Ihr letzter, noch nicht gemeldeter
// Traffic faellt weg; den Host gibt es bei ipv64 ja nicht mehr.
func (s *Server) forgetGone(rs *routes) {
	keep := map[string]bool{}
	for _, e := range rs.exact {
		keep[e.Name] = true
	}
	for _, e := range rs.wild {
		keep[e.Name] = true
	}
	gone := map[*hostStat]bool{}
	s.stats.mu.Lock()
	s.apist.mu.Lock()
	for n, st := range s.stats.m {
		if !keep[n] {
			gone[st] = true // mit ihm die gesperrten IPs und JA4-Treffer seit der letzten Meldung
			delete(s.stats.m, n)
			delete(s.apist.sent, n)
		}
	}
	s.apist.mu.Unlock()
	s.stats.mu.Unlock()
	if len(gone) > 0 { // Ueberlast nicht mehr bei vergessenen Namen zaehlen
		s.guard.forget(gone)
	}
}

// tunnelAllowed: Tunnel ist in der festen Konfiguration oder bei ipv64 (nicht gesperrt).
func (s *Server) tunnelAllowed(id string) bool {
	for _, t := range s.cfg.Tunnels {
		if t.ID == id {
			return true
		}
	}
	if c := s.apiCfg.Load(); c != nil {
		for _, t := range c.Tunnels {
			if t.ID == id {
				return !t.Blocked
			}
		}
	}
	return false
}

// apiReport: Traffic seit der letzten Meldung je Host und die verbundenen Tunnels. Scheitert die Meldung, wird
// beim naechsten Mal die ganze Differenz gemeldet (nichts geht verloren, solange der Dienst laeuft).
func (s *Server) apiReport(ctx context.Context) {
	type traffic struct {
		HostID   int   `json:"host_id"`
		BytesIn  int64 `json:"bytes_in"`
		BytesOut int64 `json:"bytes_out"`
		Conns    int64 `json:"conns"`
		Requests int64 `json:"requests,omitempty"` // Modus 2
		Rejected int64 `json:"rejected,omitempty"` // Modus 2: Anfrage-Limit
		// Schutz (0.19.0): Differenzen bzw. Werte des Intervalls
		BlockedList  int64      `json:"blocked_list,omitempty"`
		BlockedACL   int64      `json:"blocked_acl,omitempty"`
		BlockedFlood int64      `json:"blocked_flood,omitempty"`
		BlockedWAF   int64      `json:"blocked_waf,omitempty"`
		BlockedJA4   int64      `json:"blocked_ja4,omitempty"`
		JA4Hits      int64      `json:"ja4_hits,omitempty"`
		BlockedIPs   int64      `json:"blocked_ips,omitempty"` // verschiedene gesperrte IPs (IPv6 je /64)
		ConnsV4      int64      `json:"conns_v4,omitempty"`
		JA4Top       []ja4Entry `json:"ja4_top,omitempty"`
	}
	type sets struct {
		st  *hostStat
		ips map[netip.Addr]struct{}
		ja4 map[string]int64
	}
	type tun struct {
		ID          string `json:"id"`
		Node        string `json:"node,omitempty"`
		NodeVersion string `json:"node_version,omitempty"`
		Transport   string `json:"transport"`
		Since       string `json:"since"`
	}
	ids := map[string]int{}
	for _, e := range s.routes.Load().exact {
		if e.HostID > 0 {
			ids[e.Name] = e.HostID
		}
	}
	now := map[string][repN]int64{}
	var list []traffic
	var taken []sets // gesperrte IPs und JA4-Treffer: bei einem Fehler zurueck (naechste Meldung)
	ok := false
	defer func() {
		if !ok {
			for _, x := range taken {
				x.st.putSets(x.ips, x.ja4)
			}
		}
	}()
	s.stats.mu.Lock()
	s.apist.mu.Lock()
	for name, st := range s.stats.m {
		id := ids[name]
		if id == 0 {
			continue
		}
		cur := st.counters()
		last := s.apist.sent[name]
		var d [repN]int64
		for i := range cur {
			d[i] = cur[i] - last[i]
		}
		ips, ja4 := st.takeSets()
		if len(ips) > 0 || len(ja4) > 0 {
			taken = append(taken, sets{st, ips, ja4})
		}
		if d != [repN]int64{} || len(ips) > 0 || len(ja4) > 0 {
			list = append(list, traffic{HostID: id, BytesIn: d[0], BytesOut: d[1], Conns: d[2], Requests: d[3], Rejected: d[4],
				BlockedList: d[5], BlockedACL: d[6], BlockedFlood: d[7], BlockedWAF: d[8], BlockedJA4: d[9], JA4Hits: d[10],
				ConnsV4: d[11], BlockedIPs: int64(len(ips)), JA4Top: ja4Top(ja4)})
		}
		now[name] = cur
	}
	s.apist.mu.Unlock()
	s.stats.mu.Unlock()
	var tl []tun
	s.mu.Lock()
	for id, ps := range s.peers {
		for _, p := range ps {
			tl = append(tl, tun{ID: id, Node: p.Node, NodeVersion: p.Version, Transport: p.Session.Transport(), Since: p.Since.UTC().Format(time.RFC3339)})
		}
	}
	s.mu.Unlock()
	b, _ := json.Marshal(map[string]any{"version": s.version, "tunnels": tl, "traffic": list})
	resp, err := s.apiRequest(ctx, http.MethodPost, "/cdn64o/edge/report", b)
	if err != nil {
		s.apiFail(err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		s.apiFail(fmt.Errorf("report: http %d", resp.StatusCode))
		return
	}
	var out struct {
		Data struct {
			Changed int `json:"changed"`
		} `json:"data"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	ok = true
	s.apist.mu.Lock()
	for k, v := range now {
		s.apist.sent[k] = v
	}
	s.apist.mu.Unlock()
	if out.Data.Changed > 0 { // Sperren geaendert: gleich neu holen
		s.apiFetch(ctx)
	}
}

// ---------------------------------------------------------------- Raten mit dem Nachbarn (Bandbreite)

// rateLoop schickt dem Nachbarn jede Sekunde die eigenen Raten der Accounts mit Limit (nur wenn es welche gibt).
func (s *Server) rateLoop(ctx context.Context) {
	if len(s.cfg.Peers) == 0 || s.cfg.PeerSecret == "" {
		return
	}
	var conn net.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		r := s.bw.rates() // auch leer jede Sekunde: der Nachbar sieht so, dass dieser Server da ist (peer_up)
		if conn == nil {
			p := s.cfg.Peers[0]
			h, _, _ := net.SplitHostPort(p.Addr)
			d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 3 * time.Second}, Config: &tls.Config{ServerName: h, RootCAs: s.peerRoots, MinVersion: tls.VersionTLS13}}
			c, err := d.DialContext(ctx, "tcp", p.Addr)
			if err != nil {
				continue
			}
			hb, _ := json.Marshal(peerHello{Secret: s.cfg.PeerSecret, Kind: "rates", From: s.cfg.Name})
			if _, err := c.Write(append(hb, '\n')); err != nil {
				c.Close()
				continue
			}
			conn = c
		}
		m := map[string]float64{}
		for uid, v := range r {
			m[strconv.Itoa(uid)] = v
		}
		b, _ := json.Marshal(m)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(append(b, '\n')); err != nil {
			conn.Close()
			conn = nil
		}
	}
}

// readRates: Raten vom Nachbarn (eine JSON-Zeile je Sekunde), bis die Verbindung endet.
func (s *Server) readRates(r *bufio.Reader) {
	for {
		line, err := r.ReadSlice('\n')
		if err != nil {
			return
		}
		var m map[string]float64
		if json.Unmarshal(line, &m) != nil {
			return
		}
		out := map[int]float64{}
		for k, v := range m {
			if uid, err := strconv.Atoi(k); err == nil {
				out[uid] = v
			}
		}
		s.bw.setPeer(out)
	}
}
