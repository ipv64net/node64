package cdnedge

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/metrics"
)

// Prometheus-Schnittstelle (nur fuer den Betreiber): eigener Port metrics_listen, nur fuer die Adressen in
// metrics_allow und nur mit dem Bearer-Token aus metrics_token_file (fehlt die Datei, wird ein Token erzeugt und mit
// 0600 abgelegt). Ohne metrics_allow bleibt der Port zu. Inhalt: Zustand des Dienstes, Tunnel, Namen je Modus,
// Verkehr gesamt und je Account (je Name hoechstens metricsMaxHosts), Schutz, Drossel, Zertifikate, Steuerung von
// ipv64, Nachbar, Portmapper. Doku: docs/CDN64-EDGE-PROMETHEUS.md.

const metricsMaxHosts = 200 // Namen mit eigenen Zeilen (nach Verkehr), der Rest nur je Account

// edgeCounters: Zaehler, die nur fuer Prometheus gefuehrt werden (seit dem Start).
type edgeCounters struct {
	req     [4][6][4]atomic.Int64 // Modus 2/3 x Statusklasse 1xx-5xx (0 = abgebrochen) x HTTP 1/2/3
	termRej [len(termRejReasons)]atomic.Int64
	certOK  [2]atomic.Int64 // je CA (0 Let's Encrypt, 1 ZeroSSL)
	certErr [2]atomic.Int64
	apiErr  atomic.Int64
}

// Abweisungen von Anfragen in Modus 2/3 (terminate.go).
var termRejReasons = [...]string{"misdirected", "req_rate", "acl", "blocked", "blocklist", "waf"}

func termRejIndex(why string) int {
	for i, r := range termRejReasons {
		if r == why {
			return i
		}
	}
	return -1
}

func (c *edgeCounters) termReject(why string) {
	if i := termRejIndex(why); i >= 0 {
		c.termRej[i].Add(1)
	}
}

func caIndex(ca string) int {
	if ca == caZeroSSL {
		return 1
	}
	return 0
}

// countRequest: beantwortete Anfrage in Modus 2/3.
func (c *edgeCounters) countRequest(mode, status, proto int) {
	if mode < 2 || mode > 3 {
		return
	}
	cl := status / 100
	if cl < 1 || cl > 5 {
		cl = 0
	}
	if proto < 1 || proto > 3 {
		proto = 1
	}
	c.req[mode][cl][proto].Add(1)
}

// statusRec merkt sich den Status der Antwort (Unwrap fuer http.ResponseController: Flush, Hijack bei WebSocket).
type statusRec struct {
	http.ResponseWriter
	status int
}

func (w *statusRec) WriteHeader(code int) {
	if w.status == 0 && (code < 100 || code >= 200 || code == http.StatusSwitchingProtocols) { // 1xx davor zaehlt nicht
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusRec) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusRec) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusRec) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ---------------------------------------------------------------- Zugang

type metricsAuth struct {
	allow []netip.Prefix
	token string
}

func parseAllow(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, errors.New("metrics_allow: " + s + " is not an IP address or network")
		}
		out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
	}
	return out, nil
}

// metricsToken liest das Token oder legt es an (32 Byte, hex, Datei 0600).
func metricsToken(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); len(t) >= 32 {
			return t, nil
		}
		return "", errors.New("metrics token file " + path + " is too short (at least 32 characters)")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	t := hex.EncodeToString(raw)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}

func (a *metricsAuth) ok(r *http.Request) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip, allowed := ap.Addr().Unmap(), false
	for _, p := range a.allow {
		allowed = allowed || p.Contains(ip)
	}
	h := r.Header.Get("Authorization")
	tok, okPrefix := strings.CutPrefix(h, "Bearer ")
	return allowed && okPrefix && subtle.ConstantTimeCompare([]byte(strings.TrimSpace(tok)), []byte(a.token)) == 1
}

// startMetrics oeffnet den Port (nur mit metrics_listen und metrics_allow).
func (s *Server) startMetrics() error {
	if s.cfg.MetricsListen == "" || len(s.cfg.MetricsAllow) == 0 {
		return nil
	}
	allow, err := parseAllow(s.cfg.MetricsAllow)
	if err != nil {
		return err
	}
	tok, err := metricsToken(s.cfg.MetricsTokenFile)
	if err != nil {
		return err
	}
	auth := &metricsAuth{allow: allow, token: tok}
	ln, err := net.Listen("tcp", s.cfg.MetricsListen)
	if err != nil {
		return err
	}
	s.lns = append(s.lns, ln)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		if !auth.ok(r) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mw := metrics.New()
		s.writeMetrics(r.Context(), mw)
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = mw.WriteTo(w)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { http.Error(w, "forbidden", http.StatusForbidden) })
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10}
	// fremde Adressen gleich beim Annehmen trennen (die Firewall laesst sie ohnehin nicht durch)
	go func() { _ = srv.Serve(&allowListener{Listener: ln, allow: allow}) }()
	s.log.Info("metrics listening", "addr", ln.Addr().String(), "allow", len(allow))
	return nil
}

type allowListener struct {
	net.Listener
	allow []netip.Prefix
}

func (l *allowListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := addrOf(c.RemoteAddr())
		for _, p := range l.allow {
			if p.Contains(ip) {
				return c, nil
			}
		}
		_ = c.Close()
	}
}

// ---------------------------------------------------------------- Inhalt

type accTraffic struct {
	in, out, conns int64
	hosts          int
}

func (s *Server) writeMetrics(_ context.Context, w *metrics.Writer) {
	srv := []string{"server", s.cfg.Name}
	lbl := func(kv ...string) []string { return append(append([]string{}, srv...), kv...) }

	// Dienst
	w.Gauge("cdn64_edge_info", "Version and location (always 1)", 1, lbl("version", s.version, "location", s.cfg.Location, "go", runtime.Version())...)
	w.Gauge("cdn64_edge_start_time_seconds", "Start of the service (Unix time)", float64(s.started.Unix()), srv...)
	w.Gauge("cdn64_edge_goroutines", "Goroutines", float64(runtime.NumGoroutine()), srv...)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	w.Gauge("cdn64_edge_memory_heap_bytes", "Heap in use", float64(ms.HeapInuse), srv...)
	w.Gauge("cdn64_edge_memory_sys_bytes", "Memory from the operating system", float64(ms.Sys), srv...)

	// Tunnel der Nodes
	byTransport := map[string]int{}
	s.mu.Lock()
	ids := len(s.peers)
	for _, l := range s.peers {
		for _, p := range l {
			byTransport[p.Session.Transport()]++
		}
	}
	s.mu.Unlock()
	w.Gauge("cdn64_edge_tunnels", "Tunnels with at least one connection", float64(ids), srv...)
	for _, t := range []string{"quic", "tcp"} { // tcp = Ausweichweg (TLS ueber TCP, auch Port 443)
		if _, ok := byTransport[t]; !ok {
			byTransport[t] = 0
		}
	}
	keys := make([]string, 0, len(byTransport))
	for k := range byTransport {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, t := range keys {
		w.Gauge("cdn64_edge_tunnel_connections", "Tunnel connections by transport", float64(byTransport[t]), lbl("transport", t)...)
	}
	w.Gauge("cdn64_edge_streams", "Open visitor streams through tunnels", float64(s.streams.Load()), srv...)
	w.Counter("cdn64_edge_streams_total", "Visitor streams since start", float64(s.total.Load()), srv...)

	// Namen je Modus, Accounts, Sperren
	rs := s.routes.Load()
	modes, blocked := map[int]int{1: 0, 2: 0, 3: 0}, map[string]int{}
	type hostRow struct {
		name    string
		mode    int
		account int
	}
	hosts := map[string]hostRow{}
	accounts := map[int]bool{}
	if rs != nil {
		for _, e := range rs.exact {
			if _, seen := hosts[e.Name]; seen {
				continue
			}
			hosts[e.Name] = hostRow{e.Name, e.Mode, e.UserID}
			modes[e.Mode]++
			accounts[e.UserID] = true
			if e.Blocked != "" {
				blocked[e.Blocked]++
			}
		}
	}
	for _, md := range []int{1, 2, 3} {
		w.Gauge("cdn64_edge_hosts", "Names switched on by mode", float64(modes[md]), lbl("mode", strconv.Itoa(md))...)
	}
	w.Gauge("cdn64_edge_accounts", "Accounts with at least one name", float64(len(accounts)), srv...)
	if _, ok := blocked["traffic"]; !ok {
		blocked["traffic"] = 0
	}
	for why, n := range blocked {
		w.Gauge("cdn64_edge_hosts_blocked", "Names blocked by ipv64 (e.g. traffic used up) by reason", float64(n), lbl("reason", why)...)
	}

	// Verkehr: gesamt, je Account, je Name (die groessten metricsMaxHosts)
	type hostTraffic struct {
		hostRow
		in, out, conns, via, noTun, reqs, rej int64
	}
	var list []hostTraffic
	s.stats.mu.Lock()
	for n, st := range s.stats.m {
		row, ok := hosts[n]
		if !ok {
			row = hostRow{name: n}
		}
		list = append(list, hostTraffic{hostRow: row, in: st.BytesIn.Load(), out: st.BytesOut.Load(), conns: st.Conns.Load(), via: st.ViaPeer.Load(),
			noTun: st.NoTunnel.Load(), reqs: st.Requests.Load(), rej: st.Rejected.Load()})
	}
	s.stats.mu.Unlock()
	var tin, tout, tconns, tvia, tnotun int64
	acc := map[int]*accTraffic{}
	for _, h := range list {
		tin, tout, tconns, tvia, tnotun = tin+h.in, tout+h.out, tconns+h.conns, tvia+h.via, tnotun+h.noTun
		a := acc[h.account]
		if a == nil {
			a = &accTraffic{}
			acc[h.account] = a
		}
		a.in, a.out, a.conns, a.hosts = a.in+h.in, a.out+h.out, a.conns+h.conns, a.hosts+1
	}
	w.Counter("cdn64_edge_bytes_total", "Bytes since start (in = visitor to node, out = node to visitor)", float64(tin), lbl("direction", "in")...)
	w.Counter("cdn64_edge_bytes_total", "Bytes since start (in = visitor to node, out = node to visitor)", float64(tout), lbl("direction", "out")...)
	w.Counter("cdn64_edge_connections_total", "Visitor connections since start", float64(tconns), srv...)
	w.Counter("cdn64_edge_via_peer_total", "Visitor connections handed to the neighbour server since start", float64(tvia), srv...)
	w.Counter("cdn64_edge_no_tunnel_total", "Visitor connections without a tunnel here or at the neighbour since start", float64(tnotun), srv...)
	accIDs := make([]int, 0, len(acc))
	for id := range acc {
		accIDs = append(accIDs, id)
	}
	sort.Ints(accIDs)
	for _, id := range accIDs {
		a, l := acc[id], lbl("account_id", strconv.Itoa(id))
		w.Counter("cdn64_edge_account_bytes_total", "Bytes since start by account", float64(a.in), append(l, "direction", "in")...)
		w.Counter("cdn64_edge_account_bytes_total", "Bytes since start by account", float64(a.out), append(l, "direction", "out")...)
		w.Counter("cdn64_edge_account_connections_total", "Visitor connections since start by account", float64(a.conns), l...)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].in+list[i].out > list[j].in+list[j].out })
	for i, h := range list {
		if i >= metricsMaxHosts {
			break
		}
		l := lbl("host", h.name, "mode", strconv.Itoa(h.mode), "account_id", strconv.Itoa(h.account))
		w.Counter("cdn64_edge_host_bytes_total", "Bytes since start by name (largest names only)", float64(h.in), append(l, "direction", "in")...)
		w.Counter("cdn64_edge_host_bytes_total", "Bytes since start by name (largest names only)", float64(h.out), append(l, "direction", "out")...)
		w.Counter("cdn64_edge_host_connections_total", "Visitor connections since start by name (largest names only)", float64(h.conns), l...)
		if h.reqs > 0 {
			w.Counter("cdn64_edge_host_requests_total", "Requests (mode 2/3) since start by name (largest names only)", float64(h.reqs), l...)
		}
	}
	w.Gauge("cdn64_edge_hosts_with_traffic", "Names with traffic since start (rows above are capped)", float64(len(list)), srv...)

	// Anfragen Modus 2/3 je Status und HTTP-Version
	classes := []string{"aborted", "1xx", "2xx", "3xx", "4xx", "5xx"}
	for md := 2; md <= 3; md++ {
		for cl := 0; cl < 6; cl++ {
			for p := 1; p <= 3; p++ {
				if n := s.mx.req[md][cl][p].Load(); n > 0 {
					w.Counter("cdn64_edge_requests_total", "Requests answered here (mode 2/3) by status class and HTTP version", float64(n),
						lbl("mode", strconv.Itoa(md), "status", classes[cl], "http", strconv.Itoa(p))...)
				}
			}
		}
	}
	for i, why := range termRejReasons {
		w.Counter("cdn64_edge_requests_rejected_total", "Requests rejected (mode 2/3) by reason", float64(s.mx.termRej[i].Load()), lbl("reason", why)...)
	}

	// Schutz
	w.Gauge("cdn64_edge_connections_open", "Open visitor connections", float64(s.guard.open.Load()), srv...)
	w.Gauge("cdn64_edge_connections_tracked", "Long-lived connections checked again after each config change", float64(s.liveCount()), srv...)
	for i, why := range guardReasons {
		w.Counter("cdn64_edge_guard_rejected_total", "Visitor connections rejected by the shield by reason", float64(s.guard.rej[i].Load()), lbl("reason", why)...)
	}
	w.Gauge("cdn64_edge_blocklist_entries", "Entries of the server blocklists", float64(s.guard.set.Load().Total()), srv...)
	if qd := s.qd.Load(); qd != nil {
		w.Gauge("cdn64_edge_quic_passthrough", "QUIC visitors passed through to nodes (mode 1, HTTP/3)", float64(qd.open()), srv...)
	}

	// Drossel
	load, capacity, throttled := s.bw.fairStatus()
	w.Gauge("cdn64_edge_load_mbit", "Throughput right now (all accounts)", load, srv...)
	w.Gauge("cdn64_edge_capacity_mbit", "Capacity for the fair throttle (0 = off)", capacity, srv...)
	w.Gauge("cdn64_edge_throttled_accounts", "Accounts throttled by the fair throttle right now", float64(len(throttled)), srv...)
	for id, mb := range throttled {
		w.Gauge("cdn64_edge_account_throttle_mbit", "Fair throttle per account (Mbit/s)", mb, lbl("account_id", strconv.Itoa(id))...)
	}
	for id, r := range s.bw.rates() {
		w.Gauge("cdn64_edge_account_rate_mbit", "Throughput of accounts with a class limit right now (Mbit/s)", r*8/1e6, lbl("account_id", strconv.Itoa(id))...)
	}

	// Zertifikate (Modus 2/3)
	certs := s.certs.list()
	w.Gauge("cdn64_edge_certificates", "Certificates for mode 2/3 names", float64(len(certs)), srv...)
	if len(certs) > 0 {
		minDays := -1.0
		for _, na := range certs {
			d := time.Until(na).Hours() / 24
			if minDays < 0 || d < minDays {
				minDays = d
			}
		}
		w.Gauge("cdn64_edge_certificate_min_days", "Days until the first certificate expires", minDays, srv...)
	}
	for i, ca := range []string{caLE, caZeroSSL} {
		w.Counter("cdn64_edge_certificate_orders_total", "Certificate orders since start by CA and result", float64(s.mx.certOK[i].Load()), lbl("ca", ca, "result", "ok")...)
		w.Counter("cdn64_edge_certificate_orders_total", "Certificate orders since start by CA and result", float64(s.mx.certErr[i].Load()), lbl("ca", ca, "result", "error")...)
	}
	ci := s.caInfo()
	for d, n := range ci.LEWeek {
		w.Gauge("cdn64_edge_letsencrypt_week", "New Let's Encrypt certificates in 7 days by registered domain (limit 50)", float64(n), lbl("domain", d)...)
	}
	w.Gauge("cdn64_edge_letsencrypt_cooldown", "Domains going to ZeroSSL right now (rate limit)", float64(len(ci.Cooldown)), srv...)

	// Steuerung von ipv64
	if s.cfg.APIURL != "" {
		ver, nh := "", 0
		if c := s.apiCfg.Load(); c != nil {
			ver, nh = c.Version, len(c.Hosts)
		}
		s.apist.mu.Lock()
		last, lastErr := s.apist.lastOK, s.apist.lastErr
		s.apist.mu.Unlock()
		if !last.IsZero() {
			w.Gauge("cdn64_edge_config_age_seconds", "Seconds since the last successful config fetch from ipv64", time.Since(last).Seconds(), srv...)
		}
		w.Gauge("cdn64_edge_config_ok", "1 last request to ipv64 ok, 0 error", metrics.Bool(lastErr == ""), srv...)
		w.Counter("cdn64_edge_config_errors_total", "Failed requests to ipv64 since start", float64(s.mx.apiErr.Load()), srv...)
		w.Gauge("cdn64_edge_config_info", "Config version from ipv64 (always 1)", 1, lbl("version", ver, "hosts", strconv.Itoa(nh))...)
	}

	// Nachbar (Raten jede Sekunde)
	if len(s.cfg.Peers) > 0 {
		s.bw.mu.Lock()
		at := s.bw.peerAt
		s.bw.mu.Unlock()
		w.Gauge("cdn64_edge_peer_up", "1 neighbour server reported its rates in the last 5 s", metrics.Bool(!at.IsZero() && time.Since(at) < 5*time.Second), srv...)
	}

	// Portmapper (Modus 3)
	tcp, udp := s.pm.open()
	w.Gauge("cdn64_edge_portmap_ports", "Open portmapper ports", float64(tcp), lbl("transport", "tcp")...)
	w.Gauge("cdn64_edge_portmap_ports", "Open portmapper ports", float64(udp), lbl("transport", "udp")...)
	w.Gauge("cdn64_edge_portmap_udp_sessions", "Open UDP portmapper sessions", float64(s.pm.udpSessions()), srv...)
}
