package cdn64

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/tunnel"
)

// CDN64 online: Tunnel zu srv07/srv08.cdn64.de. Die Server reichen Besucher-Verbindungen durch den Tunnel, die
// Node nimmt sie wie Verbindungen auf Port 443/80 an (Eingang.ServeConn) - ohne offene Ports zu Hause.
// Tunnel-Daten kommen per Klick von ipv64 (online_click.go); von Hand setzen geht weiter (API, Tests). Planung:
// docs/CDN64-ONLINE.md.

const (
	setOnline         = "cdn64.online"          // JSON onlineConf
	setOnlineSessions = "cdn64.online_sessions" // parallele Verbindungen je Server, die ipv64 der Klasse erlaubt
)

type onlineConf struct {
	Tunnel string        `json:"tunnel"`
	Token  string        `json:"token"` // verschluesselt (secrets.Box)
	Edges  []tunnel.Edge `json:"edges"`
}

type onlineState struct {
	mu     sync.Mutex
	box    *secrets.Box
	roots  *x509.CertPool // Tests: eigene CA der Server (sonst System)
	client *tunnel.Client
	cancel context.CancelFunc
	done   chan struct{}

	api     OnlineAPI                         // ipv64 /cdn64o (nil = nicht verfuegbar)
	op      sync.Mutex                        // ein Ein-/Ausschalten bzw. Abgleich gleichzeitig
	remote  atomic.Pointer[onlineRemote]      // letzter Stand von ipv64
	names   atomic.Pointer[map[string]bool]   // eingeschaltete Namen (geteilter DNS)
	kick    chan struct{}                     // Abgleich bald
	want    atomic.Bool                       // Liste geoeffnet: Stand von ipv64 auch ohne eigene Namen holen
	portIdx atomic.Pointer[map[portKey]int64] // Portmapper: (tcp/udp, Name, Port des Streams) -> Stream
	portMu  sync.Mutex                        // Fehler je Stream beim Anmelden
	portErr map[int64]string                  // Stream -> Code (cdn64.online.e.<code>)
	seenMu  sync.Mutex                        // Selbsttest: Streams je Name
	seen    map[string]int                    //
	ports   [2]int                            // Tests: Besucher-Ports der Server (sonst 443, 80)
	notify  func(notify.Alert)                // Meldungen (nil = keine)
	prot    protectionCache                   // CDN64 Statistik (protection_ui.go)
}

// SetSecrets gibt den Schluessel fuer verschluesselt gespeicherte Werte (Tunnel-Token).
func (m *Module) SetSecrets(b *secrets.Box) { m.online.box = b }

func (m *Module) onlineConf(ctx context.Context) (*onlineConf, string, error) {
	v := m.core.SettingOr(ctx, setOnline, "")
	if v == "" {
		return nil, "", nil
	}
	c := &onlineConf{}
	if err := json.Unmarshal([]byte(v), c); err != nil {
		return nil, "", err
	}
	tok := c.Token
	if m.online.box != nil {
		var err error
		if tok, err = m.online.box.Decrypt(c.Token); err != nil {
			return nil, "", err
		}
	}
	return c, tok, nil
}

// onlineStart startet den Tunnel, wenn er eingerichtet ist (beim Start des Moduls und nach Aenderungen).
func (m *Module) onlineStart(ctx context.Context) {
	m.onlineStop()
	c, tok, err := m.onlineConf(ctx)
	if err != nil {
		m.log.Warn("cdn64 online: settings not readable", "err", err)
		return
	}
	if c == nil || c.Tunnel == "" || len(c.Edges) == 0 || m.edge == nil {
		return
	}
	node, _ := os.Hostname()
	sessions, _ := strconv.Atoi(m.core.SettingOr(ctx, setOnlineSessions, "1"))
	cl := tunnel.NewClient(tunnel.ClientConfig{Tunnel: c.Tunnel, Token: tok, Node: node, NodeVersion: m.version, Edges: c.Edges,
		Handler: m.onlineHandle, Log: m.log, RootCAs: m.online.roots, Caps: []string{tunnel.CapQUIC, tunnel.CapPorts}, Sessions: sessions})
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	m.online.mu.Lock()
	oldCancel, oldDone := m.online.cancel, m.online.done // gleichzeitig gestartet: den anderen beenden (sonst laeuft er weiter)
	m.online.client, m.online.cancel, m.online.done = cl, cancel, done
	m.online.mu.Unlock()
	go func() { defer close(done); cl.Run(rctx) }()
	if oldCancel != nil {
		oldCancel()
		<-oldDone
	}
	if !m.isRunning() { // Modul inzwischen gestoppt (Stop hat den Tunnel evtl. schon vorher beendet)
		m.onlineStop()
		return
	}
	m.log.Info("cdn64 online: tunnel started", "tunnel", c.Tunnel, "edges", len(c.Edges), "sessions", max(sessions, 1))
}

func (m *Module) onlineStop() {
	m.online.mu.Lock()
	cancel, done := m.online.cancel, m.online.done
	m.online.client, m.online.cancel, m.online.done = nil, nil, nil
	m.online.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// onlineHandle: Stream aus dem Tunnel an den Eingang (Port 443 bzw. 80), mit der echten Besucher-Adresse.
func (m *Module) onlineHandle(st tunnel.Stream, h tunnel.Header) {
	ra := h.ClientAddr()
	if ra == nil || m.edge == nil {
		_ = st.Close()
		return
	}
	c := &tunnelConn{Stream: st, remote: ra}
	m.onlineSeen(h.Host)
	// Der Server reicht fuer genau einen Namen durch (h.Host): nur der ist ueber diese Verbindung erreichbar, nicht
	// andere (z. B. nur im Heimnetz veroeffentlichte) Namen per anderem SNI, absoluter URL oder spaeterer Anfrage.
	switch h.Kind {
	case tunnel.KindTLS:
		m.edge.ServeConnFor(c, 443, h.Host)
	case tunnel.KindHTTP80:
		m.edge.ServeConnFor(c, 80, h.Host)
	case tunnel.KindHTTP: // Modus 2: TLS endete auf dem Server
		m.edge.ServeConnFor(c, edge.PortTerminated, h.Host)
	case tunnel.KindQUIC: // Modus 1, HTTP/3: QUIC-Datagramme des Besuchers
		ap, err := netip.ParseAddrPort(h.Client)
		if err != nil {
			_ = st.Close()
			return
		}
		m.edge.ServeQUICStreamFor(c, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), h.Host)
	case tunnel.KindTCP, tunnel.KindUDP: // Portmapper Modus 1/2: an den Stream der Node
		m.onlinePortStream(c, h)
	default:
		_ = st.Close()
	}
}

// onlineHTTP3: geht HTTP/3 fuer Modus 1 ueber die Server (Tunnel laeuft, alle verbundenen Server reichen QUIC durch)?
func (m *Module) onlineHTTP3() bool {
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	return cl != nil && cl.AllHave(tunnel.CapQUIC)
}

// tunnelConn: Stream mit der Besucher-Adresse als Gegenstelle.
type tunnelConn struct {
	tunnel.Stream
	remote net.Addr
}

func (c *tunnelConn) RemoteAddr() net.Addr { return c.remote }

// ---------------------------------------------------------------- API (Status; Tunnel von Hand setzen)

type onlineView struct {
	Configured bool                 `json:"configured"`
	Tunnel     string               `json:"tunnel,omitempty"`
	Edges      []tunnel.EdgeStatus  `json:"edges"`
	APIReady   bool                 `json:"api_ready"` // ipv64-Account verbunden
	Names      []onlineName         `json:"names"`
	Quota      *ipv64api.CDN64Quota `json:"quota,omitempty"`
	Synced     *time.Time           `json:"synced,omitempty"` // letzter Abgleich mit ipv64
	SyncError  string               `json:"sync_error,omitempty"`
	UDPBuffer  int                  `json:"udp_buffer,omitempty"` // net.core.rmem_max
	UDPLow     bool                 `json:"udp_buffer_low"`       // zu klein fuer volle QUIC-Geschwindigkeit
}

func (m *Module) onlineStatus(ctx context.Context) onlineView {
	v := onlineView{Edges: []tunnel.EdgeStatus{}, Names: []onlineName{}}
	v.APIReady = m.online.api != nil && m.online.api.Ready(ctx)
	if list, err := m.onlineNames(ctx); err == nil {
		v.Names = list
	}
	if rm := m.online.remote.Load(); rm != nil {
		at := rm.At
		v.Synced, v.SyncError = &at, rm.Err
		if rm.Data != nil {
			q := rm.Data.Quota
			v.Quota = &q
		}
	}
	v.UDPBuffer, v.UDPLow = udpBufferLow()
	if c, _, err := m.onlineConf(ctx); err == nil && c != nil {
		v.Configured, v.Tunnel = true, c.Tunnel
		for _, e := range c.Edges {
			v.Edges = append(v.Edges, tunnel.EdgeStatus{Name: e.Name, Host: e.Host})
		}
	}
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	if cl != nil {
		v.Edges = cl.Status()
	}
	return v
}

func (m *Module) apiOnlineGet(w http.ResponseWriter, r *http.Request) {
	// Kontingent frisch, wenn noch keins da oder aelter als 5 Minuten (erster Schritt im Fenster)
	if a := m.online.api; a != nil && a.Ready(r.Context()) {
		if rm := m.online.remote.Load(); rm == nil || time.Since(rm.At) > 5*time.Minute {
			ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
			ov, err := a.Overview(ctx)
			cancel()
			m.onlineSetRemote(ov, err)
		}
	}
	writeJSON(w, http.StatusOK, m.onlineStatus(r.Context()))
}

func (m *Module) apiOnlinePut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		Tunnel string        `json:"tunnel"`
		Token  string        `json:"token"` // leer = unveraendert
		Edges  []tunnel.Edge `json:"edges"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	in.Tunnel = strings.TrimSpace(in.Tunnel)
	if in.Tunnel == "" || len(in.Edges) == 0 || len(in.Edges) > 16 {
		m.apiFail(w, ferr("tunnel", "cdn64.online.err_conf"))
		return
	}
	for i := range in.Edges {
		e := &in.Edges[i]
		e.Name, e.Host = strings.TrimSpace(e.Name), strings.TrimSpace(e.Host)
		if e.Name == "" || e.Host == "" || e.Port < 0 || e.Port > 65535 {
			m.apiFail(w, ferr("edges", "cdn64.online.err_conf"))
			return
		}
	}
	tok := in.Token
	if tok == "" {
		old, oldTok, err := m.onlineConf(r.Context())
		if err != nil || old == nil {
			m.apiFail(w, ferr("token", "cdn64.online.err_conf"))
			return
		}
		tok = oldTok
	}
	m.online.op.Lock() // nicht gleichzeitig mit Abgleich bzw. Einschalten (die starten den Tunnel auch)
	if err := m.onlineSave(r.Context(), in.Tunnel, tok, in.Edges); err != nil {
		m.online.op.Unlock()
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if m.isRunning() {
		m.onlineStart(r.Context())
	}
	m.online.op.Unlock()
	m.g.Audit(r, "cdn64.online", in.Tunnel, "")
	m.apiOnlineGet(w, r)
}

func (m *Module) apiOnlineDelete(w http.ResponseWriter, r *http.Request) {
	m.online.op.Lock()
	m.onlineStop()
	err := m.core.SetSetting(r.Context(), setOnline, "")
	m.online.op.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	m.g.Audit(r, "cdn64.online.delete", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) isRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}
