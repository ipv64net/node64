package cdn64

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/tunnel"
)

// CDN64 online: Tunnel zu srv07/srv08.cdn64.de. Die Server reichen Besucher-Verbindungen durch den Tunnel, die
// Node nimmt sie wie Verbindungen auf Port 443/80 an (Eingang.ServeConn) - ohne offene Ports zu Hause.
// T1: Tunnel-Daten werden von Hand gesetzt (API); ab T3/T4 kommen sie per Klick von ipv64. Planung: docs/CDN64-ONLINE.md.

const setOnline = "cdn64.online" // JSON onlineConf

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
	cl := tunnel.NewClient(tunnel.ClientConfig{Tunnel: c.Tunnel, Token: tok, Node: node, NodeVersion: m.version, Edges: c.Edges,
		Handler: m.onlineHandle, Log: m.log, RootCAs: m.online.roots})
	rctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan struct{})
	m.online.mu.Lock()
	m.online.client, m.online.cancel, m.online.done = cl, cancel, done
	m.online.mu.Unlock()
	go func() { defer close(done); cl.Run(rctx) }()
	m.log.Info("cdn64 online: tunnel started", "tunnel", c.Tunnel, "edges", len(c.Edges))
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
	switch h.Kind {
	case tunnel.KindTLS:
		m.edge.ServeConn(c, 443)
	case tunnel.KindHTTP80:
		m.edge.ServeConn(c, 80)
	default:
		_ = st.Close()
	}
}

// tunnelConn: Stream mit der Besucher-Adresse als Gegenstelle.
type tunnelConn struct {
	tunnel.Stream
	remote net.Addr
}

func (c *tunnelConn) RemoteAddr() net.Addr { return c.remote }

// ---------------------------------------------------------------- API (T1: von Hand; ab T4 per Klick)

type onlineView struct {
	Configured bool                `json:"configured"`
	Tunnel     string              `json:"tunnel,omitempty"`
	Edges      []tunnel.EdgeStatus `json:"edges"`
}

func (m *Module) apiOnlineGet(w http.ResponseWriter, r *http.Request) {
	v := onlineView{Edges: []tunnel.EdgeStatus{}}
	if c, _, err := m.onlineConf(r.Context()); err == nil && c != nil {
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
	writeJSON(w, http.StatusOK, v)
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
	stored := tok
	if m.online.box != nil {
		stored = m.online.box.Encrypt(tok)
	}
	b, _ := json.Marshal(onlineConf{Tunnel: in.Tunnel, Token: stored, Edges: in.Edges})
	if err := m.core.SetSetting(r.Context(), setOnline, string(b)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	m.g.Audit(r, "cdn64.online", in.Tunnel, "")
	if m.isRunning() {
		m.onlineStart(r.Context())
	}
	m.apiOnlineGet(w, r)
}

func (m *Module) apiOnlineDelete(w http.ResponseWriter, r *http.Request) {
	m.onlineStop()
	if err := m.core.SetSetting(r.Context(), setOnline, ""); err != nil {
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
