package cdn64

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/tunnel"
)

// CDN64 online per Klick (T4): Der Schalter an einem Host meldet bei Bedarf den Tunnel der Node bei ipv64 an
// (Token verschluesselt in cdn64.online), schaltet die Namen des Hosts ein (DNS zeigt danach auf srv07/srv08) und
// prueft den Weg ueber das Internet. Ausschalten stellt alles zurueck; mit dem letzten Namen geht auch der Tunnel.
// Ein Abgleich (jede Minute und nach Aenderungen an Hosts) holt Status, Kontingent und Server-Liste von ipv64 und
// traegt Namen aus, deren Host es nicht mehr gibt. Im Heimnetz beantwortet DNS64 die Namen mit der Adresse der
// Node (OnlineName), damit Aufrufe von zu Hause nicht ueber srv07/srv08 laufen.

// OnlineAPI ist der Zugriff auf /cdn64o bei ipv64 (zentraler API-Key).
type OnlineAPI interface {
	Ready(ctx context.Context) bool
	Overview(ctx context.Context) (*ipv64api.CDN64Overview, error)
	CreateTunnel(ctx context.Context, name string) (*ipv64api.CDN64Tunnel, error)
	DeleteTunnel(ctx context.Context, id string) error
	AddHost(ctx context.Context, fqdn, tunnelID string, mode int, target *ipv64api.CDN64Target) (*ipv64api.CDN64Host, error)
	SetMode(ctx context.Context, id int64, mode int) error
	SetPaused(ctx context.Context, id int64, paused bool) error
	AddMapping(ctx context.Context, id int64, name, transport string, targetPort int) ([]ipv64api.CDN64Mapping, error)
	DeleteMapping(ctx context.Context, id, mapping int64) error
	DeleteHost(ctx context.Context, id int64) error
	Protection(ctx context.Context, days int) (*ipv64api.CDN64Protection, error)
	SetProtection(ctx context.Context, id int64, waf *bool, ja4 string) error
}

// IPv64Online ist OnlineAPI ueber den zentralen API-Key.
func IPv64Online(k *ipv64api.Key) OnlineAPI { return ipv64Online{k} }

type ipv64Online struct{ k *ipv64api.Key }

func (o ipv64Online) Ready(ctx context.Context) bool { return o.k != nil && o.k.Get(ctx) != "" }

// ListToken: Listen-Token fuer die Live-Fassung der v64 Blocklist (blocklist_live.go).
func (o ipv64Online) ListToken(ctx context.Context) (*ipv64api.ListToken, error) {
	return o.k.Client().HoneypotListToken(ctx, o.k.Get(ctx))
}
func (o ipv64Online) Overview(ctx context.Context) (*ipv64api.CDN64Overview, error) {
	return o.k.Client().CDN64(ctx, o.k.Get(ctx))
}
func (o ipv64Online) CreateTunnel(ctx context.Context, name string) (*ipv64api.CDN64Tunnel, error) {
	return o.k.Client().CDN64CreateTunnel(ctx, o.k.Get(ctx), name, "")
}
func (o ipv64Online) DeleteTunnel(ctx context.Context, id string) error {
	return o.k.Client().CDN64DeleteTunnel(ctx, o.k.Get(ctx), id)
}
func (o ipv64Online) AddHost(ctx context.Context, fqdn, tunnelID string, mode int, target *ipv64api.CDN64Target) (*ipv64api.CDN64Host, error) {
	return o.k.Client().CDN64AddHost(ctx, o.k.Get(ctx), fqdn, tunnelID, mode, target)
}
func (o ipv64Online) SetMode(ctx context.Context, id int64, mode int) error {
	_, err := o.k.Client().CDN64SetMode(ctx, o.k.Get(ctx), id, mode)
	return err
}
func (o ipv64Online) SetPaused(ctx context.Context, id int64, paused bool) error {
	_, err := o.k.Client().CDN64SetPaused(ctx, o.k.Get(ctx), id, paused)
	return err
}
func (o ipv64Online) AddMapping(ctx context.Context, id int64, name, transport string, targetPort int) ([]ipv64api.CDN64Mapping, error) {
	return o.k.Client().CDN64AddMapping(ctx, o.k.Get(ctx), id, name, transport, targetPort)
}
func (o ipv64Online) DeleteMapping(ctx context.Context, id, mapping int64) error {
	return o.k.Client().CDN64DeleteMapping(ctx, o.k.Get(ctx), id, mapping)
}
func (o ipv64Online) DeleteHost(ctx context.Context, id int64) error {
	return o.k.Client().CDN64DeleteHost(ctx, o.k.Get(ctx), id)
}

func (o ipv64Online) Protection(ctx context.Context, days int) (*ipv64api.CDN64Protection, error) {
	return o.k.Client().CDN64Protection(ctx, o.k.Get(ctx), days)
}
func (o ipv64Online) SetProtection(ctx context.Context, id int64, waf *bool, ja4 string) error {
	_, err := o.k.Client().CDN64SetProtection(ctx, o.k.Get(ctx), id, waf, ja4)
	return err
}

// SetOnlineAPI haengt ipv64 an (nil = CDN64 online nicht verfuegbar).
func (m *Module) SetOnlineAPI(a OnlineAPI) { m.online.api = a }

// onlineRemote: letzter Abgleich mit ipv64.
type onlineRemote struct {
	At   time.Time
	Err  string
	Data *ipv64api.CDN64Overview
}

// onlineErr: Fehler mit Code fuer die Oberflaeche (cdn64.online.e.<code>).
type onlineErr struct{ code string }

func (e *onlineErr) Error() string { return "cdn64 online: " + e.code }

func errOnline(code string) error { return &onlineErr{code} }

// onlineCode: Code eines Fehlers (eigene, ipv64-Fehlercodes, Erreichbarkeit).
func onlineCode(err error) string {
	var oe *onlineErr
	switch {
	case err == nil:
		return ""
	case errors.As(err, &oe):
		return oe.code
	case errors.Is(err, ipv64api.ErrUnauthorized):
		return "api_key_rejected"
	}
	if c := ipv64api.ErrorCode(err); c != "" {
		return c
	}
	if strings.Contains(err.Error(), "not reachable") || strings.Contains(err.Error(), "timeout") {
		return "ipv64_unreachable"
	}
	return "error"
}

// ---------------------------------------------------------------- eingeschaltete Namen (cdn_online)

type onlineName struct {
	Name      string    `json:"name"`
	HostID    int64     `json:"host_id"`
	RemoteID  int64     `json:"remote_id"`
	Mode      int       `json:"mode"`
	Check     string    `json:"check,omitempty"` // Healthcheck vom Einschalten
	CreatedAt time.Time `json:"created_at"`
}

func (m *Module) onlineNames(ctx context.Context) ([]onlineName, error) {
	rows, err := m.core.Reader().QueryContext(ctx, `SELECT name, host_id, remote_id, mode, check_token, created_at FROM cdn_online ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []onlineName{}
	for rows.Next() {
		var x onlineName
		var ca string
		if err := rows.Scan(&x.Name, &x.HostID, &x.RemoteID, &x.Mode, &x.Check, &ca); err != nil {
			return nil, err
		}
		x.CreatedAt = store.ParseTime(ca)
		out = append(out, x)
	}
	return out, rows.Err()
}

func (m *Module) onlineDrop(ctx context.Context, name string) {
	_, _ = m.core.Writer().ExecContext(ctx, `DELETE FROM cdn_online WHERE name = ?`, name)
}

// onlineLoadNames: Namen fuer den geteilten DNS (OnlineName) neu einlesen.
func (m *Module) onlineLoadNames(ctx context.Context) {
	list, err := m.onlineNames(ctx)
	if err != nil {
		return
	}
	set := make(map[string]bool, len(list))
	for _, x := range list {
		set[x.Name] = true
	}
	m.online.names.Store(&set)
}

// OnlineName: der Name ist in CDN64 online eingeschaltet (DNS64 beantwortet ihn im Heimnetz mit der Node).
func (m *Module) OnlineName(name string) bool {
	if !m.isRunning() {
		return false
	}
	p := m.online.names.Load()
	return p != nil && (*p)[strings.TrimSuffix(strings.ToLower(name), ".")]
}

// ---------------------------------------------------------------- Tunnel

// onlineSave speichert Tunnel, Token (verschluesselt) und Server.
func (m *Module) onlineSave(ctx context.Context, id, tok string, edges []tunnel.Edge) error {
	stored := tok
	if m.online.box != nil {
		stored = m.online.box.Encrypt(tok)
	}
	b, _ := json.Marshal(onlineConf{Tunnel: id, Token: stored, Edges: edges})
	return m.core.SetSetting(ctx, setOnline, string(b))
}

func toEdges(list []ipv64api.CDN64Edge) []tunnel.Edge {
	out := make([]tunnel.Edge, 0, len(list))
	for _, e := range list {
		out = append(out, tunnel.Edge{Name: e.Name, Host: e.Host, Port: e.Port, IPs: e.IPs})
	}
	return out
}

func sameEdges(a, b []tunnel.Edge) bool {
	return slices.EqualFunc(a, b, func(x, y tunnel.Edge) bool {
		return x.Name == y.Name && x.Host == y.Host && x.Port == y.Port && slices.Equal(x.IPs, y.IPs)
	})
}

func (m *Module) onlineRunning() bool {
	m.online.mu.Lock()
	defer m.online.mu.Unlock()
	return m.online.client != nil
}

// onlineEnsureTunnel: Tunnel bei ipv64 vorhanden (sonst anlegen), Server-Liste aktuell, Tunnel laeuft.
func (m *Module) onlineEnsureTunnel(ctx context.Context) (*onlineConf, error) {
	a := m.online.api
	if a == nil || !a.Ready(ctx) {
		return nil, errOnline("no_api_key")
	}
	ov, err := a.Overview(ctx)
	m.onlineSetRemote(ov, err)
	if err != nil {
		return nil, err
	}
	c, tok, err := m.onlineConf(ctx)
	if err != nil {
		c = nil // nicht lesbar (z. B. anderer Schluessel): neu anmelden
	}
	if c != nil {
		for _, t := range ov.Tunnels {
			if t.ID != c.Tunnel {
				continue
			}
			if t.Status != "active" {
				return nil, errOnline("tunnel_blocked")
			}
			if edges := toEdges(ov.Edges); len(edges) > 0 && !sameEdges(c.Edges, edges) {
				c.Edges = edges
				if err := m.onlineSave(ctx, c.Tunnel, tok, edges); err != nil {
					return nil, err
				}
				if m.isRunning() {
					m.onlineStart(ctx)
				}
			} else if m.isRunning() && !m.onlineRunning() {
				m.onlineStart(ctx)
			}
			return c, nil
		}
	}
	name := m.core.SettingOr(ctx, "node.name", "")
	if name == "" {
		name, _ = os.Hostname()
	}
	t, err := a.CreateTunnel(ctx, trunc("Node64 "+name, 100))
	if err != nil {
		return nil, err
	}
	edges := toEdges(t.Edges)
	if len(edges) == 0 {
		edges = toEdges(ov.Edges)
	}
	if err := m.onlineSave(ctx, t.ID, t.Token, edges); err != nil {
		return nil, err
	}
	m.log.Info("cdn64 online: tunnel registered at ipv64", "tunnel", t.ID)
	if m.isRunning() {
		m.onlineStart(ctx)
	}
	return &onlineConf{Tunnel: t.ID, Edges: edges}, nil
}

// onlineDropTunnel: ohne eingeschaltete Namen den Tunnel bei ipv64 entfernen und hier vergessen.
func (m *Module) onlineDropTunnel(ctx context.Context) {
	if list, err := m.onlineNames(ctx); err != nil || len(list) > 0 {
		return
	}
	c, _, _ := m.onlineConf(ctx)
	if c == nil {
		return
	}
	if a := m.online.api; a != nil && a.Ready(ctx) {
		if err := a.DeleteTunnel(ctx, c.Tunnel); err != nil && onlineCode(err) != "cdn64o_tunnel_not_found" {
			m.log.Warn("cdn64 online: tunnel not removed at ipv64", "tunnel", c.Tunnel, "err", err)
			return
		}
	}
	m.onlineStop()
	_ = m.core.SetSetting(ctx, setOnline, "")
	m.log.Info("cdn64 online: tunnel removed", "tunnel", c.Tunnel)
}

// onlineWait: wartet, bis der Tunnel zu mindestens einem Server steht (oder die Zeit um ist).
func (m *Module) onlineWait(ctx context.Context, d time.Duration) []tunnel.EdgeStatus {
	end := time.Now().Add(d)
	for {
		m.online.mu.Lock()
		cl := m.online.client
		m.online.mu.Unlock()
		var st []tunnel.EdgeStatus
		if cl != nil {
			st = cl.Status()
			for _, e := range st {
				if e.Connected {
					return st
				}
			}
		}
		if time.Now().After(end) {
			return st
		}
		select {
		case <-ctx.Done():
			return st
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// ---------------------------------------------------------------- Ein- und Ausschalten

// onlineResult: Ergebnis je Name beim Einschalten.
type onlineResult struct {
	Name   string `json:"name"`
	Result string `json:"result"` // on, skipped, error
	Code   string `json:"code,omitempty"`
	Error  string `json:"error,omitempty"`
	Text   string `json:"text,omitempty"` // Fehlertext mit Abhilfe (Sprache der Anfrage)
}

// onlineEnable schaltet die Namen eines Hosts ein; schon eingeschaltete wechseln auf mode (DNS bleibt). Scheitern
// alle, bleibt nichts zurueck. Modus 2 (TLS endet auf den Servern) geht nicht fuer "TLS durchreichen". Modus 3
// (direkt zum Ziel, ohne Tunnel) gibt es nur auf ipv64.net/cdn64; alte Modus-3-Namen lassen sich hier auf 1/2
// umstellen (bei ipv64 aus und neu ein) oder ausschalten.
func (m *Module) onlineEnable(ctx context.Context, h *Host, mode int) ([]onlineResult, error) {
	m.online.op.Lock()
	defer m.online.op.Unlock()
	if mode == 0 {
		mode = 1
	}
	if mode == 3 {
		return nil, errOnline("mode3_web")
	}
	if mode < 1 || mode > 2 {
		return nil, errOnline("mode_not_available")
	}
	if mode == 2 && h.Kind == KindPass {
		return nil, errOnline("mode2_passthrough")
	}
	if mode == 2 && h.Kind == KindStream { // ohne HTTPS gibt es auf den Servern nichts zu beenden
		return nil, errOnline("mode2_stream")
	}
	c, err := m.onlineEnsureTunnel(ctx)
	if err != nil {
		return nil, err
	}
	tunnelID := c.Tunnel
	have, err := m.onlineNames(ctx)
	if err != nil {
		return nil, err
	}
	on := map[string]onlineName{}
	for _, x := range have {
		on[x.Name] = x
	}
	var out []onlineResult
	for _, n := range h.Names {
		switch {
		case strings.HasPrefix(n, "*."):
			out = append(out, onlineResult{Name: n, Result: "skipped", Code: "wildcard_name"})
			continue
		}
		if x, ok := on[n]; ok && x.Mode == 3 { // alter Modus-3-Name (direkt) -> Tunnel: bei ipv64 aus und neu ein
			if err := m.onlineRemoteOff(ctx, x); err != nil {
				out = append(out, onlineResult{Name: n, Result: "error", Code: onlineCode(err), Error: err.Error()})
				continue
			}
			delete(on, n)
		}
		if x, ok := on[n]; ok {
			if x.Mode != mode {
				if err := m.online.api.SetMode(ctx, x.RemoteID, mode); err != nil {
					out = append(out, onlineResult{Name: n, Result: "error", Code: onlineCode(err), Error: err.Error()})
					continue
				}
				_, _ = m.core.Writer().ExecContext(ctx, `UPDATE cdn_online SET mode = ? WHERE name = ?`, mode, n)
			}
			out = append(out, onlineResult{Name: n, Result: "on"})
			continue
		}
		rh, err := m.online.api.AddHost(ctx, n, tunnelID, mode, nil)
		if err != nil {
			out = append(out, onlineResult{Name: n, Result: "error", Code: onlineCode(err), Error: err.Error()})
			continue
		}
		if _, err := m.core.Writer().ExecContext(ctx, `INSERT OR REPLACE INTO cdn_online (name, host_id, remote_id, mode, created_at) VALUES (?, ?, ?, ?, ?)`,
			n, h.ID, rh.ID, mode, store.Now()); err != nil {
			_ = m.online.api.DeleteHost(ctx, rh.ID)
			out = append(out, onlineResult{Name: n, Result: "error", Code: "error", Error: err.Error()})
			continue
		}
		out = append(out, onlineResult{Name: n, Result: "on"})
	}
	m.onlineLoadNames(ctx)
	m.onlineDropTunnel(ctx) // nichts eingeschaltet: Tunnel wieder weg
	m.onlineKick()
	return out, nil
}

// onlineDisable schaltet alle Namen eines Hosts aus; mit dem letzten Namen geht der Tunnel.
func (m *Module) onlineDisable(ctx context.Context, hostID int64) error {
	m.online.op.Lock()
	defer m.online.op.Unlock()
	list, err := m.onlineNames(ctx)
	if err != nil {
		return err
	}
	var first error
	for _, x := range list {
		if x.HostID != hostID {
			continue
		}
		if err := m.onlineRemoteOff(ctx, x); err != nil && first == nil {
			first = err
		}
	}
	m.onlineLoadNames(ctx)
	m.onlineDropTunnel(ctx)
	m.onlineKick()
	return first
}

// BeforeReset (module.Resetter): vor "Node zuruecksetzen" alle Namen bei ipv64 austragen und den Tunnel entfernen –
// auch wenn das Modul gerade aus ist (sonst bleiben Namen und Tunnel bei ipv64 zurueck). Nie eingeschaltet = nichts zu tun.
func (m *Module) BeforeReset(ctx context.Context) error {
	m.online.op.Lock()
	defer m.online.op.Unlock()
	list, err := m.onlineNames(ctx)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return nil
		}
		return err
	}
	var first error
	for _, x := range list {
		if err := m.onlineRemoteOff(ctx, x); err != nil && first == nil {
			first = err
		}
	}
	m.onlineLoadNames(ctx)
	m.onlineDropTunnel(ctx)
	return first
}

// onlineRemoteOff: Name bei ipv64 ausschalten (schon weg zaehlt als erledigt) und hier austragen.
func (m *Module) onlineRemoteOff(ctx context.Context, x onlineName) error {
	if a := m.online.api; a != nil {
		if !a.Ready(ctx) {
			return errOnline("no_api_key")
		}
		if err := a.DeleteHost(ctx, x.RemoteID); err != nil && onlineCode(err) != "cdn64o_host_not_found" {
			return err
		}
	}
	m.onlineDrop(ctx, x.Name)
	return nil
}

// ---------------------------------------------------------------- Abgleich mit ipv64

func (m *Module) onlineSetRemote(ov *ipv64api.CDN64Overview, err error) {
	r := &onlineRemote{At: time.Now(), Data: ov}
	if err != nil {
		r.Err = err.Error()
		if old := m.online.remote.Load(); old != nil {
			r.Data = old.Data // letzter bekannter Stand bleibt sichtbar
		}
	}
	m.online.remote.Store(r)
}

// onlineKick: Abgleich bald (nach Aenderungen an Hosts).
func (m *Module) onlineKick() {
	select {
	case m.online.kick <- struct{}{}:
	default:
	}
}

func (m *Module) onlineLoop(ctx context.Context) {
	m.onlineLoadNames(ctx)
	m.onlinePortsIndex(ctx)
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		m.onlineSync(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-m.online.kick:
			select { // mehrere Aenderungen kurz nacheinander: einmal abgleichen
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}
	}
}

// onlineSync: Stand von ipv64 holen; Namen ohne Host (oder nicht mehr am Host) ausschalten, auf der Webseite
// ausgeschaltete Namen hier austragen, Server-Liste uebernehmen.
func (m *Module) onlineSync(ctx context.Context) {
	a := m.online.api
	if a == nil || !a.Ready(ctx) {
		return
	}
	m.online.op.Lock()
	defer m.online.op.Unlock()
	list, err := m.onlineNames(ctx)
	if err != nil {
		return
	}
	c, tok, _ := m.onlineConf(ctx)
	idle := len(list) == 0 && c == nil // nichts von dieser Node: Namen des Accounts nur zur Anzeige (Modus 3, andere Nodes)
	if rm := m.online.remote.Load(); idle && !m.online.want.Swap(false) && rm != nil && time.Since(rm.At) < onlineIdleEvery &&
		(rm.Data == nil || len(rm.Data.Hosts) == 0) {
		return
	}
	ov, err := a.Overview(ctx)
	m.onlineSetRemote(ov, err)
	if err != nil {
		return
	}
	if idle {
		m.onlinePortsApply(ctx, ov) // keine Namen mehr: Portmapper der Streams austragen
		return
	}
	remote := map[int64]ipv64api.CDN64Host{}
	for _, rh := range ov.Hosts {
		remote[rh.ID] = rh
	}
	hosts := map[int64]*Host{}
	if hl, err := m.hosts(ctx); err == nil {
		for _, h := range hl {
			hosts[h.ID] = h
		}
	} else {
		return
	}
	removed := false
	for _, x := range list {
		h := hosts[x.HostID]
		switch {
		case remote[x.RemoteID].ID == 0:
			m.onlineDrop(ctx, x.Name)
			removed = true
		case h == nil || !slices.Contains(h.Names, x.Name):
			if err := m.onlineRemoteOff(ctx, x); err != nil {
				m.log.Warn("cdn64 online: name not switched off", "name", x.Name, "err", err)
				continue
			}
			removed = true
		case (h.Kind == KindPass || h.Kind == KindStream) && remote[x.RemoteID].Mode == 2: // z. B. auf der Webseite gewechselt: geht hier nicht
			if err := a.SetMode(ctx, x.RemoteID, 1); err != nil {
				m.log.Warn("cdn64 online: mode 2 not reset", "name", x.Name, "kind", h.Kind, "err", err)
			} else {
				m.log.Warn("cdn64 online: mode 2 is not possible for this host kind, switched back to 1", "name", x.Name, "kind", h.Kind)
				_, _ = m.core.Writer().ExecContext(ctx, `UPDATE cdn_online SET mode = 1 WHERE name = ?`, x.Name)
			}
		case remote[x.RemoteID].Mode != x.Mode && remote[x.RemoteID].Mode > 0: // anderswo gewechselt: hier uebernehmen
			_, _ = m.core.Writer().ExecContext(ctx, `UPDATE cdn_online SET mode = ? WHERE name = ?`, remote[x.RemoteID].Mode, x.Name)
		}
	}
	if removed {
		m.onlineLoadNames(ctx)
		m.onlineDropTunnel(ctx)
	}
	m.onlinePortsApply(ctx, ov)
	if removed {
		return
	}
	if c != nil {
		for _, t := range ov.Tunnels {
			if cur := m.core.SettingOr(ctx, setOnlineSessions, "1"); t.ID == c.Tunnel && t.Sessions > 0 && strconv.Itoa(t.Sessions) != cur {
				// Klasse geaendert (z. B. Business): so viele parallele Verbindungen je Server aufbauen
				if err := m.core.SetSetting(ctx, setOnlineSessions, strconv.Itoa(t.Sessions)); err == nil && m.isRunning() {
					m.log.Info("cdn64 online: parallel sessions changed", "sessions", t.Sessions)
					m.onlineStart(ctx)
				}
			}
			if edges := toEdges(ov.Edges); t.ID == c.Tunnel && len(edges) > 0 && !sameEdges(c.Edges, edges) {
				if err := m.onlineSave(ctx, c.Tunnel, tok, edges); err == nil && m.isRunning() {
					m.log.Info("cdn64 online: server list changed", "edges", len(edges))
					m.onlineStart(ctx)
				}
			}
		}
	}
}

// ---------------------------------------------------------------- Selbsttest ueber das Internet

// onlineSeen zaehlt Streams je Name, die durch den Tunnel ankommen (Selbsttest: kam die Probe hier an?).
func (m *Module) onlineSeen(host string) {
	host = strings.ToLower(host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	m.online.seenMu.Lock()
	if m.online.seen == nil {
		m.online.seen = map[string]int{}
	}
	if len(m.online.seen) < 4096 || m.online.seen[host] > 0 {
		m.online.seen[host]++
	}
	m.online.seenMu.Unlock()
}

func (m *Module) onlineSeenCount(host string) int {
	m.online.seenMu.Lock()
	defer m.online.seenMu.Unlock()
	return m.online.seen[host]
}

// onlineProbe: eine Probe ueber einen Server und eine Adresse.
type onlineProbe struct {
	Edge    string `json:"edge"`
	Addr    string `json:"addr"`
	Family  string `json:"family"` // ipv4, ipv6
	OK      bool   `json:"ok"`
	Skipped bool   `json:"skipped,omitempty"` // die Node hat diese Adressfamilie nicht
	Ms      int64  `json:"ms,omitempty"`
	Trusted *bool  `json:"trusted,omitempty"`    // Zertifikat fuer Besucher gueltig (nur TLS)
	Other   bool   `json:"other_node,omitempty"` // Antwort kam, aber nicht durch diesen Tunnel (Name bei einer anderen Node)
	Error   string `json:"error,omitempty"`
}

// onlineTest: Ergebnis je Name.
type onlineTest struct {
	Name   string        `json:"name"`
	TLS    bool          `json:"tls"`
	Probes []onlineProbe `json:"probes"`
	DNS    []string      `json:"dns"`                   // Antwort eines oeffentlichen Resolvers
	DNSOK  bool          `json:"dns_ok"`                // zeigt auf die Server
	Route  string        `json:"route_error,omitempty"` // Host hier nicht geroutet (z. B. Name von DNS64 belegt)

	StreamOnly bool `json:"stream_only,omitempty"` // Host "nur Streams": kein HTTP/HTTPS, nur Ports der Streams
}

func (m *Module) onlinePorts() (int, int) {
	if m.online.ports[0] > 0 {
		return m.online.ports[0], m.online.ports[1]
	}
	return 443, 80
}

// onlineSelfTest prueft jeden eingeschalteten Namen eines Hosts ueber jeden Server und jede Adresse.
func (m *Module) onlineSelfTest(ctx context.Context, h *Host) ([]onlineTest, error) {
	c, _, err := m.onlineConf(ctx)
	if err != nil || c == nil {
		return nil, errOnline("not_configured")
	}
	list, err := m.onlineNames(ctx)
	if err != nil {
		return nil, err
	}
	useTLS := h.Kind == KindPass || h.HTTPS()
	for _, x := range list {
		useTLS = useTLS || (x.HostID == h.ID && x.Mode >= 2) // Modus 2/3: TLS auf den Servern, auch fuer reine HTTP-Hosts
	}
	streamOnly := h.Kind == KindStream
	m.mu.Lock()
	routeErr := m.routeErr[h.ID]
	m.mu.Unlock()
	var out []onlineTest
	for _, x := range list {
		if x.HostID != h.ID {
			continue
		}
		t := onlineTest{Name: x.Name, TLS: useTLS, Probes: []onlineProbe{}, Route: routeErr, StreamOnly: streamOnly}
		allIPs := map[string]bool{}
		for _, e := range c.Edges {
			ips := e.IPs
			if len(ips) == 0 {
				ips, _ = net.DefaultResolver.LookupHost(ctx, e.Host)
			}
			for _, ip := range ips {
				allIPs[ip] = true
				t.Probes = append(t.Probes, m.onlineProbeOne(ctx, e.Name, ip, x.Name, useTLS, x.Mode != 3, streamOnly))
			}
		}
		t.DNS = publicLookup(ctx, x.Name)
		for _, a := range t.DNS {
			t.DNSOK = t.DNSOK || allIPs[a]
		}
		out = append(out, t)
	}
	return out, nil
}

// streamOnly: Host "nur Streams" - die Node schliesst die Verbindung ohne Antwort, es zaehlt, dass sie ankommt.
func (m *Module) onlineProbeOne(ctx context.Context, edgeName, ip, name string, useTLS, viaTunnel, streamOnly bool) onlineProbe {
	p := onlineProbe{Edge: edgeName, Addr: ip, Family: "ipv4"}
	if strings.Contains(ip, ":") {
		p.Family = "ipv6"
	}
	p443, p80 := m.onlinePorts()
	port := p80
	if useTLS {
		port = p443
	}
	before := m.onlineSeenCount(name)
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		if s := err.Error(); strings.Contains(s, "network is unreachable") || strings.Contains(s, "no route to host") ||
			strings.Contains(s, "address family not supported") || strings.Contains(s, "cannot assign requested address") {
			p.Skipped = true
		}
		p.Error = err.Error()
		return p
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	if useTLS {
		tc := tls.Client(conn, &tls.Config{ServerName: name, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}) //nolint:gosec // Selbsttest: Gueltigkeit wird unten geprueft
		if err := tc.HandshakeContext(ctx); err != nil {
			p.Error = err.Error()
			return p
		}
		cs := tc.ConnectionState()
		trusted := false
		if len(cs.PeerCertificates) > 0 {
			inter := x509.NewCertPool()
			for _, c := range cs.PeerCertificates[1:] {
				inter.AddCert(c)
			}
			_, verr := cs.PeerCertificates[0].Verify(x509.VerifyOptions{DNSName: name, Intermediates: inter})
			trusted = verr == nil
		}
		p.Trusted = &trusted
		conn = tc // Modus 2 oeffnet den Stream erst mit der Anfrage
	}
	_, _ = io.WriteString(conn, "HEAD / HTTP/1.1\r\nHost: "+name+"\r\nUser-Agent: Node64-CDN64-Selftest\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil && !useTLS && !streamOnly { // bei TLS genuegt der Handschlag (Durchreichen), die Antwort ist Sache des Ziels
		p.Error = err.Error()
		return p
	}
	if resp != nil {
		resp.Body.Close()
	}
	if !viaTunnel { // Modus 3: die Server gehen selbst zum Ziel - ok, wenn eine Antwort vom Ziel kommt
		p.Ms = time.Since(start).Milliseconds()
		switch {
		case resp == nil:
			p.Error = "no answer"
		case resp.StatusCode == http.StatusBadGateway:
			p.Error = "target not reachable from the servers"
		default:
			p.OK = true
		}
		return p
	}
	p.Ms = time.Since(start).Milliseconds()
	for i := 0; i < 20 && m.onlineSeenCount(name) <= before; i++ { // der Stream kommt parallel zur Antwort an
		time.Sleep(50 * time.Millisecond)
	}
	if m.onlineSeenCount(name) <= before {
		p.Other, p.Error = true, "answered, but not through this node's tunnel"
		return p
	}
	p.OK = true
	return p
}

// publicLookup fragt einen oeffentlichen Resolver (nicht DNS64 der Node, das im Heimnetz die Node nennt).
var publicLookup = func(ctx context.Context, name string) []string {
	var out []string
	for _, srv := range []string{"1.1.1.1:53", "[2606:4700:4700::1111]:53", "9.9.9.9:53"} {
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, srv)
		}}
		lctx, cancel := context.WithTimeout(ctx, 4*time.Second)
		addrs, err := r.LookupHost(lctx, name)
		cancel()
		if err == nil {
			return append(out, addrs...)
		}
	}
	return out
}

// ---------------------------------------------------------------- API

// onlineText: Text zum Code in der Sprache der Anfrage (cdn64.online.e.<code>), sonst fallback.
func (m *Module) onlineText(r *http.Request, code, fallback string) string {
	key := "cdn64.online.e." + code
	if m.g.T != nil {
		if t := m.g.T(r, key); t != "" && t != key {
			return t
		}
	}
	return fallback
}

func (m *Module) onlineFail(w http.ResponseWriter, r *http.Request, err error) {
	code := onlineCode(err)
	st := http.StatusBadGateway
	switch {
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, "host not found")
		return
	case code == "no_api_key" || code == "not_configured" || code == "mode_not_available" || code == "not_online":
		st = http.StatusConflict
	case code == "api_key_rejected" || code == "plan_not_allowed" || code == "limit_reached" || code == "traffic_limit_reached" || code == "tunnel_blocked":
		st = http.StatusForbidden
	}
	writeJSON(w, st, map[string]string{"error": err.Error(), "code": code, "text": m.onlineText(r, code, err.Error())})
}

// POST /api/cdn64/online/tunnel: Tunnel anmelden bzw. pruefen und auf die Verbindung warten.
func (m *Module) apiOnlineTunnel(w http.ResponseWriter, r *http.Request) {
	m.online.op.Lock()
	c, err := m.onlineEnsureTunnel(r.Context())
	m.online.op.Unlock()
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	m.g.Audit(r, "cdn64.online.tunnel", c.Tunnel, "")
	m.onlineWait(r.Context(), 25*time.Second)
	writeJSON(w, http.StatusOK, m.onlineStatus(r.Context()))
}

// POST /api/cdn64/hosts/{id}/online {mode, healthcheck}: Namen des Hosts einschalten.
func (m *Module) apiOnlineEnable(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	in := struct {
		Mode        int  `json:"mode"`
		Healthcheck bool `json:"healthcheck"` // Online-Check auf den ersten Namen anlegen
	}{}
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in) // leer = Standard
	res, err := m.onlineEnable(r.Context(), h, in.Mode)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	out := struct {
		Results    []onlineResult `json:"results"`
		Check      string         `json:"check,omitempty"`
		CheckError string         `json:"check_error,omitempty"`
	}{Results: res}
	var on []string
	for i := range res {
		if res[i].Code != "" {
			res[i].Text = m.onlineText(r, res[i].Code, res[i].Error)
		}
		if res[i].Result == "on" {
			on = append(on, res[i].Name)
		}
	}
	if in.Healthcheck && len(on) > 0 && h.Kind != KindStream { // nur Streams: nichts fuer einen HTTP-Check
		out.Check, err = m.onlineCheck(r, h, on[0])
		if err != nil {
			out.CheckError = err.Error()
		}
	}
	m.g.Audit(r, "cdn64.online.enable", h.Names[0], "on="+strings.Join(on, ","))
	writeJSON(w, http.StatusOK, out)
}

// onlineCheck legt einen Online-Healthcheck (von ipv64 aus) auf den Namen an und merkt ihn sich.
func (m *Module) onlineCheck(r *http.Request, h *Host, name string) (string, error) {
	if m.checks == nil {
		return "", errors.New("healthchecks not running")
	}
	scheme := "http"
	if h.Kind == KindPass || h.HTTPS() {
		scheme = "https"
	}
	body, _ := json.Marshal(map[string]any{"name": trunc("CDN64: "+name, 100), "type": "http", "target": scheme + "://" + name + "/",
		"execution": "online", "tags": []string{"cdn64"}, "description": "CDN64"})
	tok, err := m.checks(r, body)
	if err != nil {
		return "", err
	}
	_, _ = m.core.Writer().ExecContext(r.Context(), `UPDATE cdn_online SET check_token = ? WHERE name = ?`, tok, name)
	return tok, nil
}

// DELETE /api/cdn64/hosts/{id}/online: alle Namen des Hosts ausschalten (DNS zurueck).
func (m *Module) apiOnlineDisable(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	if err := m.onlineDisable(r.Context(), h.ID); err != nil {
		m.onlineFail(w, r, err)
		return
	}
	m.g.Audit(r, "cdn64.online.disable", h.Names[0], "")
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/cdn64/hosts/{id}/online/pause {paused}: alle eingeschalteten Namen des Hosts pausieren bzw. fortsetzen. Die
// Server nehmen dann nichts mehr an und trennen offene Verbindungen; DNS bleibt auf den Servern (die eigene Adresse
// bleibt verborgen), der Tunnel bleibt verbunden.
func (m *Module) apiOnlinePause(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	in := struct {
		Paused bool `json:"paused"`
	}{}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	ids, err := m.onlineHostIDs(r.Context(), h)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	if err := m.onlinePause(r.Context(), ids, in.Paused); err != nil {
		m.onlineFail(w, r, err)
		return
	}
	m.g.Audit(r, "cdn64.online.pause", h.Names[0], strconv.FormatBool(in.Paused))
	w.WriteHeader(http.StatusNoContent)
}

// onlineHostIDs: Namen eines Hosts bei ipv64 - von hier eingeschaltet, sonst die des Hosts in CDN64 (Modus 3, andere
// Node).
func (m *Module) onlineHostIDs(ctx context.Context, h *Host) ([]int64, error) {
	list, err := m.onlineNames(ctx)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for _, x := range list {
		if x.HostID == h.ID {
			ids = append(ids, x.RemoteID)
		}
	}
	if len(ids) == 0 {
		foreign := m.onlineForeign(ctx)
		for _, n := range h.Names {
			if rh, ok := foreign[strings.ToLower(n)]; ok {
				ids = append(ids, rh.ID)
			}
		}
	}
	if len(ids) == 0 {
		return nil, errOnline("not_online")
	}
	return ids, nil
}

// POST /api/cdn64/online/names/{rid}/pause {paused}: ein Name des Accounts, den diese Node nicht verwaltet (Modus 3
// von ipv64.net, Name einer anderen Node).
func (m *Module) apiOnlineRemotePause(w http.ResponseWriter, r *http.Request) {
	rid, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	in := struct {
		Paused bool `json:"paused"`
	}{}
	if err != nil || rid <= 0 || json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&in) != nil {
		writeErr(w, http.StatusBadRequest, "invalid request")
		return
	}
	name := ""
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		for _, rh := range rm.Data.Hosts {
			if rh.ID == rid {
				name = rh.FQDN
			}
		}
	}
	if name == "" {
		writeErr(w, http.StatusNotFound, "name not found")
		return
	}
	if err := m.onlinePause(r.Context(), []int64{rid}, in.Paused); err != nil {
		m.onlineFail(w, r, err)
		return
	}
	m.g.Audit(r, "cdn64.online.pause", name, strconv.FormatBool(in.Paused))
	w.WriteHeader(http.StatusNoContent)
}

// onlinePause setzt die Pause bei ipv64 und holt danach den Stand (die Liste zeigt ihn sofort).
func (m *Module) onlinePause(ctx context.Context, ids []int64, paused bool) error {
	a := m.online.api
	if a == nil || !a.Ready(ctx) {
		return errOnline("no_api_key")
	}
	for _, id := range ids {
		if err := a.SetPaused(ctx, id, paused); err != nil {
			return err
		}
	}
	ov, err := a.Overview(ctx)
	m.onlineSetRemote(ov, err)
	return nil
}

// POST /api/cdn64/hosts/{id}/online/test: Selbsttest ueber srv07/srv08.
func (m *Module) apiOnlineTest(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	res, err := m.onlineSelfTest(r.Context(), h)
	if err != nil {
		m.onlineFail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------- Liste der Hosts

// onlineRow: Zustand von CDN64 online fuer eine Zeile der Host-Liste.
type onlineRow struct {
	Mode    int // 1 oder 2 (gemischt: der hoechste)
	Names   []string
	Missing int // Namen des Hosts, die (noch) nicht eingeschaltet sind (ohne Platzhalter)
	Edges   []onlineBadge
	Via     string // schwaechster Weg der verbundenen Server: quic, quic443, tls ("" = keiner verbunden)
	Status  string // active, blocked, pending ("" = noch kein Abgleich)
	Reason  string
	Paused  bool        // mindestens ein Name pausiert (Server nehmen nichts an, DNS bleibt)
	Month   onlineMonth // Zahlen der Server in diesem Monat (aus dem letzten Abgleich)
	// Foreign: die Namen sind in CDN64, aber nicht von dieser Node eingeschaltet - Modus 3 (auf ipv64.net eingerichtet)
	// oder Tunnel einer anderen Node. Die Zeile zeigt nur den Stand und bietet Pause; einschalten geht hier nicht.
	Foreign  bool
	RemoteID int64                   // erster Name bei ipv64 (Bearbeiten auf ipv64.net)
	Target   *ipv64api.CDN64Target   // Modus 3: Ziel und Cache der Server
	ACL      *ipv64api.CDN64ACL      // Erlauben-/Sperrliste auf den Servern (erster Name)
	Mappings []ipv64api.CDN64Mapping // Portmapper der Namen (Modus 3 zum Ziel, Modus 1/2 zu Streams der Node)
	WAF      bool                    // Muster-WAF (erster Name)
	JA4      string                  // Angriffs-Werkzeuge: off, count, block ("" = Portal kennt den Schutz noch nicht)
}

// onlineMonth: was srv07/srv08 fuer die Namen eines Hosts im laufenden Monat gezaehlt haben.
type onlineMonth struct {
	Bytes, Conns, Requests, Rejected int64
	Known                            bool // Zahlen von ipv64 vorhanden
}

type onlineBadge struct {
	Name      string
	State     string // direct, peer, down
	Transport string
	Via       string // quic, quic443, tls ("" = nicht verbunden)
	Sessions  int    // verbundene parallele Verbindungen (mehr als 1: Business/Company)
}

// viaOrder: Wege vom besten zum schwaechsten (die Zeile zeigt den schwaechsten verbundenen).
var viaOrder = []string{"", "quic", "quic443", "tls"}

// onlineIndex: Zustand je Host-ID (nur Hosts mit eingeschalteten Namen).
func (m *Module) onlineIndex(ctx context.Context, hosts []*Host) map[int64]*onlineRow {
	list, err := m.onlineNames(ctx)
	if err != nil {
		return nil
	}
	foreign := m.onlineForeign(ctx)
	if len(list) == 0 && len(foreign) == 0 {
		return nil
	}
	var badges []onlineBadge
	via := ""
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	if cl != nil {
		up := false
		st := cl.Status()
		for _, e := range st {
			up = up || e.Connected
		}
		for _, e := range st {
			b := onlineBadge{Name: e.Name, State: "down", Transport: e.Transport, Via: e.Via, Sessions: e.Sessions}
			if slices.Index(viaOrder, e.Via) > slices.Index(viaOrder, via) {
				via = e.Via
			}
			if e.Connected {
				b.State = "direct"
			} else if up {
				b.State = "peer"
			}
			badges = append(badges, b)
		}
	}
	remote := map[int64]ipv64api.CDN64Host{}
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		for _, h := range rm.Data.Hosts {
			remote[h.ID] = h
		}
	}
	out := map[int64]*onlineRow{}
	for _, x := range list {
		r := out[x.HostID]
		if r == nil {
			r = &onlineRow{Edges: badges, Via: via}
			out[x.HostID] = r
		}
		r.Names = append(r.Names, x.Name)
		r.Mode = max(r.Mode, x.Mode)
		if rh, ok := remote[x.RemoteID]; ok {
			tm := rh.TrafficMonth
			r.Month.Known = true
			r.Month.Bytes += tm.BytesIn + tm.BytesOut
			r.Month.Conns += tm.Conns
			r.Month.Requests += tm.Requests
			r.Month.Rejected += tm.Rejected
			r.Paused = r.Paused || rh.Paused
			r.Mappings = append(r.Mappings, rh.Mappings...)
			if r.JA4 == "" {
				r.WAF, r.JA4 = rh.WAF, rh.JA4
			}
			if r.Status != "blocked" {
				r.Status = rh.Status
				if rh.BlockedReason != nil {
					r.Reason = *rh.BlockedReason
				}
			}
		}
	}
	for _, h := range hosts {
		if r := out[h.ID]; r != nil {
			for _, n := range h.Names {
				if !strings.HasPrefix(n, "*.") && !slices.Contains(r.Names, n) {
					r.Missing++
				}
			}
			continue
		}
		for _, n := range h.Names { // nicht von hier eingeschaltet, aber in CDN64: Stand in der Zeile des Hosts
			rh, ok := foreign[strings.ToLower(n)]
			if !ok {
				continue
			}
			r := out[h.ID]
			if r == nil {
				r = &onlineRow{Foreign: true, RemoteID: rh.ID, Target: rh.Target, ACL: rh.ACL, WAF: rh.WAF, JA4: rh.JA4}
				out[h.ID] = r
			}
			r.Mappings = append(r.Mappings, rh.Mappings...)
			tm := rh.TrafficMonth
			r.Names = append(r.Names, rh.FQDN)
			r.Mode = max(r.Mode, rh.Mode)
			r.Month.Known = true
			r.Month.Bytes += tm.BytesIn + tm.BytesOut
			r.Month.Conns += tm.Conns
			r.Month.Requests += tm.Requests
			r.Month.Rejected += tm.Rejected
			r.Paused = r.Paused || rh.Paused
			if r.Status != "blocked" {
				r.Status = rh.Status
				if rh.BlockedReason != nil {
					r.Reason = *rh.BlockedReason
				}
			}
		}
	}
	return out
}

// onlineOther: Name des Accounts, den diese Node nicht verwaltet - Modus 3 (auf ipv64.net eingerichtet, die Server
// gehen direkt zum Ziel) oder Modus 1/2 ueber den Tunnel einer anderen Node. Nur Anzeige und Pause; bearbeitet wird
// er dort, wo er eingerichtet ist.
type onlineOther struct {
	ipv64api.CDN64Host
	Bytes int64 // Traffic im Monat (rein + raus)
}

// onlineForeign: Namen aus dem letzten Abgleich, die diese Node nicht eingeschaltet hat (Modus 3 von ipv64.net, Namen
// anderer Nodes), nach Name (klein).
func (m *Module) onlineForeign(ctx context.Context) map[string]ipv64api.CDN64Host {
	rm := m.online.remote.Load()
	if rm == nil || rm.Data == nil || len(rm.Data.Hosts) == 0 {
		return nil
	}
	mine := map[int64]bool{}
	if list, err := m.onlineNames(ctx); err == nil {
		for _, x := range list {
			mine[x.RemoteID] = true
		}
	}
	out := map[string]ipv64api.CDN64Host{}
	for _, h := range rm.Data.Hosts {
		if !mine[h.ID] {
			out[strings.ToLower(h.FQDN)] = h
		}
	}
	return out
}

// onlineOthers: Namen aus dem letzten Abgleich, die weder diese Node eingeschaltet hat noch zu einem Host hier gehoeren
// (die stehen in der Zeile ihres Hosts), nach Name sortiert.
func (m *Module) onlineOthers(ctx context.Context) []onlineOther {
	foreign := m.onlineForeign(ctx)
	if hl, err := m.hosts(ctx); err == nil {
		for _, h := range hl {
			for _, n := range h.Names {
				delete(foreign, strings.ToLower(n))
			}
		}
	}
	var out []onlineOther
	for _, h := range foreign {
		out = append(out, onlineOther{CDN64Host: h, Bytes: h.TrafficMonth.BytesIn + h.TrafficMonth.BytesOut})
	}
	slices.SortFunc(out, func(a, b onlineOther) int { return strings.Compare(a.FQDN, b.FQDN) })
	return out
}

// onlineStrings: Texte fuer cdn64-online.js (JSON im data-Attribut der Seite).
func (m *Module) onlineStrings(r *http.Request) string {
	if m.g.T == nil {
		return "{}"
	}
	keys := []string{"intro", "start", "retest", "close", "s_account", "s_tunnel", "s_names", "s_test", "quota", "connect", "tcp", "udp_buf",
		"skipped", "untrusted", "dns_ok", "dns_wait", "done", "partial", "failed", "hint_lan", "check_created", "check_failed", "working",
		"off_confirm", "direct", "peer", "down", "other_node", "route_error", "wait_edges", "mode2_hint", "via_quic", "via_quic443", "via_tls",
		"pause_confirm"}
	out := map[string]string{}
	for _, k := range keys {
		out[k] = m.g.T(r, "cdn64.online."+k)
	}
	for _, c := range []string{"no_api_key", "plan_not_allowed", "tunnel_down", "error"} {
		out["e."+c] = m.g.T(r, "cdn64.online.e."+c)
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// ---------------------------------------------------------------- Meldungen

// onlineGrace: so lange darf der Tunnel weg sein, bevor gemeldet wird (Neustarts der Server, kurze Netzaussetzer).
const onlineGrace = 3 * time.Minute

// onlineIdleEvery: ohne eigene Namen und ohne Tunnel holt die Node den Stand seltener (nur zur Anzeige).
const onlineIdleEvery = 5 * time.Minute

// SetNotifier haengt den Versand an (Dispatcher des Kerns; nil = keine Meldungen).
func (m *Module) SetNotifier(f func(notify.Alert)) { m.online.notify = f }

// onlineAlarm merkt sich, was gemeldet wurde.
type onlineAlarm struct {
	downSince time.Time
	downSent  bool
	blocked   map[string]bool // Name -> Sperre gemeldet
}

// onlineMonitor prueft alle 30 s: eingeschaltete Namen, aber zu keinem Server ein Tunnel -> nach onlineGrace melden,
// bei Rueckkehr Entwarnung; von ipv64 gesperrte Namen einmal melden.
func (m *Module) onlineMonitor(ctx context.Context) {
	a := &onlineAlarm{blocked: map[string]bool{}}
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.onlineCheckAlarm(ctx, a, time.Now())
	}
}

func (m *Module) onlineCheckAlarm(ctx context.Context, a *onlineAlarm, now time.Time) {
	list, err := m.onlineNames(ctx)
	if err != nil {
		return
	}
	if len(list) == 0 {
		a.downSince, a.downSent = time.Time{}, false
		return
	}
	names := make([]string, 0, len(list))
	for _, x := range list {
		names = append(names, x.Name)
	}
	label := strings.Join(names, ", ")
	up := false
	m.online.mu.Lock()
	cl := m.online.client
	m.online.mu.Unlock()
	if cl != nil {
		for _, e := range cl.Status() {
			up = up || e.Connected
		}
	}
	switch {
	case !up && a.downSince.IsZero():
		a.downSince = now
	case !up && !a.downSent && now.Sub(a.downSince) >= onlineGrace:
		a.downSent = true
		m.onlineSend(notify.KindCDNOnlineDown, label, "", "")
	case up:
		if a.downSent {
			m.onlineSend(notify.KindCDNOnlineUp, label, "", "")
		}
		a.downSince, a.downSent = time.Time{}, false
	}
	if rm := m.online.remote.Load(); rm != nil && rm.Data != nil {
		ids := map[int64]bool{}
		for _, x := range list {
			ids[x.RemoteID] = true
		}
		for _, h := range rm.Data.Hosts {
			if !ids[h.ID] {
				continue
			}
			switch {
			case h.Status == "blocked" && !a.blocked[h.FQDN]:
				a.blocked[h.FQDN] = true
				reason := ""
				if h.BlockedReason != nil {
					reason = *h.BlockedReason
				}
				m.onlineSend(notify.KindCDNOnlineBlocked, h.FQDN, reason, "")
			case h.Status != "blocked":
				delete(a.blocked, h.FQDN)
			}
		}
	}
}

func (m *Module) onlineSend(kind notify.Kind, name, reason, msg string) {
	if m.online.notify == nil {
		return
	}
	now := time.Now().UTC()
	m.log.Info("notification", "kind", kind, "name", name, "reason", reason)
	m.online.notify(notify.Alert{EventID: "cdn64-" + string(kind) + "-" + strconv.FormatInt(now.UnixNano(), 36), Kind: kind, Time: now,
		Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Reason: reason, Message: msg})
}

// ---------------------------------------------------------------- Hinweise

// udpBufferLow: Puffer fuer UDP zu klein fuer QUIC (G4; quic-go moechte 7 MiB), nur Linux.
func udpBufferLow() (int, bool) {
	b, err := os.ReadFile("/proc/sys/net/core/rmem_max")
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, false
	}
	return n, n < 7<<20
}
