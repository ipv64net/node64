package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/eval"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// Laufzeit der Hosts: Schluessel der Node, Sammler je Zugang, Auftraege im Planer, Laufzeitstand speichern.

const (
	setNodeKey   = "monitor64.node_key" // privater Schluessel der Node (verschluesselt, OpenSSH-PEM)
	saveEvery    = 5 * time.Minute      // Laufzeitstand je Host hoechstens so oft speichern (ausser bei Zustandswechsel)
	smartEvery   = 30 * time.Minute     // SSH ohne Agent: SMART lesen
	updatesEvery = time.Hour            // SSH ohne Agent: Paket-Updates pruefen
)

// nodeSigner liefert den Schluessel der Node (erzeugt ihn beim ersten Mal).
func (m *Module) nodeSigner(ctx context.Context) (ssh.Signer, error) {
	if enc := m.st.SettingOr(ctx, setNodeKey, ""); enc != "" {
		pem, err := m.box.Decrypt(enc)
		if err != nil {
			return nil, fmt.Errorf("monitor64: node key: %w", err)
		}
		return transport.ParseKey([]byte(pem))
	}
	pem, signer, err := transport.GenerateKey("node64@" + m.st.SettingOr(ctx, "node.name", "node"))
	if err != nil {
		return nil, err
	}
	if err := m.st.SetSetting(ctx, setNodeKey, m.box.Encrypt(string(pem))); err != nil {
		return nil, err
	}
	m.log.Info("monitor64: node key created", "fingerprint", transport.Fingerprint(signer.PublicKey()))
	return signer, nil
}

// PublicKeyLine ist die Zeile fuer authorized_keys bzw. den Installationsbefehl des Agents.
func (m *Module) PublicKeyLine(ctx context.Context) (string, error) {
	s, err := m.nodeSigner(ctx)
	if err != nil {
		return "", err
	}
	return transport.AuthorizedKeyLine(s.PublicKey(), "node64@"+m.st.SettingOr(ctx, "node.name", "node")), nil
}

// startHosts laedt alle Hosts und plant ihre Abfragen ein.
func (m *Module) startHosts(ctx context.Context) error {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		m.scheduleHost(ctx, h)
	}
	return nil
}

// ReloadHost plant einen Host nach einer Aenderung neu ein (bzw. entfernt ihn).
func (m *Module) ReloadHost(ctx context.Context, uid string) {
	h, err := m.store.Host(ctx, uid)
	if errors.Is(err, ErrNotFound) {
		m.removeHost(uid)
		return
	}
	if err != nil {
		m.log.Warn("monitor64: reload host", "host", uid, "err", err)
		return
	}
	m.removeHost(uid)
	m.scheduleHost(ctx, h)
}

func (m *Module) removeHost(uid string) {
	if s := m.scheduler(); s != nil {
		s.Remove("host:" + uid)
	}
	m.rtMu.Lock()
	rt := m.rts[uid]
	delete(m.rts, uid)
	m.rtMu.Unlock()
	if rt != nil {
		rt.mu.Lock()
		for _, a := range rt.accs {
			if a.col != nil {
				a.col.close()
			}
		}
		rt.mu.Unlock()
	}
}

func (m *Module) scheduleHost(ctx context.Context, h *Host) {
	sched := m.scheduler()
	if sched == nil {
		return
	}
	rt := &hostRT{host: h, Trackers: map[string]*eval.Tracker{}, Failures: map[string]int{}}
	var mem *eval.HostMemory
	if raw, _ := m.store.Runtime(ctx, h.UID); len(raw) > 0 {
		var saved struct {
			RT  json.RawMessage  `json:"rt"`
			Mem *eval.HostMemory `json:"mem"`
		}
		if json.Unmarshal(raw, &saved) == nil {
			_ = json.Unmarshal(saved.RT, rt)
			mem = saved.Mem
		}
		if rt.Trackers == nil {
			rt.Trackers = map[string]*eval.Tracker{}
		}
		if rt.Failures == nil {
			rt.Failures = map[string]int{}
		}
		rt.LastDisc = time.Time{} // nach dem (Neu-)Laden sofort erkennen (z. B. neuer Zugang)
	}
	m.notifyMu.Lock()
	if m.notifier.Hosts == nil {
		m.notifier.Hosts = map[string]*eval.HostMemory{}
	}
	if mem != nil {
		m.notifier.Hosts[h.UID] = mem
	}
	m.notifyMu.Unlock()
	accs, err := m.store.Accesses(ctx, h.UID)
	if err != nil {
		m.log.Warn("monitor64: accesses", "host", h.Name, "err", err)
	}
	for _, a := range accs {
		if !a.Enabled {
			continue
		}
		col, err := m.newCollector(ctx, h, a)
		ar := &accRT{row: a, col: col}
		if err != nil {
			ar.err = err.Error()
		}
		rt.accs = append(rt.accs, ar)
	}
	m.rtMu.Lock()
	if m.rts == nil {
		m.rts = map[string]*hostRT{}
	}
	m.rts[h.UID] = rt
	m.rtMu.Unlock()
	sched.Set("host:"+h.UID, time.Duration(h.IntervalSec)*time.Second, func(ctx context.Context) { m.poll(ctx, rt) })
}

// accessConfig ist die Konfiguration eines Zugangs (JSON ohne Geheimnisse).
type accessConfig struct {
	Port  int    `json:"port,omitempty"`
	User  string `json:"user,omitempty"`
	Smart bool   `json:"smart,omitempty"` // SSH: SMART per sudo smartctl
	// API-Zugaenge (Proxmox VE, PBS, Docker)
	URL     string `json:"url,omitempty"`
	TokenID string `json:"token_id,omitempty"`
	Node    string `json:"node,omitempty"`
	Pin     string `json:"pin,omitempty"`
}

// newCollector baut den Sammler eines Zugangs.
func (m *Module) newCollector(ctx context.Context, h *Host, a *Access) (collector, error) {
	var cfg accessConfig
	_ = json.Unmarshal(a.Config, &cfg)
	secret := ""
	if a.Secret != "" {
		s, err := m.box.Decrypt(a.Secret)
		if err != nil {
			return nil, errors.New("Zugangsdaten nicht lesbar")
		}
		secret = s
	}
	onKey := func(fp string) { // TOFU: ersten Hostschluessel merken
		a.HostKey = fp
		if err := m.store.SetHostKey(context.Background(), a.UID, fp); err != nil {
			m.log.Warn("monitor64: save host key", "err", err)
		}
	}
	addr := h.Address
	switch a.Type {
	case "agent":
		signer, err := m.nodeSigner(ctx)
		if err != nil {
			return nil, err
		}
		port := cfg.Port
		if port == 0 {
			port = m64proto.DefaultPort
		}
		c, err := m.pool.Agent(a.UID, transport.AgentConfig{Addr: hostPort(addr, port), Signer: signer, HostKey: a.HostKey, OnHostKey: onKey})
		if err != nil {
			return nil, err
		}
		return &agentCollector{c: c}, nil
	case "ssh":
		signer, err := m.nodeSigner(ctx)
		if err != nil {
			return nil, err
		}
		port := cfg.Port
		if port == 0 {
			port = 22
		}
		sc := transport.SSHConfig{Addr: hostPort(addr, port), User: firstNonEmpty(cfg.User, "monitor64"), HostKey: a.HostKey, OnHostKey: onKey}
		if secret != "" {
			sc.Password = secret // Ausnahme: System ohne Schluessel-Anmeldung
		} else {
			sc.Signer = signer
		}
		c, err := m.pool.SSH(a.UID, sc)
		if err != nil {
			return nil, err
		}
		return &sshCollector{c: c, smart: cfg.Smart}, nil
	}
	return newAPICollector(a.Type, h, cfg, secret)
}

func hostPort(host string, port int) string {
	if len(host) > 0 && host[0] != '[' && containsColon(host) {
		return fmt.Sprintf("[%s]:%d", host, port) // IPv6
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// agentCollector fragt den Monitor64-Agent ab.
type agentCollector struct {
	c    *transport.AgentClient
	prev *m64proto.Report
}

func (a *agentCollector) collect(ctx context.Context) ([]model.Service, error) {
	rep, err := a.c.Collect(ctx)
	if err != nil {
		return nil, err
	}
	out := MapReport(a.prev, rep)
	a.prev = rep
	return out, nil
}

func (a *agentCollector) close() {}

// sshCollector fuehrt das feste Skript per SSH aus (ohne Agent). Langsame Abschnitte (SMART, Updates) werden
// seltener gelesen und dazwischen aus dem letzten Bericht uebernommen.
type sshCollector struct {
	c           *transport.SSHClient
	smart       bool
	prev        *m64proto.Report
	lastSmart   time.Time
	lastUpdates time.Time
	slowSmart   []m64proto.SMART
	slowUpd     *m64proto.Updates
}

func (s *sshCollector) collect(ctx context.Context) ([]model.Service, error) {
	now := time.Now()
	var args []string
	doSmart := s.smart && now.Sub(s.lastSmart) >= smartEvery
	doUpd := now.Sub(s.lastUpdates) >= updatesEvery
	if doSmart {
		args = append(args, m64linux.ScriptArgSmart)
	}
	if doUpd {
		args = append(args, m64linux.ScriptArgUpdates)
	}
	out, err := s.c.Run(ctx, m64linux.Script, args...)
	if err != nil && len(out) == 0 {
		return nil, err
	}
	rep, perr := m64linux.ParseScriptOutput(out, now)
	if perr != nil {
		return nil, perr
	}
	if doSmart {
		s.lastSmart, s.slowSmart = now, rep.SMART
	} else if len(rep.SMART) == 0 {
		rep.SMART = s.slowSmart
	}
	if doUpd {
		s.lastUpdates, s.slowUpd = now, rep.Updates
	} else if rep.Updates == nil {
		rep.Updates = s.slowUpd
	}
	svcs := MapReport(s.prev, rep)
	s.prev = rep
	return svcs, nil
}

func (s *sshCollector) close() {}

// saveRuntime speichert den Laufzeitstand eines Hosts (Tracker, Fehlerzaehler, Gedaechtnis der Meldungen).
func (m *Module) saveRuntime(ctx context.Context, rt *hostRT, mem []byte) {
	v := rt.getView()
	changed := v != nil && (rt.lastSavedState != v.State || rt.lastSavedView != v.View)
	if !rt.dirty && !changed && time.Since(rt.lastSave) < saveEvery {
		return
	}
	rtJSON, _ := json.Marshal(rt)
	b, _ := json.Marshal(map[string]json.RawMessage{"rt": rtJSON, "mem": mem})
	if err := m.store.SaveRuntime(ctx, rt.host.UID, b); err != nil {
		m.log.Warn("monitor64: save runtime", "host", rt.host.Name, "err", err)
		return
	}
	rt.dirty, rt.lastSave = false, time.Now()
	if v != nil {
		rt.lastSavedState, rt.lastSavedView = v.State, v.View
	}
}

// Views liefert den aktuellen Stand aller Hosts (fuer die Oberflaeche).
func (m *Module) Views() []*HostView {
	m.rtMu.Lock()
	rts := make([]*hostRT, 0, len(m.rts))
	for _, rt := range m.rts {
		rts = append(rts, rt)
	}
	m.rtMu.Unlock()
	out := make([]*HostView, 0, len(rts))
	for _, rt := range rts {
		v := rt.getView()
		if v == nil {
			v = &HostView{Host: rt.host, View: eval.ViewUnknown, State: eval.Unknown}
		}
		out = append(out, v)
	}
	return out
}
