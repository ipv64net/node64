package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/promscrape"
	"github.com/ipv64net/node64/internal/monitor64/transport"
	"github.com/ipv64net/node64/internal/secrets"
)

// Sammler je Zugang (Agent, SSH ohne Agent) und Schluessel der Node.

const (
	collectReserve = 2 * time.Second // vom Zeitlimit der Runde fuer die Auswertung nach der Abfrage zurueckhalten
	slowStaleAfter = 3               // SSH: langsame Werte nach so vielen verpassten Intervallen verwerfen
)

// slowTimeout: Zeitlimit des langsamen SSH-Laufs (SMART, Updates), getrennt von der Abfragerunde.
var slowTimeout = 5 * time.Minute

// nodeKeyMu verhindert, dass zwei gleichzeitige erste Aufrufe je einen Schluessel erzeugen.
var nodeKeyMu sync.Mutex

// nodeSigner liefert den Schluessel der Node (erzeugt ihn beim ersten Mal).
func (m *Module) nodeSigner(ctx context.Context) (ssh.Signer, error) {
	return loadNodeKey(ctx, m.st, m.box, m.log, m.st.SettingOr(ctx, "node.name", "node"))
}

// settingStore ist der Teil des Kern-Stores, den der Schluessel der Node braucht.
type settingStore interface {
	Setting(ctx context.Context, key string) (string, bool, error)
	SetSetting(ctx context.Context, key, value string) error
}

// loadNodeKey liest den Schluessel der Node; nur wenn der Eintrag wirklich fehlt, wird ein neuer erzeugt. Ein
// Lesefehler ist ein Fehler (sonst wuerde der Schluessel ueberschrieben und alle Agents waeren ausgesperrt).
func loadNodeKey(ctx context.Context, st settingStore, box *secrets.Box, log *slog.Logger, nodeName string) (ssh.Signer, error) {
	nodeKeyMu.Lock()
	defer nodeKeyMu.Unlock()
	enc, ok, err := st.Setting(ctx, setNodeKey)
	if err != nil {
		return nil, fmt.Errorf("monitor64: node key: %w", err)
	}
	if ok && enc != "" {
		pem, err := box.Decrypt(enc)
		if err != nil {
			return nil, fmt.Errorf("monitor64: node key: %w", err)
		}
		return transport.ParseKey([]byte(pem))
	}
	pem, signer, err := transport.GenerateKey("node64@" + nodeName)
	if err != nil {
		return nil, err
	}
	if err := st.SetSetting(ctx, setNodeKey, box.Encrypt(string(pem))); err != nil {
		return nil, err
	}
	if log != nil {
		log.Info("monitor64: node key created", "fingerprint", transport.Fingerprint(signer.PublicKey()))
	}
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
	// Prometheus: eigene Metriken (beliebige Exporter)
	Metrics []promscrape.CustomMetric `json:"metrics,omitempty"`
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
	switch a.Type {
	case "agent", "ssh":
	default:
		return m.newAPICollector(a, h, cfg, secret)
	}
	pool := m.pool
	if pool == nil {
		return nil, transport.ErrClosed
	}
	signer, err := m.nodeSigner(ctx)
	if err != nil {
		return nil, err
	}
	ref := &poolRef{pool: pool, key: a.UID, hostKey: a.HostKey}
	onKey := func(fp string) { // TOFU: ersten Hostschluessel merken
		ref.learn(fp)
		a.HostKey = fp
		if err := m.store.SetHostKey(context.Background(), a.UID, fp); err != nil {
			m.log.Warn("monitor64: save host key", "err", err)
		}
	}
	if a.Type == "agent" {
		ac := transport.AgentConfig{Addr: accessAddr(h.Address, cfg.Port, m64proto.DefaultPort), Signer: signer, OnHostKey: onKey}
		if _, err := ref.agent(ac); err != nil {
			return nil, err
		}
		return &agentCollector{ref: ref, cfg: ac}, nil
	}
	sc := transport.SSHConfig{Addr: accessAddr(h.Address, cfg.Port, 22), User: firstNonEmpty(cfg.User, "monitor64"), OnHostKey: onKey}
	if secret != "" {
		sc.Password = secret // Ausnahme: System ohne Schluessel-Anmeldung
	} else {
		sc.Signer = signer
	}
	if _, err := ref.ssh(sc); err != nil {
		return nil, err
	}
	return newSSHCollector(ref, sc, cfg.Smart), nil
}

// accessAddr: Adresse mit Port. Ein im Zugang gesetzter Port gilt vor einem Port in der Adresse des Hosts; sonst
// bleibt ein Port in der Adresse, ohne beide gilt def.
func accessAddr(addr string, port, def int) string {
	if port > 0 {
		return transport.HostPort(transport.SplitHost(addr), port)
	}
	return transport.HostPort(addr, def)
}

// hostPort ergaenzt den Standard-Port (vorhandenen Port respektieren, IPv6 in Klammern).
func hostPort(host string, port int) string { return transport.HostPort(host, port) }

// withReserve kuerzt das Zeitlimit um collectReserve, damit nach einer abgelaufenen Abfrage noch Zeit fuer die
// Auswertung bleibt.
func withReserve(ctx context.Context) (context.Context, context.CancelFunc) {
	if d, ok := ctx.Deadline(); ok && time.Until(d) > 2*collectReserve {
		return context.WithDeadline(ctx, d.Add(-collectReserve))
	}
	return context.WithCancel(ctx)
}

// poolRef holt den Client eines Zugangs in jeder Runde aus dem Pool. Damit zaehlt jede Runde als Nutzung, ein
// verworfener Client wird neu gebaut, und ein per TOFU gelernter Hostschluessel haelt den Client. close entfernt
// den Eintrag, damit ReloadHost bzw. "neuen uebernehmen" wirklich einen neuen Client bauen.
type poolRef struct {
	pool *transport.Pool
	key  string

	mu      sync.Mutex
	hostKey string
	closed  bool
}

func (r *poolRef) learn(fp string) {
	r.mu.Lock()
	r.hostKey = fp
	r.mu.Unlock()
}

func (r *poolRef) agent(cfg transport.AgentConfig) (*transport.AgentClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, transport.ErrClosed
	}
	cfg.HostKey = r.hostKey
	return r.pool.Agent(r.key, cfg)
}

func (r *poolRef) ssh(cfg transport.SSHConfig) (*transport.SSHClient, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, transport.ErrClosed
	}
	cfg.HostKey = r.hostKey
	return r.pool.SSH(r.key, cfg)
}

func (r *poolRef) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.pool.Remove(r.key)
	}
}

// agentCollector fragt den Monitor64-Agent ab.
type agentCollector struct {
	ref  *poolRef
	cfg  transport.AgentConfig
	prev *m64proto.Report
}

func (a *agentCollector) collect(ctx context.Context) ([]model.Service, error) {
	c, err := a.ref.agent(a.cfg)
	if err != nil {
		return nil, transport.CleanError(err)
	}
	ctx, cancel := withReserve(ctx)
	defer cancel()
	rep, err := c.Collect(ctx)
	if err != nil {
		return nil, err // vom Transport schon gekuerzt/bereinigt bzw. *TimeoutError
	}
	out := MapReport(a.prev, rep)
	a.prev = rep
	return out, sectionErrors(rep)
}

// sectionErrors: Abschnitte, die der Host nicht lesen konnte, als Teilfehler (die dort fehlenden Dienste gelten dann
// nicht als "verschwunden", der Zugang zeigt den Fehler).
func sectionErrors(rep *m64proto.Report) error {
	if rep == nil || len(rep.Errors) == 0 {
		return nil
	}
	pe := &apis.PartialError{}
	seen := map[string]bool{}
	for _, e := range rep.Errors {
		if len(pe.Errs) < 5 {
			pe.Errs = append(pe.Errs, transport.CleanError(errors.New(e.Section+": "+e.Error)).Error())
		}
		sec, _, _ := strings.Cut(e.Section, ":")
		for _, p := range sectionPrefixes[sec] {
			if !seen[p] {
				seen[p] = true
				pe.Prefixes = append(pe.Prefixes, p)
			}
		}
		if len(sectionPrefixes[sec]) == 0 && !seen["?"] { // unbekannter Abschnitt: vorsichtig alle Dienste halten
			seen["?"] = true
			pe.Prefixes = append(pe.Prefixes, "")
		}
	}
	sort.Strings(pe.Prefixes)
	return pe
}

// sectionPrefixes: welche Dienste ein Abschnitt des Berichts liefert (fuer "verschwunden" bei Teilfehlern).
var sectionPrefixes = map[string][]string{
	m64proto.SecCPU: {"cpu"}, m64proto.SecMem: {"mem", "swap"}, m64proto.SecLoad: {"load"}, m64proto.SecFS: {"fs:"},
	m64proto.SecDisk: {"disk:"}, m64proto.SecSmart: {"disk:"}, m64proto.SecNet: {"if:"}, m64proto.SecBond: {"bond:"},
	m64proto.SecRAID: {"raid:"}, m64proto.SecZFS: {"zfs:"}, m64proto.SecTemp: {"temp:"}, m64proto.SecSystemd: {"systemd"},
	m64proto.SecUpdates: {"updates"}, m64proto.SecReboot: {"reboot"}, m64proto.SecLocal: {"local:"}, m64proto.SecWinSvc: {"winsvc"},
}

func (a *agentCollector) close() { a.ref.close() }

// sshCollector fuehrt das feste Skript per SSH aus (ohne Agent). Jede Runde laeuft nur der schnelle Teil (ohne
// Argumente). SMART und Updates laufen getrennt in einer eigenen Goroutine mit eigenem Zeitlimit (slowTimeout);
// ihr Ergebnis wird gepuffert und in die schnellen Laeufe eingemischt. Der Zeitpunkt wird auch bei Fehler oder
// Zeitlimit gesetzt (kein Dauerversuch); der Fehler bleibt bis zum naechsten Lauf als Hinweis im Bericht.
type sshCollector struct {
	ref   *poolRef
	cfg   transport.SSHConfig
	smart bool
	now   func() time.Time
	prev  *m64proto.Report // nur in collect (Runden laufen nie gleichzeitig)

	life   context.Context
	cancel context.CancelFunc

	mu          sync.Mutex // Felder des langsamen Laufs
	running     bool
	ran         bool // mindestens ein langsamer Lauf beendet
	lastSmart   time.Time
	lastUpdates time.Time
	smartPart   slowPart
	updPart     slowPart
}

// slowPart ist das gepufferte Ergebnis eines langsamen Abschnitts.
type slowPart struct {
	ok    time.Time // letzter erfolgreicher Lauf (Null = nie)
	smart []m64proto.SMART
	upd   *m64proto.Updates
	boot  *m64proto.Reboot // needs-restarting laeuft nur im Updates-Lauf
	notes []m64proto.SectionNote
	errs  []m64proto.SectionErr
}

func newSSHCollector(ref *poolRef, cfg transport.SSHConfig, smart bool) *sshCollector {
	life, cancel := context.WithCancel(context.Background())
	return &sshCollector{ref: ref, cfg: cfg, smart: smart, now: time.Now, life: life, cancel: cancel}
}

func (s *sshCollector) collect(ctx context.Context) ([]model.Service, error) {
	now := s.now()
	c, err := s.ref.ssh(s.cfg)
	if err != nil {
		return nil, transport.CleanError(err)
	}
	ctx, cancel := withReserve(ctx)
	defer cancel()
	out, err := c.Run(ctx, m64linux.Script)
	if err != nil && len(out) == 0 {
		return nil, err // vom Transport schon gekuerzt/bereinigt bzw. *TimeoutError
	}
	rep, perr := m64linux.ParseScriptOutput(out, now)
	if perr != nil {
		return nil, transport.CleanError(perr)
	}
	if done := s.startSlow(now); done != nil {
		// Erster langsamer Lauf: im Rahmen dieser Runde auf das Ergebnis warten, damit SMART/Updates nicht erst
		// eine Runde spaeter auftauchen. Die schnellen Werte sind schon da.
		select {
		case <-done:
		case <-ctx.Done():
		}
	}
	s.merge(rep, now)
	svcs := MapReport(s.prev, rep)
	s.prev = rep
	return svcs, sectionErrors(rep)
}

// startSlow startet den langsamen Lauf, wenn er faellig ist und keiner laeuft. done ist nur beim allerersten Lauf
// gesetzt (sonst nil: nicht warten).
func (s *sshCollector) startSlow(now time.Time) (done chan struct{}) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running || s.life.Err() != nil {
		return nil
	}
	doSmart := s.smart && now.Sub(s.lastSmart) >= smartEvery
	doUpd := now.Sub(s.lastUpdates) >= updatesEvery
	if !doSmart && !doUpd {
		return nil
	}
	var args []string
	if doSmart {
		args = append(args, m64linux.ScriptArgSmart)
		s.lastSmart = now // auch bei Fehler: naechster Versuch erst nach smartEvery
	}
	if doUpd {
		args = append(args, m64linux.ScriptArgUpdates)
		s.lastUpdates = now
	}
	s.running = true
	ch := make(chan struct{})
	go s.runSlow(args, doSmart, doUpd, ch)
	if s.ran {
		return nil
	}
	return ch
}

func (s *sshCollector) runSlow(args []string, doSmart, doUpd bool, done chan struct{}) {
	defer close(done)
	ctx, cancel := context.WithTimeout(s.life, slowTimeout)
	defer cancel()
	var rep *m64proto.Report
	c, err := s.ref.ssh(s.cfg)
	if err == nil {
		var out []byte
		out, err = c.Run(ctx, m64linux.Script, args...)
		if err == nil || len(out) > 0 {
			var perr error
			if rep, perr = m64linux.ParseScriptOutput(out, s.now()); perr != nil {
				rep, err = nil, perr
			}
		}
	}
	errText := ""
	if rep == nil && err != nil {
		errText = transport.CleanError(err).Error()
	}
	at := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.running, s.ran = false, true
	if doSmart {
		s.smartPart.update(rep, errText, m64proto.SecSmart, at)
	}
	if doUpd {
		s.updPart.update(rep, errText, m64proto.SecUpdates, at)
	}
}

// update uebernimmt das Ergebnis eines langsamen Laufs fuer den Abschnitt sec (bei Fehler bleiben die alten Werte).
func (p *slowPart) update(rep *m64proto.Report, errText, sec string, at time.Time) {
	p.notes, p.errs = nil, nil
	if rep == nil {
		msg := "langsame Abfrage fehlgeschlagen: " + errText
		if p.ok.IsZero() {
			p.errs = append(p.errs, m64proto.SectionErr{Section: sec, Error: msg})
		} else {
			p.notes = append(p.notes, m64proto.SectionNote{Section: sec, Note: msg})
		}
		return
	}
	p.ok = at
	p.smart, p.upd, p.boot = rep.SMART, rep.Updates, rep.Reboot
	for _, n := range rep.Notes {
		switch n.Section {
		case sec:
			p.notes = append(p.notes, n)
		case "script": // Ausgabe unvollstaendig (Zeitlimit eines Programms)
			p.notes = append(p.notes, m64proto.SectionNote{Section: sec, Note: n.Note})
		}
	}
	for _, e := range rep.Errors {
		if e.Section == sec {
			p.errs = append(p.errs, e)
		}
	}
}

// merge mischt die gepufferten langsamen Werte in den Bericht des schnellen Laufs.
func (s *sshCollector) merge(rep *m64proto.Report, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.smart {
		if len(rep.SMART) == 0 && s.smartPart.fresh(now, smartEvery) {
			rep.SMART = slices.Clone(s.smartPart.smart)
		}
		s.smartPart.addTo(rep, now, smartEvery, m64proto.SecSmart)
	}
	if rep.Updates == nil && s.updPart.fresh(now, updatesEvery) {
		if u := s.updPart.upd; u != nil {
			c := *u
			rep.Updates = &c
		}
	}
	if b := s.updPart.boot; b != nil && b.Required && s.updPart.fresh(now, updatesEvery) {
		if rep.Reboot == nil || !rep.Reboot.Required { // Neustart noetig aus dem letzten Updates-Lauf (RHEL: needs-restarting)
			c := *b
			rep.Reboot = &c
		}
	}
	s.updPart.addTo(rep, now, updatesEvery, m64proto.SecUpdates)
}

// fresh: es gibt Werte, und sie sind nicht zu alt (sonst gilt der Abschnitt als nicht lesbar).
func (p *slowPart) fresh(now time.Time, every time.Duration) bool {
	return !p.ok.IsZero() && now.Sub(p.ok) <= slowStaleAfter*every
}

// addTo haengt Hinweise und Fehler des Abschnitts an. Sind die Werte verworfen (zu alt), werden die Hinweise zu
// Fehlern (Grund fuer "Unbekannt").
func (p *slowPart) addTo(rep *m64proto.Report, now time.Time, every time.Duration, sec string) {
	if !p.ok.IsZero() && !p.fresh(now, every) {
		for _, n := range p.notes {
			rep.Errors = append(rep.Errors, m64proto.SectionErr{Section: sec, Error: n.Note})
		}
	} else {
		rep.Notes = append(rep.Notes, p.notes...)
	}
	rep.Errors = append(rep.Errors, p.errs...)
}

func (s *sshCollector) close() {
	s.cancel()
	s.ref.close()
}
