// Package ops ueberwacht den Betrieb der hubs und alarmiert den Betreiber (nicht die Nutzer):
// Erreichbarkeit der anderen hubs (ueber das Internet, unabhaengig von der Datenbank) und die
// eigene Datenbankverbindung. Die Kanaele stehen in config.yaml (ops.alerts), damit Alarme auch
// bei ausgefallener Datenbank rausgehen.
package ops

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Alert ist ein Kanal aus der Konfiguration.
type Alert struct {
	Type   string            `yaml:"type"` // pushover, ntfy, telegram, webhook, smtp, discord, gotify, ipv64_mail, ipv64_sms
	Name   string            `yaml:"name"`
	UserID int64             `yaml:"userid"` // nur fuer ipv64_sms (Tageslimit des Accounts)
	Config map[string]string `yaml:"config"`
}

// Config ist der Abschnitt ops in config.yaml.
type Config struct {
	Peers           []string `yaml:"peers"` // https://hc-srv02.ipv64.net
	Alerts          []Alert  `yaml:"alerts"`
	IntervalSeconds int      `yaml:"interval_seconds"` // Standard 60
	FailAfter       int      `yaml:"fail_after"`       // Fehlversuche bis Alarm, Standard 3
	RepeatMinutes   int      `yaml:"repeat_minutes"`   // Erinnerung bei anhaltendem Ausfall, Standard 60, negativ = aus
}

type probe struct {
	name     string // Anzeige
	fails    int
	oks      int
	down     bool
	since    time.Time
	lastErr  string
	reminded time.Time
}

// Watcher fuehrt die Pruefungen aus.
type Watcher struct {
	cfg     Config
	self    string // Name dieser Instanz (hc-srv01)
	selfLoc string // Standortname
	db      *sql.DB
	senders map[notify.Type]notify.Sender
	log     *slog.Logger
	client  *http.Client

	mu     sync.Mutex
	probes map[string]*probe
	dbOK   bool
	dbErr  string
}

// New erzeugt den Watcher.
func New(cfg Config, self, selfLoc string, db *sql.DB, senders map[notify.Type]notify.Sender, log *slog.Logger) *Watcher {
	if cfg.IntervalSeconds <= 0 {
		cfg.IntervalSeconds = 60
	}
	if cfg.FailAfter <= 0 {
		cfg.FailAfter = 3
	}
	if cfg.RepeatMinutes < 0 {
		cfg.RepeatMinutes = 0
	} else if cfg.RepeatMinutes == 0 {
		cfg.RepeatMinutes = 60
	}
	w := &Watcher{cfg: cfg, self: self, selfLoc: selfLoc, db: db, senders: senders, log: log.With("module", "ops"),
		client: &http.Client{Timeout: 10 * time.Second}, probes: map[string]*probe{}, dbOK: true}
	for _, p := range cfg.Peers {
		w.probes[p] = &probe{name: strings.TrimPrefix(strings.TrimPrefix(p, "https://"), "http://")}
	}
	w.probes["db"] = &probe{name: "Datenbank (von " + self + ")"}
	return w
}

// DBStatus fuer /v1/health: "ok" oder Fehlertext.
func (w *Watcher) DBStatus() (bool, string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dbOK, w.dbErr
}

// Run prueft im Intervall, bis ctx endet.
func (w *Watcher) Run(ctx context.Context) {
	w.log.Info("ops watcher started", "peers", len(w.cfg.Peers), "alert_channels", len(w.cfg.Alerts))
	t := time.NewTicker(time.Duration(w.cfg.IntervalSeconds) * time.Second)
	defer t.Stop()
	w.round(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.round(ctx)
		}
	}
}

func (w *Watcher) round(ctx context.Context) {
	// eigene Datenbank
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	var one int
	err := w.db.QueryRowContext(dctx, "SELECT 1").Scan(&one)
	cancel()
	w.mu.Lock()
	w.dbOK, w.dbErr = err == nil, ""
	if err != nil {
		w.dbErr = err.Error()
	}
	w.mu.Unlock()
	w.result(ctx, "db", err)
	// andere hubs
	for _, url := range w.cfg.Peers {
		w.result(ctx, url, w.probePeer(ctx, url))
	}
}

func (w *Watcher) probePeer(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/v1/health", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "ipv64-hub-ops/"+w.self)
	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var h struct {
		Status string `json:"status"`
		DB     string `json:"db"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		return fmt.Errorf("invalid health answer: %w", err)
	}
	if h.Status != "ok" {
		return fmt.Errorf("status %s (db: %s)", h.Status, h.DB)
	}
	return nil
}

func (w *Watcher) result(ctx context.Context, key string, err error) {
	w.mu.Lock()
	p := w.probes[key]
	now := time.Now()
	var send func()
	if err != nil {
		p.fails++
		p.oks = 0
		p.lastErr = err.Error()
		if !p.down && p.fails >= w.cfg.FailAfter {
			p.down, p.since, p.reminded = true, now.Add(-time.Duration(w.cfg.FailAfter*w.cfg.IntervalSeconds)*time.Second), now
			msg := p.lastErr
			name := p.name
			send = func() { w.alert(ctx, true, name, msg, 0) }
		} else if p.down && w.cfg.RepeatMinutes > 0 && now.Sub(p.reminded) >= time.Duration(w.cfg.RepeatMinutes)*time.Minute {
			p.reminded = now
			name, msg, dur := p.name, p.lastErr, now.Sub(p.since)
			send = func() { w.alert(ctx, true, name, msg+" (weiterhin)", dur) }
		}
	} else {
		p.oks++
		if p.down && p.oks >= 2 {
			p.down = false
			name, dur := p.name, now.Sub(p.since)
			send = func() { w.alert(ctx, false, name, "", dur) }
		}
		if !p.down {
			p.fails = 0
		}
	}
	w.mu.Unlock()
	if send != nil {
		send()
	}
}

func (w *Watcher) alert(ctx context.Context, down bool, what, reason string, dur time.Duration) {
	m := notify.Message{Time: time.Now().UTC(), Language: "de", EventID: fmt.Sprintf("ops-%d", time.Now().UnixNano()), URL: "https://ipv64.net/"}
	if down {
		m.Kind, m.Priority = notify.KindDown, 5
		m.Title = "🔴 ipv64 hub: " + what + " gestört"
		m.Text = "Gemeldet von " + w.self + " (" + w.selfLoc + ").\nGrund: " + reason
		if dur > 0 {
			m.Text += "\nDauer bisher: " + dur.Round(time.Minute).String()
		}
	} else {
		m.Kind, m.Priority = notify.KindUp, 3
		m.Title = "✅ ipv64 hub: " + what + " wieder OK"
		m.Text = "Gemeldet von " + w.self + " (" + w.selfLoc + ").\nAusfall: " + dur.Round(time.Minute).String()
	}
	m.Text += "\nZeit: " + m.Time.Format("02.01.2006 15:04") + " UTC"
	m.Check = notify.CheckInfo{Name: "ipv64 hub " + what}
	m.Payload = map[string]any{"kind": string(m.Kind), "title": m.Title, "text": m.Text, "time": m.Time.Format(time.RFC3339), "reporter": w.self, "target": what, "ops": true}
	w.log.Warn("ops alert", "down", down, "target", what, "reason", reason)
	w.send(ctx, m)
}

func (w *Watcher) send(ctx context.Context, m notify.Message) {
	if m.Payload == nil {
		m.Payload = map[string]any{"kind": string(m.Kind), "title": m.Title, "text": m.Text, "time": m.Time.Format(time.RFC3339), "reporter": w.self, "ops": true}
	}
	if len(w.cfg.Alerts) == 0 {
		w.log.Warn("ops alert not sent: no channels configured (ops.alerts)", "title", m.Title)
	}
	for _, a := range w.cfg.Alerts {
		s, ok := w.senders[notify.Type(a.Type)]
		if !ok {
			w.log.Error("ops alert: unknown channel type", "type", a.Type)
			continue
		}
		ch := &notify.Channel{UserID: a.UserID, Type: notify.Type(a.Type), Name: a.Name, Config: a.Config, Enabled: true, Lang: "de", NotifyDown: true, NotifyUp: true, Execution: "server"}
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := s.Send(sctx, ch, m)
		cancel()
		if err != nil {
			w.log.Error("ops alert failed", "channel", a.Name, "type", a.Type, "err", err)
		}
	}
}

// Test schickt eine Testnachricht an alle Kanaele (hub -ops-test).
func (w *Watcher) Test(ctx context.Context) {
	w.send(ctx, notify.Message{Kind: notify.KindTest, Priority: 3, Time: time.Now().UTC(), Language: "de", EventID: fmt.Sprintf("ops-test-%d", time.Now().UnixNano()),
		Title: "🔔 ipv64 hub: Test der Betriebsalarme", Text: "Testnachricht von " + w.self + " (" + w.selfLoc + "). Wenn du das liest, kommen Betriebsalarme an.",
		Check: notify.CheckInfo{Name: "ipv64 hub"}, URL: "https://ipv64.net/"})
}

func fmtDur(d time.Duration) string {
	m := int(d.Round(time.Minute).Minutes())
	switch {
	case m < 1:
		return "1 min"
	case m < 60:
		return fmt.Sprintf("%d min", m)
	default:
		return fmt.Sprintf("%d h %d min", m/60, m%60)
	}
}
