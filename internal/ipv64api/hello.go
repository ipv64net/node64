package ipv64api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Node-Uebersicht auf ipv64.net (nodes.php): jede Node meldet sich mit dem zentralen API-Key (POST /node64/hello) und
// schickt bei jeder Anfrage ihre Kennung mit (X-Node64-Node). Entfernt der Nutzer die Node dort, antwortet ipv64 mit
// 403 node_removed; die Node vergisst dann Key und Healthchecks-Verknuepfung (lokale Daten bleiben).

// HeaderNode traegt die Kennung der Node bei jeder Anfrage an die API v2.
const HeaderNode = "X-Node64-Node"

// CodeNodeRemoved: die Node wurde auf ipv64.net entfernt.
const CodeNodeRemoved = "node_removed"

// Zeiten der Anmeldung
const (
	HelloEvery = 15 * time.Minute // Lebenszeichen ohne Aenderung
	helloCheck = time.Minute      // so oft wird auf Aenderungen geschaut (Modul, Verknuepfung, Name)
	helloRetry = 5 * time.Minute  // nach einem Fehler ohne Aenderung
	helloFirst = 20 * time.Second // nach dem Start
)

// HelloFeatures sagt, worueber die Node sonst mit ipv64 spricht (nur Kennungen, keine Geheimnisse).
type HelloFeatures struct {
	HCSyncLinked     bool   `json:"hc_sync_linked"`               // Healthchecks-Sync ueber die hubs verknuepft
	HubNodeID        string `json:"hub_node_id,omitempty"`        // Kennung beim hub (hc2_nodes.node_id)
	HoneypotSensorID string `json:"honeypot_sensor_id,omitempty"` // hp_sensors.sensor_id
	CDN64Tunnel      string `json:"cdn64_tunnel,omitempty"`       // cdn64o_tunnels.id
	DynDNS           bool   `json:"dyndns"`                       // DynDNS-Modul laeuft
}

// Hello ist die Anmeldung einer Node (POST /node64/hello).
type Hello struct {
	NodeID   string        `json:"node_id"`
	Name     string        `json:"name"`
	Location string        `json:"location"`
	Version  string        `json:"version"`
	OSArch   string        `json:"os_arch"`
	Mode     string        `json:"mode,omitempty"` // headless = Modus ohne Oberflaeche
	Modules  []string      `json:"modules"`        // laufende Module
	Features HelloFeatures `json:"features"`
}

// SendHello meldet die Node bei ipv64 an. 403 node_removed kommt als *APIError (IsNodeRemoved).
func (c *Client) SendHello(ctx context.Context, key string, h Hello) error {
	if h.Modules == nil {
		h.Modules = []string{}
	}
	var out struct {
		Removed bool `json:"removed"`
	}
	if err := c.do(ctx, http.MethodPost, key, "/node64/hello", h, &out); err != nil {
		return err
	}
	if out.Removed { // aeltere Antwortform: entfernt, aber 200
		return &APIError{Status: http.StatusForbidden, Code: CodeNodeRemoved, Detail: "node removed on ipv64.net"}
	}
	return nil
}

// IsNodeRemoved: ipv64 hat die Node entfernt.
func IsNodeRemoved(err error) bool { return ErrorCode(err) == CodeNodeRemoved }

// PresenceConfig verbindet die Anmeldung mit der Node.
type PresenceConfig struct {
	Client    *Client
	Key       func(ctx context.Context) string // "" = kein Key, nichts senden
	Info      func(ctx context.Context) Hello  // aktueller Stand
	Removed   func(ctx context.Context) bool   // true = entfernt, nicht mehr melden (bis ein neuer Key kommt)
	OnRemoved func(ctx context.Context)        // einmal je Entfernung
	Log       *slog.Logger
}

// Presence meldet die Node beim Start, alle 15 Minuten und kurz nach Aenderungen an.
type Presence struct {
	cfg PresenceConfig
	now func() time.Time

	mu       sync.Mutex
	last     string    // zuletzt gesendeter Stand (JSON)
	lastOK   time.Time // letzte angenommene Anmeldung
	lastTry  time.Time
	failed   bool
	lastErr  string
	removedN bool // Entfernung schon behandelt (bis der Key wieder geht)
}

// NewPresence erzeugt die Anmeldung (Log nil = Standard).
func NewPresence(cfg PresenceConfig) *Presence {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Presence{cfg: cfg, now: time.Now}
}

// Run meldet bis ctx endet.
func (p *Presence) Run(ctx context.Context) {
	t := time.NewTimer(helloFirst)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		p.Tick(ctx)
		t.Reset(helloCheck)
	}
}

// Tick sendet, wenn noetig: Stand geaendert, Lebenszeichen faellig oder Wiederholung nach einem Fehler.
func (p *Presence) Tick(ctx context.Context) {
	if p.cfg.Removed != nil {
		if p.cfg.Removed(ctx) {
			return
		}
		p.mu.Lock()
		p.removedN = false // Merker aufgehoben (neuer Key): eine erneute Entfernung wieder behandeln
		p.mu.Unlock()
	}
	key := p.cfg.Key(ctx)
	if key == "" {
		return
	}
	h := p.cfg.Info(ctx)
	if h.NodeID == "" {
		return
	}
	raw, _ := json.Marshal(h)
	cur := string(raw)
	now := p.now()
	p.mu.Lock()
	due := cur != p.last || now.Sub(p.lastOK) >= HelloEvery
	if p.failed && cur == p.last && now.Sub(p.lastTry) < helloRetry {
		due = false
	}
	p.mu.Unlock()
	if !due {
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	err := p.cfg.Client.SendHello(cctx, key, h)
	cancel()
	p.mu.Lock()
	p.last, p.lastTry, p.failed = cur, now, err != nil
	if err == nil {
		p.lastOK, p.lastErr, p.removedN = now, "", false
	}
	handled := p.removedN
	if IsNodeRemoved(err) {
		p.removedN = true
	}
	p.mu.Unlock()
	switch {
	case err == nil:
		p.cfg.Log.Debug("ipv64 hello sent", "node", h.NodeID)
	case IsNodeRemoved(err):
		if !handled {
			p.cfg.Log.Warn("this node was removed on ipv64.net: api key and healthchecks link are cleared, local data stays")
			if p.cfg.OnRemoved != nil {
				p.cfg.OnRemoved(ctx)
			}
		}
	default:
		p.mu.Lock()
		same := p.lastErr == err.Error()
		p.lastErr = err.Error()
		p.mu.Unlock()
		if !same { // gleichen Fehler nur einmal melden
			p.cfg.Log.Info("ipv64 hello failed", "err", err)
		}
	}
}
