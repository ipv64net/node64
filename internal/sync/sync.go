// Package sync ist die Verbindung der Node zu ipv64.net (hub): Erstverknuepfung
// per Code, WebSocket-Dauerverbindung, Konfigurationsabgleich mit Revisionen
// (Server fuehrend), Outbox und Konflikte fuer lokale Aenderungen, Upload von
// Messpunkten, Zustaenden und Ereignissen, Kommandos und Sendeauftraege.
//
// Ablauf nach jeder Verbindung (Sync-Plan 3.9): hello -> config anwenden
// (ausstehende lokale Aenderungen derselben Entitaet werden Konflikt) ->
// Outbox abspielen -> Messpunkte/Ereignisse nachliefern.
package sync

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/wire"
)

// DefaultEndpoints sind die hub-Server, solange keine Liste vom Server vorliegt.
// NODE64_HUB_URL ueberschreibt sie (Tests).
var DefaultEndpoints = []wire.Endpoint{
	{Location: "fsn", Name: "Falkenstein", URL: "https://hc-srv01.ipv64.net"},
	{Location: "nbg", Name: "Nürnberg", URL: "https://hc-srv02.ipv64.net"},
}

// Einstellungsschluessel (Kern-Store).
const (
	SetToken         = "sync.token" // verschluesselt
	SetAccount       = "sync.account"
	SetEndpoints     = "sync.endpoints"
	SetNodeName      = "sync.node_name"
	SetLocation      = "sync.location"
	SetNodeInfoDirty = "sync.node_info_dirty" // Name/Standort lokal geaendert, noch nicht beim hub
	SetNotifyDirty   = "sync.notify_dirty"    // Benachrichtigungs-Einstellungen lokal geaendert, noch nicht beim hub
	SetRemoteMgmt    = "sync.remote_mgmt"
	SetRevision      = "sync.last_revision"
	SetAckSeq        = "sync.ack_seq"
	SetEventID       = "sync.last_event_id"
	SetLinkedAt      = "sync.linked_at"
	SetHub           = "sync.hub"
	SetPendCode      = "sync.pending_code"
	SetPendSecret    = "sync.pending_secret"
	SetPendExp       = "sync.pending_expires"
	SetLocalNotif    = "sync.local_notifications" // "1": Node alarmiert ihre Kanaele auch verknuepft
)

// State beschreibt den Verbindungszustand fuer die Anzeige im UI.
type State struct {
	Linked      bool
	Connected   bool
	AccountID   string
	Plan        string
	NodeName    string
	Location    string
	RemoteMgmt  string
	Hub         string
	LastSyncAt  string
	Outbox      int
	Conflicts   int
	LastError   string
	PendingCode string
	Requesting  bool   // Code wird gerade beim hub angefordert (laeuft im Hintergrund)
	ConnectedAt string // seit wann die aktuelle Verbindung steht
	RxBytes     int64  // Sync-Verkehr seit Start (empfangen)
	TxBytes     int64  // Sync-Verkehr seit Start (gesendet)
	OnlineLimit int    // Online-Messstellen laut Account (0 = unbegrenzt)
	ChecksToday int    // Online-Messungen und Pushes heute (Tageskontingent)
	ChecksLimit int    // Tageskontingent laut Account (0 = unbegrenzt)
	Locations   int    // Standorte je Check laut Account
	Revision    int64
	Endpoints   []wire.Endpoint
	LinkedAt    string
}

// Client ist die Verbindung zu ipv64.net.
type Client interface {
	State() State
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// Linker sind die Aktionen der Verknuepfungsseite.
type Linker interface {
	LinkStart(ctx context.Context) (code string, expires time.Time, err error)
	LinkPoll(ctx context.Context) (bool, error)
	LinkCancel()
	Unlink(ctx context.Context, keepChecks bool) error
	Resolve(ctx context.Context, id int64, keep string) error
	// TestServerChannel laesst ipv64 einen Testversand ueber einen Server-Kanal machen (Mail, SMS, App).
	TestServerChannel(ctx context.Context, remoteID int64, lang string) error
	// NodeInfoChanged: Name/Standort wurden in den Einstellungen geaendert, an ipv64 melden.
	NodeInfoChanged()
	// NotifySettingsChanged: Ruhezeiten/Grenzen geaendert, gelten fuer den Account (an ipv64 melden).
	NotifySettingsChanged()
}

// NoOp ist der Standalone-Client: nicht verknuepft, tut nichts.
type NoOp struct{}

func (NoOp) State() State                { return State{} }
func (NoOp) Start(context.Context) error { return nil }
func (NoOp) Stop(context.Context) error  { return nil }

// Deps sind die Abhaengigkeiten des echten Clients.
type Deps struct {
	Core    *store.Store
	HC      *healthchecks.Module
	NF      *notify.Store
	Box     *secrets.Box
	Version string
	Log     *slog.Logger
	Senders map[notify.Type]notify.Sender
	Modules Modules // nil = Module nicht automatisch einschalten
	// UnlinkAPI trennt die Node ueber die ipv64 API v2, wenn kein hub erreichbar ist (nil = ohne API-Key)
	UnlinkAPI func(ctx context.Context, nodeID string, keepChecks bool) error
	// DirectNotify: die Node kann Benachrichtigungen ueber die API v2 selbst verschicken (API-Key da); nil = nein
	DirectNotify func() bool
}

// Modules schaltet beim Verknuepfen das Healthchecks-Modul ein (sonst fehlen die Tabellen fuer die Checks von ipv64).
type Modules interface {
	IsRunning(name string) bool
	Enable(ctx context.Context, name string) error
}

// Live ist der echte Client.
type Live struct {
	d   Deps
	log *slog.Logger
	hc  *http.Client

	linkBusy      bool       // LinkStart laeuft gerade
	pollMu        sync.Mutex // LinkPoll nur einmal gleichzeitig (Seite und Hintergrund fragen beide)
	histMu        sync.Mutex // Nachladen des Verlaufs (history.go) nur einmal gleichzeitig
	ackOK, ackBad time.Time  // letzte Bestaetigung ohne bzw. mit Fehler (hub erreichbar, aber z. B. ohne Datenbank)
	sessionReady  bool       // aktuelle Sitzung hat hello/config erhalten
	pushOnce      sync.Once  // Warteschlange fuer weitergereichte Pushes
	pushQ         chan wire.Msg
	infoGen       atomic.Int64 // zaehlt lokale Aenderungen von Name/Standort (refreshMe ueberschreibt sie nicht)
	notifyGen     atomic.Int64 // zaehlt lokale Aenderungen der Benachrichtigungs-Einstellungen
	// hubDirect: der hub kann wire.NotifyDirect und die Node hat es ihm gemeldet; bleibt nach einer Trennung stehen
	// (der hub laesst dann bei spaet gemeldeten Zustaenden die Kanaele aus, die die Node selbst sendet)
	hubDirect atomic.Bool

	mu        sync.Mutex
	connected bool
	hub       string
	lastErr   string
	lastSync  time.Time
	connAt    time.Time
	rxBytes   atomic.Int64
	txBytes   atomic.Int64
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	running   bool
	wake      chan struct{}
	states    map[string]wire.State
	ws        *session
	// revHeld: eine Aenderung liess sich nicht anwenden, die Revision bleibt davor stehen (bis zur naechsten
	// Sitzung, die ab dort neu liefert); applyFails zaehlt Fehlschlaege je Aenderung (dauerhafte werden uebergangen)
	revHeld    bool
	applyFails map[string]int
}

// New erzeugt den Client; Start installiert die Hooks.
func New(d Deps) *Live {
	return &Live{d: d, log: d.Log.With("module", "sync"), hc: &http.Client{Timeout: 60 * time.Second}, wake: make(chan struct{}, 1), states: map[string]wire.State{}}
}

// nodeID ist die beim Setup erzeugte Kennung (node.id). Aeltere Installationen haben keine;
// dann wird sie hier einmalig erzeugt (32 Zeichen, wie beim Setup).
func (c *Live) nodeID() string {
	ctx := context.Background()
	if id := c.d.Core.SettingOr(ctx, "node.id", ""); id != "" {
		return id
	}
	b := make([]byte, 24)
	_, _ = crand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)
	c.logErr("SetSetting", c.d.Core.SetSetting(ctx, "node.id", id))
	return id
}

func (c *Live) setting(key, def string) string {
	return c.d.Core.SettingOr(context.Background(), key, def)
}

func (c *Live) set(key, val string) {
	c.logErr("save setting "+key, c.d.Core.SetSetting(context.Background(), key, val))
}

// logErr loggt einen Fehler beim Speichern des Sync-Stands (Revisionen, Zuordnungen, Postausgang, Zustellungen).
// Solche Fehler blieben sonst still und Node und hub liefen unbemerkt auseinander.
func (c *Live) logErr(what string, err error) {
	if err != nil {
		c.log.Error("sync state not saved", "what", what, "err", err)
	}
}

func (c *Live) setInt(key string, v int64) { c.set(key, strconv.FormatInt(v, 10)) }

func (c *Live) getInt(key string) int64 {
	v, _ := strconv.ParseInt(c.setting(key, "0"), 10, 64)
	return v
}

func (c *Live) token() string {
	enc := c.setting(SetToken, "")
	if enc == "" {
		return ""
	}
	if c.d.Box != nil && secrets.IsEncrypted(enc) {
		plain, err := c.d.Box.Decrypt(enc)
		if err != nil {
			return ""
		}
		return plain
	}
	return enc
}

// Linked sagt, ob ein Token vorliegt.
func (c *Live) Linked() bool { return c.token() != "" }

// AccountID: ipv64-Account der Verknuepfung (0 = nicht verknuepft), ohne den ganzen Status zu lesen (die lokale
// Gruppe fragt das bei jeder Anfrage).
func (c *Live) AccountID() int64 {
	if !c.Linked() {
		return 0
	}
	var acc struct {
		ID int64 `json:"id"`
	}
	_ = json.Unmarshal([]byte(c.setting(SetAccount, "")), &acc)
	return acc.ID
}

func (c *Live) endpoints() []wire.Endpoint {
	if u := os.Getenv("NODE64_HUB_URL"); u != "" {
		return []wire.Endpoint{{Location: "test", Name: "Test", URL: strings.TrimRight(u, "/")}}
	}
	var eps []wire.Endpoint
	if raw := c.setting(SetEndpoints, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &eps)
	}
	if len(eps) == 0 {
		eps = append([]wire.Endpoint(nil), DefaultEndpoints...)
	}
	sort.Slice(eps, func(i, j int) bool { return eps[i].URL < eps[j].URL })
	return eps
}

// ServerSends sagt, ob der hub die Benachrichtigungen gerade uebernehmen kann: verbunden und
// die letzte Bestaetigung kam ohne Fehler. Sonst sendet die Node ihre Kanaele selbst.
func (c *Live) ServerSends() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.connected {
		return false
	}
	return c.ackBad.IsZero() || c.ackOK.After(c.ackBad)
}

// HubDirect (notify.Dispatcher.SetHubDirect): der hub ueberlaesst der Node die Meldungen ihrer nur hier gemessenen
// Checks (verknuepft, hub mit wire.NotifyDirect, in der Statusmeldung angekuendigt, API-Key da).
func (c *Live) HubDirect() bool {
	return c.Linked() && c.hubDirect.Load() && c.d.DirectNotify != nil && c.d.DirectNotify()
}

func (c *Live) noteAck(ok bool) {
	c.mu.Lock()
	wasOK := c.ackBad.IsZero() || c.ackOK.After(c.ackBad)
	if ok {
		c.ackOK = time.Now()
	} else {
		c.ackBad = time.Now()
	}
	c.mu.Unlock()
	switch {
	case wasOK && !ok:
		c.log.Warn("hub not confirming (e.g. database down): node sends its own notifications")
	case !wasOK && ok:
		c.log.Info("hub confirming again: notifications via ipv64")
	}
}

// hubHealthy fragt /v1/health eines hubs ab.
func (c *Live) hubHealthy(ctx context.Context, url string) bool {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, url+"/v1/health", nil)
	if err != nil {
		return false
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var h struct {
		Status string `json:"status"`
	}
	return resp.StatusCode == 200 && json.NewDecoder(resp.Body).Decode(&h) == nil && h.Status == "ok"
}

// homeHub ist der Stamm-hub dieser Node: fest nach Node-ID verteilt (crc32), damit sich die Nodes
// gleichmaessig auf die hubs aufteilen und jede Node immer denselben bevorzugt.
func (c *Live) homeHub() string {
	eps := c.endpoints()
	return eps[int(crc32.ChecksumIEEE([]byte(c.nodeID()))%uint32(len(eps)))].URL
}

// ordered liefert die Endpunkte mit dem Stamm-hub zuerst.
func (c *Live) ordered() []wire.Endpoint {
	eps, home := c.endpoints(), c.homeHub()
	out := make([]wire.Endpoint, 0, len(eps))
	for _, e := range eps {
		if e.URL == home {
			out = append([]wire.Endpoint{e}, out...)
		} else {
			out = append(out, e)
		}
	}
	return out
}

// State liefert den Zustand fuer die Oberflaeche.
func (c *Live) State() State {
	ctx := context.Background()
	c.mu.Lock()
	st := State{Connected: c.connected, Hub: c.hub, LastError: c.lastErr, RxBytes: c.rxBytes.Load(), TxBytes: c.txBytes.Load()}
	if !c.lastSync.IsZero() {
		st.LastSyncAt = c.lastSync.UTC().Format(time.RFC3339)
	}
	if c.connected && !c.connAt.IsZero() {
		st.ConnectedAt = c.connAt.UTC().Format(time.RFC3339)
	}
	c.mu.Unlock()
	st.Linked = c.Linked()
	st.NodeName, st.Location, st.RemoteMgmt = c.setting(SetNodeName, ""), c.setting(SetLocation, ""), c.setting(SetRemoteMgmt, "")
	c.mu.Lock()
	st.Requesting = c.linkBusy
	c.mu.Unlock()
	st.LinkedAt, st.Revision = c.setting(SetLinkedAt, ""), c.getInt(SetRevision)
	st.Endpoints = c.endpoints()
	var acc wire.Account
	if raw := c.setting(SetAccount, ""); raw != "" && json.Unmarshal([]byte(raw), &acc) == nil {
		st.AccountID, st.Plan = strconv.FormatInt(acc.ID, 10), acc.Plan
		st.OnlineLimit, st.Locations = acc.Limits["healthchecks_online"], acc.Limits["locations"]
		st.ChecksToday, st.ChecksLimit = acc.Usage["checks_today"], acc.Limits["checks_per_day"]
	}
	if exp := c.setting(SetPendExp, ""); exp != "" {
		if t, err := time.Parse(time.RFC3339, exp); err == nil && time.Now().Before(t) {
			st.PendingCode = c.setting(SetPendCode, "")
		}
	}
	if c.d.HC != nil {
		st.Outbox, st.Conflicts = c.d.HC.OutboxCount(ctx), c.d.HC.ConflictCount(ctx)
	}
	return st
}

// Start installiert die Hooks und startet die Verbindung, wenn verknuepft.
func (c *Live) Start(ctx context.Context) error {
	c.d.HC.Store().OnChange = c.onChange
	c.d.HC.Store().OnRuntime = c.onRuntime
	notify.OnChange = c.onChannelChange
	if c.Linked() {
		c.startLoop(ctx)
	} else if code := c.setting(SetPendCode, ""); code != "" {
		if exp, err := time.Parse(time.RFC3339, c.setting(SetPendExp, "")); err == nil && time.Now().Before(exp) {
			go c.pollPending(code, exp) // offener Code vom letzten Lauf
		}
	}
	return nil
}

func (c *Live) startLoop(ctx context.Context) {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	ctx, c.cancel = context.WithCancel(ctx)
	c.mu.Unlock()
	c.wg.Add(1)
	go c.loop(ctx)
}

// Stop beendet die Verbindung.
func (c *Live) Stop(ctx context.Context) error {
	c.mu.Lock()
	cancel := c.cancel
	c.running = false
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	done := make(chan struct{})
	go func() { c.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}

func (c *Live) setErr(err error) {
	c.mu.Lock()
	if err != nil {
		c.lastErr = err.Error()
	} else {
		c.lastErr = ""
	}
	c.mu.Unlock()
}

// ---------------------------------------------------------------- Erstverknuepfung

// LinkStart holt einen Code beim hub. Der Nutzer gibt ihn im Portal ein.
// Die Oberflaeche ruft das im Hintergrund auf (Seite blockiert nicht); Fehler landen im Status (LastError).
func (c *Live) LinkStart(ctx context.Context) (code string, expires time.Time, err error) {
	c.mu.Lock()
	if c.linkBusy {
		c.mu.Unlock()
		return "", time.Time{}, errors.New("already requesting")
	}
	c.linkBusy = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.linkBusy = false
		c.mu.Unlock()
		c.setErr(err)
	}()
	name := c.d.Core.SettingOr(ctx, "node.name", "Node64")
	body, _ := json.Marshal(wire.LinkStart{NodeID: c.nodeID(), Name: name, Version: c.d.Version})
	var out wire.LinkStarted
	var lastErr error
	for _, ep := range c.ordered() {
		// je hub hoechstens 12 s, sonst wartet der Nutzer bei blockiertem Netz minutenlang
		ectx, cancel := context.WithTimeout(ctx, 12*time.Second)
		resp, err := c.post(ectx, ep.URL+"/v1/nodes/link/start", "", body)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if err := json.Unmarshal(resp, &out); err != nil || out.Code == "" {
			lastErr = errors.New("unexpected answer from hub")
			continue
		}
		c.set(SetPendCode, out.Code)
		c.set(SetPendSecret, out.PollSecret)
		c.set(SetPendExp, out.ExpiresAt.Format(time.RFC3339))
		c.set(SetHub, ep.URL)
		go c.pollPending(out.Code, out.ExpiresAt)
		return out.Code, out.ExpiresAt, nil
	}
	return "", time.Time{}, fmt.Errorf("hub not reachable (check DNS, outbound HTTPS and the clock): %w", lastErr)
}

// pollPending fragt im Hintergrund nach, bis der Code eingeloest, abgelaufen oder verworfen ist.
// So klappt die Verknuepfung auch, wenn die Seite im Browser nicht offen ist.
func (c *Live) pollPending(code string, exp time.Time) {
	for time.Now().Before(exp.Add(30 * time.Second)) {
		time.Sleep(5 * time.Second)
		if c.setting(SetPendCode, "") != code {
			return // verknuepft, abgebrochen oder neuer Code
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		linked, err := c.LinkPoll(ctx)
		cancel()
		if linked {
			return
		}
		if err != nil {
			c.log.Debug("link poll", "err", err)
		}
	}
}

// RefreshAccount laedt Klasse, Limits und Verbrauch des Accounts sofort vom hub (z. B. nach einem Upgrade).
func (c *Live) RefreshAccount(ctx context.Context) {
	if c.Linked() {
		c.refreshMe(ctx)
	}
}

// Quota liefert das Tageskontingent der Online-Checks (heute, Limit; Limit 0 = unbegrenzt oder unbekannt)
// und die Standorte je Check laut Account (fuer die Hochrechnung).
func (c *Live) Quota() (today, limit, locs int) {
	if !c.Linked() {
		return 0, 0, 0
	}
	var acc wire.Account
	if raw := c.setting(SetAccount, ""); raw == "" || json.Unmarshal([]byte(raw), &acc) != nil {
		return 0, 0, 0
	}
	return acc.Usage["checks_today"], acc.Limits["checks_per_day"], acc.HCLocation
}

// LinkPoll fragt nach, ob der Code eingeloest wurde. true = jetzt verknuepft.
func (c *Live) LinkPoll(ctx context.Context) (bool, error) {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	if c.Linked() {
		return true, nil // inzwischen vom Hintergrund-Poll verknuepft
	}
	code, secret := c.setting(SetPendCode, ""), c.setting(SetPendSecret, "")
	if code == "" {
		return false, errors.New("no pending code")
	}
	body, _ := json.Marshal(wire.LinkPoll{Code: code, PollSecret: secret})
	hub := c.setting(SetHub, c.endpoints()[0].URL)
	resp, status, err := c.postStatus(ctx, hub+"/v1/nodes/link/poll", "", body)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusAccepted:
		return false, nil
	case http.StatusOK:
	default:
		c.LinkCancel()
		return false, fmt.Errorf("code expired or rejected (%d)", status)
	}
	var out wire.Linked
	if err := json.Unmarshal(resp, &out); err != nil || out.NodeToken == "" {
		return false, errors.New("unexpected answer from hub")
	}
	tok := out.NodeToken
	if c.d.Box != nil {
		tok = c.d.Box.Encrypt(tok)
	}
	c.set(SetToken, tok)
	acc, _ := json.Marshal(out.Account)
	c.set(SetAccount, string(acc))
	if len(out.Endpoints) > 0 {
		eps, _ := json.Marshal(out.Endpoints)
		c.set(SetEndpoints, string(eps))
	}
	c.set(SetNodeName, out.Name)
	c.set(SetLocation, out.Location)
	if out.Location != "" {
		c.set("node.location", out.Location) // beim Verknuepfen im Portal eingetragen; leer = eigener Standort geht an ipv64
	}
	c.set(SetRemoteMgmt, out.RemoteMgmt)
	c.set(SetLinkedAt, time.Now().UTC().Format(time.RFC3339))
	c.LinkCancel()
	c.log.Info("linked with ipv64", "account", out.Account.ID, "plan", out.Account.Plan)
	if m := c.d.Modules; m != nil && !m.IsRunning(healthchecks.Name) {
		if err := m.Enable(ctx, healthchecks.Name); err != nil {
			c.log.Error("enable healthchecks after link", "err", err)
		} else {
			c.log.Info("healthchecks module enabled for the link")
		}
	}
	if err := c.bootstrap(ctx); err != nil {
		c.log.Error("bootstrap failed", "err", err)
		c.setErr(err)
	}
	c.startLoop(context.Background())
	return true, nil
}

// LinkCancel verwirft einen offenen Code.
func (c *Live) LinkCancel() {
	c.set(SetPendCode, "")
	c.set(SetPendSecret, "")
	c.set(SetPendExp, "")
}

// Unlink trennt die Verknuepfung; keepChecks = Checks beim Account als online weiterlaufen lassen.
func (c *Live) Unlink(ctx context.Context, keepChecks bool) error {
	body, _ := json.Marshal(map[string]bool{"keep_checks": keepChecks})
	tok := c.token()
	hubOK := false
	for _, ep := range c.endpoints() {
		if _, err := c.post(ctx, ep.URL+"/v1/nodes/me/unlink", tok, body); err == nil {
			hubOK = true
			break
		}
	}
	if !hubOK && c.d.UnlinkAPI != nil { // hubs nicht erreichbar: direkt ueber die API v2 trennen
		if err := c.d.UnlinkAPI(ctx, c.nodeID(), keepChecks); err != nil {
			c.log.Warn("unlink via ipv64 API failed", "err", err)
		} else {
			c.log.Info("hubs unreachable, unlinked via ipv64 API")
		}
	}
	_ = c.Stop(ctx)
	if err := c.clearLink(ctx); err != nil {
		return err
	}
	c.log.Info("unlinked from ipv64", "keep_checks", keepChecks)
	return nil
}

// Forget trennt die Verknuepfung nur lokal (ohne hub und API): die Node wurde auf ipv64.net entfernt, der Token ist
// dort schon widerrufen. Wie der Widerruf durch den hub; lokale Checks und Daten bleiben.
func (c *Live) Forget(ctx context.Context) error {
	if !c.Linked() {
		return nil
	}
	_ = c.Stop(ctx)
	if err := c.clearLink(ctx); err != nil {
		return err
	}
	c.setErr(errors.New("the node was removed on ipv64.net, the node runs standalone"))
	c.log.Warn("ipv64 link cleared: node removed on ipv64.net")
	return nil
}

// clearLink setzt die Node lokal auf standalone: Zugangsdaten weg, alle Checks wieder eigene,
// Platzhalter der Server-Kanaele entfernt. Beim Trennen hier und beim Widerruf durch ipv64.
func (c *Live) clearLink(ctx context.Context) error {
	for _, k := range []string{SetToken, SetAccount, SetLinkedAt, SetRevision, SetAckSeq, SetEventID, SetHub} {
		c.set(k, "")
	}
	c.mu.Lock()
	c.connected, c.hub, c.lastErr = false, "", ""
	c.mu.Unlock()
	c.hubDirect.Store(false)
	if m := c.d.Modules; m == nil || m.IsRunning(healthchecks.Name) { // ohne Modul gibt es keine Checks
		if err := c.d.HC.SetOwnerAllSelf(ctx); err != nil {
			return err
		}
	}
	// Platzhalter der Server-Kanaele entfernen
	if chans, err := c.d.NF.Channels(ctx); err == nil {
		for _, ch := range chans {
			if ch.Execution == "server" {
				c.logErr("Delete", c.d.NF.Delete(notify.WithRemote(ctx), ch.ID))
			} else if ch.RemoteID != 0 {
				c.logErr("SetRemote", c.d.NF.SetRemote(ctx, ch.ID, 0, ch.Revision))
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------- HTTP

func (c *Live) post(ctx context.Context, url, token string, body []byte) ([]byte, error) {
	b, status, err := c.postStatus(ctx, url, token, body)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("hub %s: HTTP %d: %s", url, status, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func (c *Live) postStatus(ctx context.Context, url, token string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "node64/"+c.d.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	var buf strings.Builder
	_, _ = copyLimited(&buf, resp, 16<<20)
	c.txBytes.Add(int64(len(body)))
	c.rxBytes.Add(int64(buf.Len()))
	return []byte(buf.String()), resp.StatusCode, nil
}

func (c *Live) get(ctx context.Context, url, token string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "node64/"+c.d.Version)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var buf strings.Builder
	_, _ = copyLimited(&buf, resp, 16<<20)
	c.rxBytes.Add(int64(buf.Len()))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("hub %s: HTTP %d", url, resp.StatusCode)
	}
	return []byte(buf.String()), nil
}

func copyLimited(dst *strings.Builder, resp *http.Response, limit int64) (int64, error) {
	buf := make([]byte, 32<<10)
	var n int64
	for n < limit {
		k, err := resp.Body.Read(buf)
		if k > 0 {
			dst.Write(buf[:k])
			n += int64(k)
		}
		if err != nil {
			break
		}
	}
	return n, nil
}

// ---------------------------------------------------------------- Bootstrap

// bootstrap laedt die lokale Konfiguration nach der Erstverknuepfung hoch.
func (c *Live) bootstrap(ctx context.Context) error {
	var in wire.Bootstrap
	chans, _ := c.d.NF.Channels(ctx)
	for _, ch := range chans {
		if ch.Execution == "server" {
			continue
		}
		w := wire.Channel{LocalID: ch.ID, Type: string(ch.Type), Name: ch.Name, Enabled: ch.Enabled, Default: ch.Default, Lang: ch.Lang, NotifyDown: ch.NotifyDown, NotifyUp: ch.NotifyUp, Revision: ch.Revision}
		if !ch.SecretOnlyLocal {
			w.Config = ch.Config
		} else {
			w.Config = ch.Masked()
		}
		in.Channels = append(in.Channels, w)
	}
	checks, _ := c.d.HC.AllChecks(ctx)
	for _, ck := range checks {
		if !ck.MeasuredHere() {
			continue
		}
		in.Checks = append(in.Checks, c.d.HC.WireCheck(ck, nil)) // Kanaele: lokale IDs, der Server bildet sie ueber channel_map ab
	}
	maint, _ := c.d.HC.AllMaintenance(ctx)
	for _, mw := range maint {
		w := c.d.HC.WireMaintenance(mw)
		w.ID = mw.ID // lokale ID, der Server liefert die Zuordnung
		in.Maintenance = append(in.Maintenance, w)
	}
	body, _ := json.Marshal(in)
	resp, err := c.post(ctx, c.hubURL()+"/v1/nodes/me/bootstrap", c.token(), body)
	if err != nil {
		return err
	}
	var out wire.BootstrapResult
	if err := json.Unmarshal(resp, &out); err != nil {
		return err
	}
	for local, remote := range out.ChannelMap {
		if ch, _ := c.d.NF.Channel(ctx, local); ch != nil {
			c.logErr("SetRemote", c.d.NF.SetRemote(ctx, local, remote, ch.Revision))
		}
	}
	for local, remote := range out.MaintMap {
		c.logErr("SetMaintenanceRemote", c.d.HC.SetMaintenanceRemote(ctx, local, remote, 1))
	}
	for _, ck := range out.Checks {
		c.logErr("SetCheckRevision", c.d.HC.SetCheckRevision(ctx, ck.Token, ck.Revision))
	}
	for _, r := range out.Renamed {
		c.log.Warn("token collision, server assigned a new token (not applied locally)", "old", r.OldToken, "new", r.NewToken)
	}
	// Vollabgleich holt Server-Kanaele und fremde Checks; Messdaten ab jetzt
	c.setInt(SetAckSeq, c.d.HC.MaxMeasurementSeq(ctx))
	c.setInt(SetEventID, c.d.HC.MaxEventID(ctx))
	return c.fullSync(ctx)
}

func (c *Live) hubURL() string {
	if u := os.Getenv("NODE64_HUB_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	if h := c.setting(SetHub, ""); h != "" {
		return h
	}
	return c.endpoints()[0].URL
}

// fullSync holt die gesamte Konfiguration (Repair, Sync-Plan 3.6) und wendet sie an.
func (c *Live) fullSync(ctx context.Context) error {
	resp, err := c.get(ctx, c.hubURL()+"/v1/nodes/me/config", c.token())
	if err != nil {
		return err
	}
	var cfg wire.FullConfig
	if err := json.Unmarshal(resp, &cfg); err != nil {
		return err
	}
	var changes []wire.Change
	for _, ch := range cfg.Channels {
		changes = append(changes, wire.Change{Entity: "channel", ID: strconv.FormatInt(ch.ID, 10), Op: "upsert", Revision: ch.Revision, Data: mustJSON(ch)})
	}
	for _, ck := range cfg.Checks {
		changes = append(changes, wire.Change{Entity: "check", ID: ck.Token, Op: "upsert", Revision: ck.Revision, Data: mustJSON(ck)})
	}
	for _, mw := range cfg.Maintenance {
		changes = append(changes, wire.Change{Entity: "maintenance", ID: strconv.FormatInt(mw.ID, 10), Op: "upsert", Revision: mw.Revision, Data: mustJSON(mw)})
	}
	// Eigene Checks, die der Server nicht (mehr) kennt, sind dort geloescht
	known := map[string]bool{}
	for _, ck := range cfg.Checks {
		known[ck.Token] = true
	}
	if list, err := c.d.HC.AllChecks(ctx); err == nil {
		for _, ck := range list {
			if !known[ck.Token] && !c.d.HC.OutboxHas(ctx, "check", ck.Token) {
				changes = append(changes, wire.Change{Entity: "check", ID: ck.Token, Op: "delete"})
			}
		}
	}
	c.applyChanges(ctx, changes, cfg.Revision)
	c.applySettings(ctx, cfg.Settings, true)
	return nil
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// ---------------------------------------------------------------- Aenderungen anwenden

// applyChanges wendet Server-Aenderungen an; Entitaeten mit ausstehender lokaler
// Aenderung werden zum Konflikt (Sync-Plan 3.9 Schritt 2).
func (c *Live) applyChanges(ctx context.Context, changes []wire.Change, revision int64) {
	remoteToLocal := func(remote int64) int64 {
		if ch, _ := c.d.NF.ByRemote(ctx, remote); ch != nil {
			return ch.ID
		}
		return 0
	}
	for _, ch := range changes {
		if ch.Entity == "check" || ch.Entity == "maintenance" || ch.Entity == "channel" {
			id := ch.ID
			if ch.Entity != "check" {
				// Outbox fuehrt lokale IDs; Server-ID auf lokale abbilden
				id = c.localIDFor(ctx, ch.Entity, ch.ID)
			}
			if id != "" && c.d.HC.OutboxHas(ctx, ch.Entity, id) && c.conflict(ctx, ch.Entity, id, ch) {
				continue
			}
		}
		var err error
		switch ch.Entity {
		case "check":
			if ch.Op == "delete" {
				err = c.d.HC.RemoveRemoteCheck(ctx, ch.ID)
			} else {
				var w wire.Check
				if err = json.Unmarshal(ch.Data, &w); err == nil {
					err = c.d.HC.ApplyWireCheck(ctx, w, remoteToLocal)
				}
			}
		case "maintenance":
			var rid int64
			fmt.Sscan(ch.ID, &rid)
			if ch.Op == "delete" {
				err = c.d.HC.RemoveRemoteMaintenance(ctx, rid)
			} else {
				var w wire.Maintenance
				if err = json.Unmarshal(ch.Data, &w); err == nil {
					err = c.d.HC.ApplyWireMaintenance(ctx, w)
				}
			}
		case "channel":
			var rid int64
			fmt.Sscan(ch.ID, &rid)
			if ch.Op == "delete" {
				err = c.removeRemoteChannel(ctx, rid)
			} else {
				var w wire.Channel
				if err = json.Unmarshal(ch.Data, &w); err == nil {
					err = c.applyChannel(ctx, w)
				}
			}
		case "node":
			// Name/Standort/Fernverwaltung wurden im Portal geaendert: sofort nachladen
			c.refreshMe(ctx)
		case "settings":
			var kv map[string]string
			if json.Unmarshal(ch.Data, &kv) == nil {
				c.applySettings(ctx, kv, false)
			}
		}
		if err != nil {
			c.log.Warn("apply change failed", "entity", ch.Entity, "id", checks.TokenHint(ch.ID), "op", ch.Op, "err", err)
			if c.applyFailed(ch) {
				c.log.Error("apply change failed repeatedly, skipped", "entity", ch.Entity, "id", checks.TokenHint(ch.ID), "op", ch.Op)
			} else {
				c.holdRevision() // nicht ueber die fehlgeschlagene Aenderung hinaus: die naechste Sitzung liefert ab hier neu
			}
		}
		if ch.Revision > c.getInt(SetRevision) && !c.revisionHeld() {
			c.setInt(SetRevision, ch.Revision)
		}
	}
	if revision > c.getInt(SetRevision) && !c.revisionHeld() {
		c.setInt(SetRevision, revision)
	}
	c.mu.Lock()
	c.lastSync = time.Now()
	c.mu.Unlock()
}

// maxApplyFails: so oft darf dieselbe Aenderung scheitern, bevor sie uebergangen wird (z. B. ungueltige Daten),
// damit eine einzelne Aenderung den Abgleich nicht dauerhaft festhaelt.
const maxApplyFails = 3

// applyFailed zaehlt einen Fehlschlag; true = dauerhaft gescheitert (uebergehen).
func (c *Live) applyFailed(ch wire.Change) bool {
	key := ch.Entity + "|" + ch.ID + "|" + strconv.FormatInt(ch.Revision, 10)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.applyFails == nil {
		c.applyFails = map[string]int{}
	}
	c.applyFails[key]++
	return c.applyFails[key] >= maxApplyFails
}

func (c *Live) holdRevision() {
	c.mu.Lock()
	c.revHeld = true
	c.mu.Unlock()
}

func (c *Live) revisionHeld() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.revHeld
}

func (c *Live) localIDFor(ctx context.Context, entity, remoteID string) string {
	var rid int64
	fmt.Sscan(remoteID, &rid)
	switch entity {
	case "maintenance":
		if list, err := c.d.HC.AllMaintenance(ctx); err == nil {
			for _, mw := range list {
				if mw.RemoteID == rid {
					return strconv.FormatInt(mw.ID, 10)
				}
			}
		}
	case "channel":
		if ch, _ := c.d.NF.ByRemote(ctx, rid); ch != nil {
			return strconv.FormatInt(ch.ID, 10)
		}
	}
	return ""
}

// adoptServer uebernimmt die Server-Fassung nach einem abgelehnten Vorschlag (leer = auf dem Server geloescht).
func (c *Live) adoptServer(ctx context.Context, entity, remoteID string, res wire.ProposeResult) {
	ch := wire.Change{Entity: entity, ID: remoteID, Op: "upsert", Revision: res.Revision, Data: res.Server}
	if len(res.Server) == 0 || string(res.Server) == "null" {
		ch.Op, ch.Data = "delete", nil
	}
	if remoteID == "" || remoteID == "0" {
		return
	}
	c.applyChanges(ctx, []wire.Change{ch}, 0)
}

// conflict: eine Server-Aenderung trifft auf eine noch nicht gemeldete lokale Aenderung. Ist sie inhaltlich
// gleich (z. B. die eigene, gerade bestaetigte Aenderung kommt als config zurueck), entfaellt der
// Postausgang-Eintrag und die Aenderung wird uebernommen (false). Sonst bleibt die lokale Fassung vorerst
// stehen (true) und geht mit ihrer Aenderungszeit an den hub: der entscheidet, welche juenger ist.
func (c *Live) conflict(ctx context.Context, entity, localID string, ch wire.Change) bool {
	list, _ := c.d.HC.OutboxPending(ctx)
	if ch.Op == "upsert" {
		same := true
		for _, o := range list {
			if o.Entity == entity && o.EntityID == localID && !sameContent(o.Payload, ch.Data) {
				same = false
			}
		}
		if same {
			for _, o := range list {
				if o.Entity == entity && o.EntityID == localID {
					c.logErr("OutboxDelete", c.d.HC.OutboxDelete(ctx, o.ID))
				}
			}
			return false
		}
	}
	c.log.Info("sync: local change pending, hub decides by change time", "entity", entity, "id", checks.TokenHint(localID))
	c.poke()
	return true
}

// sameContent vergleicht zwei JSON-Fassungen ohne Verwaltungsfelder.
func sameContent(a string, b []byte) bool {
	var x, y map[string]any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	for _, k := range []string{"revision", "created_at", "updated_at", "state", "owner", "node_id", "id", "local_id"} {
		delete(x, k)
		delete(y, k)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return string(xb) == string(yb)
}

// applyChannel: Server-Kanaele als Platzhalter (execution server), eigene Kanaele aktualisieren.
func (c *Live) applyChannel(ctx context.Context, w wire.Channel) error {
	rctx := notify.WithRemote(ctx)
	existing, _ := c.d.NF.ByRemote(ctx, w.ID)
	mine := w.NodeID != "" && w.NodeID == c.nodeID()
	if existing == nil {
		if w.NodeID != "" && !mine {
			return nil // Kanal einer anderen Node: nicht anzeigen
		}
		ch := &notify.Channel{Type: notify.Type(w.Type), Name: w.Name, Enabled: w.Enabled, Default: w.Default, Lang: w.Lang, NotifyDown: w.NotifyDown, NotifyUp: w.NotifyUp,
			RemoteID: w.ID, Revision: w.Revision, Execution: "server", Config: map[string]string{}}
		if mine {
			ch.Execution = "node"
		}
		if w.Config != nil {
			ch.Config = w.Config // eigene: alles; Portal-Kanaele: nur nicht geheime Werte (Anzeige)
		}
		if ch.Lang == "" {
			ch.Lang = "de"
		}
		return c.d.NF.Insert(rctx, ch)
	}
	existing.Name, existing.Enabled, existing.Default, existing.NotifyDown, existing.NotifyUp, existing.Revision = w.Name, w.Enabled, w.Default, w.NotifyDown, w.NotifyUp, w.Revision
	if w.Lang != "" {
		existing.Lang = w.Lang
	}
	if len(w.Config) > 0 || (!mine && w.Config != nil) {
		existing.Config = w.Config
	}
	return c.d.NF.Update(rctx, existing)
}

func (c *Live) removeRemoteChannel(ctx context.Context, remoteID int64) error {
	ch, err := c.d.NF.ByRemote(ctx, remoteID)
	if err != nil || ch == nil {
		return err
	}
	return c.d.NF.Delete(notify.WithRemote(ctx), ch.ID)
}

// ---------------------------------------------------------------- Hooks (lokale Aenderungen)

func (c *Live) onChange(ctx context.Context, entity, id, op string) {
	if !c.Linked() {
		return
	}
	payload, base := "", int64(0)
	switch entity {
	case "check":
		if op == "delete" {
			base = -1 // Server kennt die letzte Revision; Loeschen ohne Basispruefung
		} else {
			ck, _ := c.d.HC.CheckByToken(ctx, id)
			if ck == nil {
				return
			}
			// jede Aenderung melden, auch wenn diese Node den Check nicht (mehr) misst oder er einer
			// anderen Node gehoert (sonst erfaehrt die neue Messstelle nie davon)
			base = ck.Revision - 1
			if base < 0 {
				base = 0
			}
			if ck.Revision <= 1 {
				base = 0
			}
			w := c.d.HC.WireCheck(ck, c.localToRemote(ctx))
			payload = string(mustJSON(w))
		}
	case "maintenance":
		var lid int64
		fmt.Sscan(id, &lid)
		if op == "delete" {
			base = -1
			rid := healthchecks.DeletedRemoteID(ctx)
			if rid == 0 {
				return // nie auf dem Server gewesen
			}
			payload = fmt.Sprintf(`{"id":%d}`, rid)
		} else {
			mw, _ := c.d.HC.MaintenanceByID(ctx, lid)
			if mw == nil {
				return
			}
			// lokale Aenderungen erhoehen die Revision nicht: sie ist der zuletzt bekannte Server-Stand
			base = mw.Revision
			if mw.RemoteID == 0 {
				base = 0
			}
			payload = string(mustJSON(c.d.HC.WireMaintenance(*mw)))
		}
	}
	if err := c.d.HC.OutboxAdd(ctx, entity, id, op, base, payload); err != nil {
		c.log.Error("outbox add failed", "err", err)
		return
	}
	c.poke()
}

func (c *Live) onChannelChange(ctx context.Context, id int64, op string) {
	if !c.Linked() {
		return
	}
	payload := ""
	base := int64(-1)
	if op == "delete" {
		rid := notify.DeletedRemoteID(ctx)
		if rid == 0 {
			return // nie auf dem Server gewesen
		}
		payload = fmt.Sprintf(`{"id":%d}`, rid)
	} else {
		ch, _ := c.d.NF.Channel(ctx, id)
		if ch == nil {
			return
		}
		w := wire.Channel{ID: ch.RemoteID, Type: string(ch.Type), Name: ch.Name, Enabled: ch.Enabled, Default: ch.Default, Lang: ch.Lang, NotifyDown: ch.NotifyDown, NotifyUp: ch.NotifyUp, Revision: ch.Revision, LocalID: ch.ID}
		// Kanaele des Portals (execution server): nur gesetzte Werte melden, leere Geheimnisse behaelt der hub
		if ch.Execution == "server" {
			w.Config = map[string]string{}
			for k, v := range ch.Config {
				if strings.TrimSpace(v) != "" {
					w.Config[k] = v
				}
			}
		} else if !ch.SecretOnlyLocal {
			w.Config = ch.Config
		}
		payload = string(mustJSON(w))
		// lokale Aenderungen erhoehen die Revision nicht: sie ist der zuletzt bekannte Server-Stand
		base = ch.Revision
		if ch.RemoteID == 0 {
			base = 0
		}
	}
	if err := c.d.HC.OutboxAdd(ctx, "channel", strconv.FormatInt(id, 10), op, base, payload); err != nil {
		c.log.Error("outbox add failed", "err", err)
		return
	}
	c.poke()
}

// NodeInfoChanged merkt eine lokale Aenderung von Name/Standort vor; die Sitzung meldet sie dem hub,
// der sie ins Portal und an die anderen Nodes weitergibt (auch nach einer Trennung).
func (c *Live) NodeInfoChanged() {
	c.infoGen.Add(1)
	if !c.Linked() {
		return
	}
	c.set(SetNodeInfoDirty, "1")
	c.poke()
}

// NotifySettingsChanged merkt geaenderte Benachrichtigungs-Einstellungen vor; die Sitzung meldet sie dem hub
// (sie gelten fuer den Account: Portal und alle Nodes), auch nach einer Trennung.
func (c *Live) NotifySettingsChanged() {
	c.notifyGen.Add(1)
	if !c.Linked() {
		return
	}
	c.set(SetNotifyDirty, "1")
	c.poke()
}

// notifySettings liefert die gesetzten account-weiten Einstellungen dieser Node.
func (c *Live) notifySettings(ctx context.Context) map[string]string {
	out := map[string]string{}
	for _, k := range notify.SyncedSettings {
		if v, ok, _ := c.d.Core.Setting(ctx, k); ok {
			out[k] = v
		}
	}
	return out
}

// applySettings uebernimmt die Einstellungen des Accounts vom hub. Eine noch nicht gemeldete lokale Aenderung
// geht vor (sie wird gleich gemeldet). initial (Verbinden/Vollabgleich): kennt der Account noch keine,
// meldet die Node ihre eigenen; eine Aenderungsmeldung loest nie ein Zuruecksenden aus.
func (c *Live) applySettings(ctx context.Context, kv map[string]string, initial bool) {
	if c.setting(SetNotifyDirty, "") == "1" {
		return
	}
	n := 0
	for _, k := range notify.SyncedSettings {
		if v, ok := kv[k]; ok {
			n++
			c.logErr("SetSetting", c.d.Core.SetSetting(ctx, k, v))
		}
	}
	if initial && n == 0 && len(c.notifySettings(ctx)) > 0 {
		c.set(SetNotifyDirty, "1")
		c.poke()
	}
}

// nodeInfoPending: Name/Standort wurden lokal geaendert und sind noch nicht beim hub. sync.node_name und
// sync.location halten den zuletzt mit ipv64 abgeglichenen Stand; eine Abweichung kann nur von hier kommen.
func (c *Live) nodeInfoPending() bool {
	if c.setting(SetNodeInfoDirty, "") == "1" {
		return true
	}
	synced := c.setting(SetNodeName, "")
	return synced != "" && (c.setting("node.name", "") != synced || c.setting("node.location", "") != c.setting(SetLocation, ""))
}

// refreshMe holt Name, Standort und Fernverwaltung vom hub (nach Aenderung im Portal).
func (c *Live) refreshMe(ctx context.Context) {
	gen := c.infoGen.Load()
	resp, err := c.get(ctx, c.hubURL()+"/v1/nodes/me", c.token())
	if err != nil {
		return
	}
	var me struct {
		Name       string            `json:"name"`
		Location   string            `json:"location"`
		RemoteMgmt string            `json:"remote_mgmt"`
		Nodes      []json.RawMessage `json:"nodes"`
		Settings   map[string]string `json:"settings"`
		Account    json.RawMessage   `json:"account"`
	}
	if json.Unmarshal(resp, &me) != nil || me.Name == "" {
		return
	}
	if me.Nodes != nil {
		// Nodes des Accounts: Auswahl der messenden Nodes im Formular
		if b, err := json.Marshal(me.Nodes); err == nil {
			c.set(healthchecks.SettingPeers, string(b))
		}
	}
	if c.infoGen.Load() == gen && !c.nodeInfoPending() {
		// im Portal umbenannt: auch Name/Standort der Node selbst (Einstellungen, Status)
		c.set(SetNodeName, me.Name)
		c.set(SetLocation, me.Location)
		c.set("node.name", me.Name)
		c.set("node.location", me.Location)
	}
	if me.RemoteMgmt != "" {
		c.set(SetRemoteMgmt, me.RemoteMgmt)
	}
	if me.Settings != nil {
		c.applySettings(ctx, me.Settings, true) // Ruhezeiten und Grenzen des Accounts
	}
	if len(me.Account) > 2 {
		c.set(SetAccount, string(me.Account)) // Klasse, Limits und Verbrauch (z. B. SMS heute)
	}
}

func (c *Live) localToRemote(ctx context.Context) healthchecks.ChannelMap {
	return func(local int64) int64 {
		if ch, _ := c.d.NF.Channel(ctx, local); ch != nil {
			return ch.RemoteID
		}
		return 0
	}
}

func (c *Live) onRuntime(token string, rt scheduler.Runtime) {
	if !c.Linked() {
		return
	}
	c.mu.Lock()
	c.states[token] = c.d.HC.StateOf(token, rt)
	c.mu.Unlock()
	c.poke()
}

func (c *Live) poke() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// ---------------------------------------------------------------- Konflikte

// Resolve entscheidet einen Konflikt (Ablehnung durch den hub):
//   - "server": Server-Stand uebernehmen; hat der hub den Eintrag nicht (Grund bekannt, Server-Fassung leer), wird er
//     hier geloescht. Bei alten Konflikten ohne Grund ist der Server-Stand unbekannt: dann nichts loeschen, nur erneut
//     senden (der hub antwortet mit Grund und Stand).
//   - "local": die lokale Fassung erneut senden (mit der Server-Revision als Basis).
//   - "ignore": nur hier behalten - die Aenderung geht nicht mehr an den hub, der Eintrag bleibt lokal wie er ist.
func (c *Live) Resolve(ctx context.Context, id int64, keep string) error {
	cf, err := c.d.HC.ConflictByID(ctx, id)
	if err != nil || cf == nil {
		return errors.New("conflict not found")
	}
	if keep == "server" && cf.ServerPayload == "" && cf.Error == "" {
		keep = "local" // Server-Stand unbekannt: nicht loeschen, sondern erneut fragen
	}
	switch keep {
	case "ignore":
		c.logErr("OutboxDeleteEntity", c.d.HC.OutboxDeleteEntity(ctx, cf.Entity, cf.EntityID))
	case "server":
		if cf.ServerPayload == "" {
			switch cf.Entity {
			case "check":
				err = c.d.HC.RemoveRemoteCheck(ctx, cf.EntityID)
			case "maintenance":
				var lid int64
				fmt.Sscan(cf.EntityID, &lid)
				if mw, _ := c.d.HC.MaintenanceByID(ctx, lid); mw != nil {
					err = c.d.HC.RemoveRemoteMaintenance(ctx, mw.RemoteID)
				}
			case "channel":
				var lid int64
				fmt.Sscan(cf.EntityID, &lid)
				err = c.d.NF.Delete(notify.WithRemote(ctx), lid)
			}
		} else {
			c.applyChanges(ctx, []wire.Change{{Entity: cf.Entity, ID: c.remoteIDOf(ctx, cf), Op: "upsert", Revision: cf.ServerRevision, Data: json.RawMessage(cf.ServerPayload)}}, 0)
		}
		c.logErr("OutboxDeleteEntity", c.d.HC.OutboxDeleteEntity(ctx, cf.Entity, cf.EntityID))
	default:
		// lokale Version mit aktueller Server-Revision als Basis erneut einreihen
		c.logErr("OutboxDeleteEntity", c.d.HC.OutboxDeleteEntity(ctx, cf.Entity, cf.EntityID))
		op := cf.LocalOp
		if cf.LocalPayload == "" {
			op = "delete"
		}
		if err := c.d.HC.OutboxAdd(ctx, cf.Entity, cf.EntityID, op, cf.ServerRevision, cf.LocalPayload); err != nil {
			return err
		}
		c.poke()
	}
	if err != nil {
		return err
	}
	if err := c.d.HC.ConflictDelete(ctx, id); err != nil {
		return err
	}
	// Konfliktzahl am hub sofort aktualisieren (sonst erst mit dem naechsten 5-min-Status)
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	if s != nil {
		go s.sendStatus()
	}
	return nil
}

func (c *Live) remoteIDOf(ctx context.Context, cf *healthchecks.Conflict) string {
	if cf.Entity == "check" {
		return cf.EntityID
	}
	var x struct {
		ID int64 `json:"id"`
	}
	if cf.ServerPayload != "" && json.Unmarshal([]byte(cf.ServerPayload), &x) == nil && x.ID > 0 {
		return strconv.FormatInt(x.ID, 10)
	}
	return cf.EntityID
}

// pickEndpoint waehlt den zuletzt guten hub oder zufaellig einen anderen.
func (c *Live) pickEndpoint(failed string) string {
	if u := os.Getenv("NODE64_HUB_URL"); u != "" {
		return strings.TrimRight(u, "/")
	}
	eps := c.endpoints()
	if h := c.homeHub(); h != failed {
		return h
	}
	var cands []string
	for _, e := range eps {
		if e.URL != failed {
			cands = append(cands, e.URL)
		}
	}
	if len(cands) == 0 {
		return eps[0].URL
	}
	return cands[rand.IntN(len(cands))]
}

// ForwardPush stellt einen lokal empfangenen Push zur Weitergabe an den hub in eine feste Warteschlange
// (ein Sender je Prozess, keine Goroutine je Push). false: nicht verbunden oder Warteschlange voll.
func (c *Live) ForwardPush(token string, down bool, msg, from string) bool {
	c.mu.Lock()
	connected := c.ws != nil
	c.mu.Unlock()
	if !connected {
		return false
	}
	c.pushOnce.Do(func() {
		c.pushQ = make(chan wire.Msg, 64)
		go c.pushLoop()
	})
	data, _ := json.Marshal(map[string]any{"token": token, "down": down, "msg": msg, "from": from, "time": time.Now().UTC().Format(time.RFC3339Nano)})
	select {
	case c.pushQ <- wire.Msg{T: "push", Data: data}:
		return true
	default:
		return false
	}
}

// RunRemote bittet den hub, den Check bei den anderen messenden Nodes sofort zu messen.
func (c *Live) RunRemote(token string) bool {
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	if s == nil {
		return false
	}
	data, _ := json.Marshal(map[string]string{"token": token})
	return s.send(wire.Msg{T: "run_check", Data: data}) == nil
}

// pushLoop schickt Pushes ueber die jeweils aktuelle Sitzung; der hub verwirft, was zu alt ist.
func (c *Live) pushLoop() {
	for m := range c.pushQ {
		c.mu.Lock()
		s := c.ws
		c.mu.Unlock()
		if s != nil {
			_ = s.send(m)
		}
	}
}

// TestServerChannel bittet den hub, ueber einen Kanal zu senden, den nur ipv64 zustellen kann.
func (c *Live) TestServerChannel(ctx context.Context, remoteID int64, lang string) error {
	if remoteID <= 0 {
		return errors.New("channel not synced with ipv64 yet")
	}
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	if s == nil {
		return errors.New("not connected to ipv64")
	}
	m, err := s.request("channel_test", map[string]any{"channel_id": remoteID, "lang": lang})
	if err != nil {
		return err
	}
	var res struct {
		OK        bool   `json:"ok"`
		TestError string `json:"test_error"`
		Error     string `json:"error"`
	}
	_ = json.Unmarshal(m.Data, &res)
	switch {
	case res.OK:
		return nil
	case res.TestError != "":
		return errors.New(res.TestError)
	case res.Error != "":
		return errors.New(res.Error)
	}
	return errors.New("test not confirmed by ipv64")
}

// ---------------------------------------------------------------- Stellvertreter-Nodes (lokale Gruppe)

// ProxyReady: verbunden mit einem hub, der Stellvertreter-Nodes annimmt.
func (c *Live) ProxyReady() bool {
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	return s != nil && s.proxy.Load()
}

// RegisterProxies meldet die nicht verknuepften Mitglieder der lokalen Gruppe beim hub an (diese Node reicht
// weiter). Ergebnis: je angenommener Node der bestaetigte Messpunkt-Stand beim hub.
func (c *Live) RegisterProxies(ctx context.Context, items []wire.ProxyNode) (map[string]int64, error) {
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	if s == nil || !s.proxy.Load() {
		return nil, errors.New("not connected to ipv64")
	}
	m, err := s.request("proxies", map[string]any{"items": items})
	if err != nil {
		return nil, err
	}
	var a struct {
		Acks  map[string]int64 `json:"acks"`
		Error string           `json:"error"`
	}
	if err := json.Unmarshal(m.Data, &a); err != nil {
		return nil, err
	}
	if a.Error != "" {
		return nil, errors.New(a.Error)
	}
	return a.Acks, nil
}

// ProxyData reicht Zustaende und Messpunkte einer Stellvertreter-Node an den hub; Ergebnis: bestaetigte Nummer.
func (c *Live) ProxyData(ctx context.Context, node string, states []wire.State, batch []wire.Measurement) (int64, error) {
	c.mu.Lock()
	s := c.ws
	c.mu.Unlock()
	if s == nil || !s.proxy.Load() {
		return 0, errors.New("not connected to ipv64")
	}
	// in Nachrichten unter der Leselimite des hubs (limit.go), Zustaende mit dem ersten Teil
	var ack int64
	parts := chunks(shrinkMeasurements(batch))
	stParts := chunks(shrinkStates(states))
	for i := 0; i < max(1, len(parts), len(stParts)); i++ {
		var d wire.ProxyData
		d.Node = node
		if i < len(stParts) {
			d.States = stParts[i]
		}
		if i < len(parts) {
			d.Batch = parts[i]
		}
		m, err := s.request("proxy_data", d)
		if err != nil {
			return 0, err
		}
		var a wire.Ack
		if err := json.Unmarshal(m.Data, &a); err != nil {
			return 0, err
		}
		if a.Error != "" {
			return 0, errors.New(a.Error)
		}
		ack = max(ack, a.AckSeq)
	}
	return ack, nil
}
