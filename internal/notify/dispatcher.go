package notify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/i18n"
)

// Alert ist ein Ereignis, das benachrichtigt werden soll (vom Modul gemeldet).
type Alert struct {
	EventID  string
	Kind     Kind
	Time     time.Time
	Check    CheckInfo
	Reason   string
	Message  string
	Duration time.Duration
	Flaps    int
	// Data: Platzhalter fuer Meldungen eines Moduls mit eigenem Text (Proxmox VE: what, type, value, limit, detail,
	// system, path – siehe composeProxmox).
	Data map[string]string
}

// Settings liest Einstellungen des Kerns (Agent-Name, Ruhezeiten, Basis-URL).
type Settings func(key, def string) string

// SettingsFor liefert die Einstellungen eines Accounts (Server) bzw. die des
// Nodes (userID 0).
type SettingsFor func(userID int64) Settings

// ChannelStore sind die Zugriffe, die der Dispatcher braucht: Kanaele eines
// Accounts, Zustellprotokoll, letzte Nutzung.
type ChannelStore interface {
	ChannelsFor(ctx context.Context, userID int64) ([]*Channel, error)
	AddDelivery(ctx context.Context, d Delivery) error
	Touch(ctx context.Context, id int64, errText string) error
}

// Einstellungs-Schluessel
const (
	SetBaseURL        = "node.base_url"
	SetNodeName       = "node.name"
	SetNodeLocation   = "node.location"
	SetQuietEnabled   = "notify.quiet_enabled"
	SetQuietFrom      = "notify.quiet_from"
	SetQuietTo        = "notify.quiet_to"
	SetQuietDays      = "notify.quiet_days" // 1=Mo ... 7=So
	SetQuietTZ        = "notify.quiet_tz"
	SetNodeTimezone   = "node.timezone"
	SetRatePerHour    = "notify.rate_per_hour"
	SetBatchThreshold = "notify.batch_threshold"
	SetBatchWindow    = "notify.batch_window_seconds"
)

// Dispatcher verteilt Alerts an Kanaele.
type Dispatcher struct {
	st          ChannelStore
	senders     map[Type]Sender
	i18n        *i18n.Bundle
	settingsFor SettingsFor
	log         *slog.Logger

	queue   chan Alert
	mu      sync.Mutex
	pending map[int64]*batch  // je Account gesammelte Alerts (Sammelmeldung)
	held    map[int64][]Alert // in der Ruhezeit zurueckgehalten, danach als Sammelmeldung
	buckets map[int64]*bucket
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	// Hooks fuer Tests
	now func() time.Time
	// sendServerChannels: Server-Kanaele trotzdem lokal senden (Node-Einstellung)
	sendServerChannels atomic.Bool
	// Pfade fuer Links (nil = Seiten des Nodes)
	checkPath func(string) string
	listPath  func(string) string
	// direkter Versand ueber die ipv64-API (Meldungen der Module) und Kanalliste ohne Verknuepfung
	hookMu      sync.RWMutex // die Hooks darunter werden evtl. erst nach Start gesetzt
	serverSends func() bool
	apiSend     func(ctx context.Context, ch *Channel, m Message) error
	linked      func() bool // Healthchecks-Sync mit ipv64 verknuepft (nil = unbekannt: nur Modul-Meldungen ueber die API)
	hubDirect   func() bool // der hub ueberlaesst der Node die Meldungen ihrer Direct-Checks (wire.NotifyDirect)
	apiReady    func() bool
	remote      func(ctx context.Context) []*Channel
}

// SetSendServerChannels schaltet den lokalen Versand ueber Server-Kanaele.
func (d *Dispatcher) SetSendServerChannels(on bool) { d.sendServerChannels.Store(on) }

// SetServerSends meldet, ob gerade der ipv64-hub die Benachrichtigungen uebernimmt (verknuepft und verbunden).
// Dann sendet die Node ihre eigenen Kanaele nicht selbst, sondern erhaelt Sendeauftraege vom hub.
func (d *Dispatcher) SetServerSends(fn func() bool) {
	d.hookMu.Lock()
	d.serverSends = fn
	d.hookMu.Unlock()
}

// hubSends: der hub uebernimmt gerade die Benachrichtigungen (SetServerSends).
func (d *Dispatcher) hubSends() bool {
	d.hookMu.RLock()
	fn := d.serverSends
	d.hookMu.RUnlock()
	return fn != nil && fn()
}

// ErrUnavailable: der Versandweg ist (noch) nicht verfuegbar, z. B. kein API-Key oder die Route fehlt auf
// dem Server. Wird protokolliert, markiert den Kanal aber nicht als gestoert.
var ErrUnavailable = errors.New("delivery path not available")

// SetAPISender installiert den direkten Versand ueber die ipv64-API fuer Server-Kanaele (ipv64-Mail, -SMS, App).
// Er gilt fuer Meldungen der Module (CheckInfo.Local) und – ohne Verknuepfung mit dem Healthchecks-Sync
// (SetLinked) – auch fuer die Healthchecks dieser Node; verknuepft bleiben die Healthchecks beim hub. ready meldet,
// ob ein API-Key da ist.
func (d *Dispatcher) SetAPISender(send func(ctx context.Context, ch *Channel, m Message) error, ready func() bool) {
	d.hookMu.Lock()
	d.apiSend, d.apiReady = send, ready
	d.hookMu.Unlock()
}

// SetLinked meldet, ob die Node mit dem Healthchecks-Sync verknuepft ist. Ohne Verknuepfung gehen alle Meldungen
// (auch Healthchecks) an die ipv64-Kanaele ueber die API, sonst kaeme bei Nutzern ohne Sync nichts an.
func (d *Dispatcher) SetLinked(fn func() bool) {
	d.hookMu.Lock()
	d.linked = fn
	d.hookMu.Unlock()
}

// unlinked: sicher nicht verknuepft (ohne Auskunft gilt: verknuepft, also wie bisher nur Modul-Meldungen).
func (d *Dispatcher) unlinked() bool {
	d.hookMu.RLock()
	fn := d.linked
	d.hookMu.RUnlock()
	return fn != nil && !fn()
}

// SetHubDirect meldet, ob der hub der Node die Meldungen ihrer nur hier gemessenen Checks (CheckInfo.Direct)
// ueberlaesst: dann sendet die Node die ipv64-Kanaele ueber die API und ihre eigenen Kanaele selbst, der hub nur die
// uebrigen Portal-Kanaele (deren Geheimnisse liegen nur bei ipv64).
func (d *Dispatcher) SetHubDirect(fn func() bool) {
	d.hookMu.Lock()
	d.hubDirect = fn
	d.hookMu.Unlock()
}

// direct: die Node sendet diesen Alert selbst (CheckInfo.Direct, der hub kann es, API-Key vorhanden).
func (d *Dispatcher) direct(c CheckInfo) bool {
	if !c.Direct || c.Local || d.sendServerChannels.Load() {
		return false
	}
	d.hookMu.RLock()
	fn, send, ready := d.hubDirect, d.apiSend, d.apiReady
	d.hookMu.RUnlock()
	return fn != nil && fn() && send != nil && ready != nil && ready()
}

// skipForNode (hub): Kanaele, die bei einem Direct-Alert die messende Node selbst sendet – ipv64-Kanaele (API) und
// ihre eigenen Kanaele.
func skipForNode(c CheckInfo, ch *Channel) bool {
	if c.DirectNode == "" {
		return false
	}
	return (ch.Execution == "server" && apiType(ch.Type)) || (ch.Execution == "node" && ch.NodeID == c.DirectNode)
}

// SetRemoteChannels liefert ohne Verknuepfung die ipv64-Kanaele des Accounts (nur lesend, nicht gespeichert).
func (d *Dispatcher) SetRemoteChannels(fn func(ctx context.Context) []*Channel) {
	d.hookMu.Lock()
	d.remote = fn
	d.hookMu.Unlock()
}

func (d *Dispatcher) hooks() (send func(context.Context, *Channel, Message) error, ready func() bool, remote func(context.Context) []*Channel) {
	d.hookMu.RLock()
	defer d.hookMu.RUnlock()
	return d.apiSend, d.apiReady, d.remote
}

// viaAPI: Server-Kanaele dieses Alerts gehen direkt ueber die API (Modul-Meldungen immer, Healthchecks nur ohne
// Verknuepfung – verknuepft sendet sie der hub).
func (d *Dispatcher) viaAPI(c CheckInfo) bool {
	send, ready, _ := d.hooks()
	return (c.Local || d.unlinked()) && !d.sendServerChannels.Load() && send != nil && ready != nil && ready()
}

type bucket struct {
	tokens float64
	last   time.Time
}

type batch struct {
	alerts []Alert
	due    time.Time
}

// maxHeld begrenzt die in der Ruhezeit gemerkten Alerts je Account.
const maxHeld = 500

// NewDispatcher ist der Dispatcher des Nodes (ein Account).
func NewDispatcher(st *Store, senders map[Type]Sender, bundle *i18n.Bundle, settings Settings, log *slog.Logger) *Dispatcher {
	return NewMultiDispatcher(st, senders, bundle, func(int64) Settings { return settings }, log)
}

// NewMultiDispatcher ist der Dispatcher des Servers: Kanaele und Einstellungen je Account.
func NewMultiDispatcher(st ChannelStore, senders map[Type]Sender, bundle *i18n.Bundle, settingsFor SettingsFor, log *slog.Logger) *Dispatcher {
	return &Dispatcher{st: st, senders: senders, i18n: bundle, settingsFor: settingsFor, log: log.With("module", "notify"),
		queue: make(chan Alert, 1000), buckets: map[int64]*bucket{}, pending: map[int64]*batch{}, held: map[int64][]Alert{}, now: func() time.Time { return time.Now() }}
}

// settings liefert die Einstellungen eines Accounts (0 = Node/global).
func (d *Dispatcher) settings(userID int64) Settings {
	s := d.settingsFor(userID)
	if s == nil {
		return func(_, def string) string { return def }
	}
	return s
}

// Start startet die Verarbeitung.
func (d *Dispatcher) Start(ctx context.Context) {
	d.loadHeld(ctx)
	d.ctx, d.cancel = context.WithCancel(ctx)
	d.wg.Add(1)
	go d.run()
}

// Stop beendet die Verarbeitung; wartende Alerts werden noch verschickt.
func (d *Dispatcher) Stop() {
	if d.cancel == nil {
		return
	}
	d.cancel()
	d.wg.Wait()
}

// Dispatch nimmt einen Alert an (nicht blockierend).
func (d *Dispatcher) Dispatch(a Alert) {
	select {
	case d.queue <- a:
	default:
		d.log.Error("notification queue full, alert dropped", "check", a.Check.Name, "kind", a.Kind)
	}
}

// intSetting liest eine Zahl aus den Einstellungen eines Accounts (Node: 0).
func (d *Dispatcher) intSetting(uid int64, key string, def int) int {
	n, err := strconv.Atoi(d.settings(uid)(key, strconv.Itoa(def)))
	if err != nil {
		return def
	}
	return n
}

// run sammelt Alerts je Account kurz (Sammelmeldung bei vielen gleichzeitigen Aenderungen), verschickt
// sie und gibt nach dem Ende einer Ruhezeit das Zurueckgehaltene als Sammelmeldung aus.
func (d *Dispatcher) run() {
	defer d.wg.Done()
	tick := time.NewTicker(time.Second) // Sammelfenster mind. 10 s: haeufiger aufzuwachen spart nichts
	defer tick.Stop()
	lastHeld := time.Time{}
	for {
		select {
		case <-d.ctx.Done():
			d.flushDue(context.Background(), true)
			return
		case a := <-d.queue:
			d.enqueue(a)
			// was gleichzeitig ankommt (z. B. viele Checks bei einem Netzausfall), 100 ms mitnehmen: so greift die
			// Sammelmeldung auch ohne Sammelfenster; danach Faelliges sofort, nicht erst beim naechsten Takt
			gather := time.NewTimer(100 * time.Millisecond)
		collect:
			for {
				select {
				case a := <-d.queue:
					d.enqueue(a)
				case <-gather.C:
					break collect
				case <-d.ctx.Done():
					gather.Stop()
					d.flushDue(context.Background(), true)
					return
				}
			}
			d.flushDue(d.ctx, false)
		case <-tick.C:
			d.flushDue(d.ctx, false)
			if now := d.now(); now.Sub(lastHeld) >= 30*time.Second || now.Before(lastHeld) {
				lastHeld = now
				d.releaseHeld(d.ctx)
			}
		}
	}
}

// enqueue legt einen Alert in die Sammlung seines Accounts (Sammelfenster je Account).
func (d *Dispatcher) enqueue(a Alert) {
	uid := a.Check.UserID
	window := time.Duration(d.intSetting(uid, SetBatchWindow, 10)) * time.Second
	d.mu.Lock()
	b := d.pending[uid]
	if b == nil {
		b = &batch{due: d.now().Add(window)}
		d.pending[uid] = b
	}
	b.alerts = append(b.alerts, a)
	d.mu.Unlock()
}

// flushDue verschickt die Sammlungen, deren Fenster abgelaufen ist (all: alle, beim Beenden).
func (d *Dispatcher) flushDue(ctx context.Context, all bool) {
	now := d.now()
	d.mu.Lock()
	due := map[int64][]Alert{}
	for uid, b := range d.pending {
		if all || !now.Before(b.due) {
			due[uid] = b.alerts
			delete(d.pending, uid)
		}
	}
	d.mu.Unlock()
	for uid, list := range due {
		d.flush(ctx, uid, list)
	}
}

// flush verschickt die gesammelten Alerts eines Accounts: ab der Schwelle werden gleichzeitige
// Stoerungen und ebenso gleichzeitige Entwarnungen je Kanal zu einer Sammelmeldung.
func (d *Dispatcher) flush(ctx context.Context, uid int64, list []Alert) {
	if len(list) == 0 {
		return
	}
	threshold := d.intSetting(uid, SetBatchThreshold, 3)
	var downs, ups, rest []Alert
	for _, a := range list {
		switch a.Kind {
		case KindDown:
			downs = append(downs, a)
		case KindUp:
			ups = append(ups, a)
		default:
			rest = append(rest, a)
		}
	}
	if threshold > 1 && len(downs) >= threshold {
		d.sendSummary(ctx, downs, false)
	} else {
		rest = append(rest, downs...)
	}
	if threshold > 1 && len(ups) >= threshold {
		d.sendSummary(ctx, ups, true)
	} else {
		rest = append(rest, ups...)
	}
	sort.SliceStable(rest, func(i, j int) bool { return rest[i].Time.Before(rest[j].Time) })
	for _, a := range rest {
		d.deliver(ctx, a)
	}
}

// channelsFor liefert die Kanaele eines Alerts: eigene Auswahl des Checks
// oder die Standardkanaele, jeweils nur aktive.
func (d *Dispatcher) channelsFor(ctx context.Context, c CheckInfo) []*Channel {
	all, err := d.st.ChannelsFor(ctx, c.UserID)
	if err != nil {
		d.log.Error("channels", "err", err)
		return nil
	}
	want := map[int64]bool{}
	for _, id := range c.Channels {
		want[id] = true
	}
	var out []*Channel
	direct := d.direct(c)
	for _, ch := range all {
		if !ch.Enabled {
			continue
		}
		if skipForNode(c, ch) {
			continue // hub: sendet die messende Node selbst
		}
		if direct {
			if ch.Execution == "server" && !apiType(ch.Type) {
				continue // andere Portal-Kanaele (z. B. Webhook, Telegram) sendet der hub
			}
		} else if ch.Execution == "server" && !d.sendServerChannels.Load() && !d.viaAPI(c) {
			continue // vom ipv64-hub gesendet
		} else if !c.Local && !d.sendServerChannels.Load() && d.hubSends() {
			continue // verknuepft und verbunden: der hub sendet (eigene Kanaele per Sendeauftrag), sonst kaeme alles doppelt
		}
		if len(want) > 0 {
			if want[ch.ID] {
				out = append(out, ch)
			}
		} else if ch.Default {
			out = append(out, ch)
		}
	}
	// ohne Verknuepfung: die ipv64-Kanaele des Accounts ueber die API (nur Standardkanaele)
	if _, _, remote := d.hooks(); d.viaAPI(c) && remote != nil && len(want) == 0 {
		for _, ch := range remote(ctx) {
			if ch.Enabled && ch.Default {
				out = append(out, ch)
			}
		}
	}
	return out
}

// isDownKind: Stoerungsmeldungen (Sammelmeldung der Entwarnungen zaehlt als Entwarnung).
func isDownKind(k Kind) bool {
	return k == KindDown || k == KindReminder || k == KindFlappingStart || k == KindSummary || k == KindDegraded || k == KindUnchecked || k == KindDynFail || k == KindDynLimit || k == KindQuota ||
		k == KindDNS64Down || k == KindDNS64Lists || k == KindDNS64Cert || k == KindCertFail || k == KindCertExpiry || k == KindCDNOnlineDown ||
		k == KindCDNOnlineBlocked || k == KindClusterDown || k == KindHoneypotWatch || k == KindHoneypotLogin || k == KindProxmoxDown || k == KindProxmoxThreshold ||
		k == KindUpdateFailed
}

// flagsOK prueft die Schalter von Check und Kanal (Stoerung/Entwarnung/teilweise gestoert).
func flagsOK(a Alert, ch *Channel) (bool, string) {
	if a.Kind == KindTest {
		return true, ""
	}
	down := isDownKind(a.Kind)
	if (a.Kind == KindDegraded || a.Kind == KindDegradedEnd) && !a.Check.NotifyDegraded {
		return false, "notify_degraded off"
	}
	if down && (!a.Check.NotifyDown || !ch.NotifyDown) {
		return false, "notify_down off"
	}
	if !down && (!a.Check.NotifyUp || !ch.NotifyUp) {
		return false, "notify_up off"
	}
	return true, ""
}

// quiet: der Alert faellt in die Ruhezeit (massgeblich ist sein Zeitpunkt); kritische Checks melden immer.
func (d *Dispatcher) quiet(a Alert) bool {
	if a.Kind == KindTest || a.Check.Critical {
		return false
	}
	at := a.Time
	if at.IsZero() {
		at = d.now()
	}
	return d.inQuietHours(a.Check.UserID, at)
}

// heldStore: Datenhaltung der zurueckgehaltenen Alerts (Store des Nodes). Die Module merken sich Meldungen als
// verschickt (z. B. Proxmox VE); ohne Speicher gingen sie bei einem Neustart in der Ruhezeit verloren.
type heldStore interface {
	SaveHeld(ctx context.Context, userID int64, list []Alert) error
	LoadHeld(ctx context.Context) (map[int64][]Alert, error)
}

// loadHeld holt nach dem Start die zurueckgehaltenen Alerts zurueck (Sammelmeldung nach der Ruhezeit wie sonst).
func (d *Dispatcher) loadHeld(ctx context.Context) {
	hs, ok := d.st.(heldStore)
	if !ok {
		return
	}
	m, err := hs.LoadHeld(ctx)
	if err != nil {
		d.log.Warn("held notifications not loaded", "err", err)
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for uid, list := range m {
		d.held[uid] = append(d.held[uid], list[:min(len(list), maxHeld)]...)
	}
}

// saveHeld speichert den Stand eines Accounts (leer = entfernen).
func (d *Dispatcher) saveHeld(uid int64) {
	hs, ok := d.st.(heldStore)
	if !ok {
		return
	}
	d.mu.Lock()
	list := slices.Clone(d.held[uid])
	d.mu.Unlock()
	if err := hs.SaveHeld(context.Background(), uid, list); err != nil {
		d.log.Warn("held notifications not saved", "err", err)
	}
}

// hold merkt einen in der Ruhezeit unterdrueckten Alert fuer die Sammelmeldung danach (auch gespeichert).
func (d *Dispatcher) hold(a Alert) {
	if a.Time.IsZero() {
		a.Time = d.now()
	}
	d.mu.Lock()
	full := len(d.held[a.Check.UserID]) >= maxHeld
	if !full {
		d.held[a.Check.UserID] = append(d.held[a.Check.UserID], a)
	}
	d.mu.Unlock()
	if !full {
		d.saveHeld(a.Check.UserID)
	}
}

// releaseHeld schickt nach dem Ende der Ruhezeit eine Sammelmeldung mit dem, was in der Zeit passiert ist:
// je Check der letzte Stand (noch gestoert bzw. zwischendurch gestoert und wieder OK).
func (d *Dispatcher) releaseHeld(ctx context.Context) {
	now := d.now()
	d.mu.Lock()
	ready := map[int64][]Alert{}
	for uid, list := range d.held {
		if !d.inQuietHours(uid, now) {
			ready[uid] = list
			delete(d.held, uid)
		}
	}
	d.mu.Unlock()
	for uid, list := range ready {
		d.sendDigest(ctx, uid, list)
		d.saveHeld(uid) // erst nach dem Versand entfernen
	}
}

// heldKey: wofuer in der Sammelmeldung der letzte Stand zaehlt – je Check; bei Proxmox VE je System und Ressource,
// getrennt nach Zustand, Schwelle (cpu, mem, disk) und Neustart.
func heldKey(a Alert) string {
	if !IsProxmox(a.Kind) {
		return a.Check.Token
	}
	part := "state"
	switch a.Kind {
	case KindProxmoxThreshold, KindProxmoxThresholdOK:
		part = "thr:" + a.Data["what"]
	case KindProxmoxRestarted:
		part = "restarted"
	}
	return "pve|" + a.Data["path"] + "|" + a.Check.Name + "|" + part
}

// sendDigest fasst die Ereignisse einer Ruhezeit je Kanal zusammen.
func (d *Dispatcher) sendDigest(ctx context.Context, uid int64, list []Alert) {
	sort.SliceStable(list, func(i, j int) bool { return list[i].Time.Before(list[j].Time) })
	last := map[string]Alert{} // je Check der letzte Alert
	first := map[string]Alert{}
	for _, a := range list {
		k := heldKey(a)
		if _, ok := first[k]; !ok {
			first[k] = a
		}
		last[k] = a
	}
	perChannel := map[int64][]Alert{}
	chans := map[int64]*Channel{}
	for _, a := range last {
		for _, ch := range d.channelsFor(ctx, a.Check) {
			if ok, _ := flagsOK(a, ch); ok {
				perChannel[ch.ID] = append(perChannel[ch.ID], a)
				chans[ch.ID] = ch
			}
		}
	}
	loc := d.location(uid)
	for id, items := range perChannel {
		ch := chans[id]
		lang := ch.Lang
		sort.Slice(items, func(i, j int) bool { return items[i].Check.Name < items[j].Check.Name })
		var lines []string
		stillDown, pve := 0, 0
		for _, a := range items {
			at := d.i18n.FormatDateTime(lang, first[heldKey(a)].Time, loc)
			msg := a.Message
			if IsProxmox(a.Kind) { // Text des Ereignisses (Art, Gast, Wert) in der Sprache des Kanals
				pve++
				msg = d.proxmoxEventText(lang, a)
			}
			switch {
			case a.Kind == KindProxmoxRestarted: // Hinweis, keine Stoerung
				lines = append(lines, d.i18n.T(lang, "notify.body.summary_item", "name", a.Check.Name, "message", msg+" ("+d.i18n.FormatDateTime(lang, a.Time, loc)+")"))
			case isDownKind(a.Kind):
				stillDown++
				lines = append(lines, d.i18n.T(lang, "notify.body.digest_down", "name", a.Check.Name, "time", at, "message", msg))
			default:
				lines = append(lines, d.i18n.T(lang, "notify.body.digest_up", "name", a.Check.Name, "time", d.i18n.FormatDateTime(lang, a.Time, loc)))
			}
		}
		kind, path := KindSummaryUp, "/healthchecks"
		if stillDown > 0 {
			kind, path = KindSummary, "/healthchecks?state=down"
		}
		link, subject := d.listURL(uid, path), "notify.subject.quiet_digest"
		if pve > 0 { // Proxmox VE dabei: „Meldungen“ statt „Checks“; nur Proxmox: Link auf die Proxmox-Seite
			subject = "notify.subject.quiet_digest_events"
			if pve == len(items) {
				p := proxmoxPath(items[0].Data["path"])
				for _, a := range items[1:] {
					if a.Data["path"] != items[0].Data["path"] {
						p = proxmoxPath("")
						break
					}
				}
				link = d.baseURL(uid, p)
			}
		}
		m := Message{Kind: kind, Priority: 4, Time: d.now(), Language: lang, EventID: "quiet-" + strconv.FormatInt(d.now().UnixNano(), 36), Check: CheckInfo{UserID: uid},
			Title: d.i18n.T(lang, subject, "count", len(items), "down", stillDown),
			Text:  d.i18n.T(lang, "notify.body.digest_intro") + "\n" + strings.Join(lines, "\n") + "\n" + d.nodeLine(uid, lang), URL: link}
		m.Payload = map[string]any{"kind": string(kind), "count": len(items), "down": stillDown, "checks": names(items), "node": d.nodeName(uid), "time": m.Time.UTC().Format(time.RFC3339), "title": m.Title, "text": m.Text}
		d.send(ctx, ch, m)
	}
}

// location ist die Zeitzone fuer Ruhezeiten und Zeitangaben: Ruhezeiten-
// Einstellung, sonst die Zeitzone des Nodes (aus dem Setup), sonst UTC.
func (d *Dispatcher) location(uid int64) *time.Location {
	for _, key := range []string{SetQuietTZ, SetNodeTimezone} {
		if tz := d.settings(uid)(key, ""); tz != "" {
			if l, err := time.LoadLocation(tz); err == nil {
				return l
			}
		}
	}
	return time.UTC
}

// inQuietHours prueft das Ruhefenster aus den Einstellungen.
func (d *Dispatcher) inQuietHours(uid int64, now time.Time) bool {
	set := d.settings(uid)
	if set(SetQuietEnabled, "0") != "1" {
		return false
	}
	now = now.In(d.location(uid))
	from, err1 := time.Parse("15:04", set(SetQuietFrom, "22:00"))
	to, err2 := time.Parse("15:04", set(SetQuietTo, "07:00"))
	if err1 != nil || err2 != nil {
		return false
	}
	days := set(SetQuietDays, "1,2,3,4,5,6,7")
	wd := int(now.Weekday())
	if wd == 0 {
		wd = 7
	}
	fm, tm := from.Hour()*60+from.Minute(), to.Hour()*60+to.Minute()
	nm := now.Hour()*60 + now.Minute()
	if fm <= tm {
		return nm >= fm && nm < tm && strings.Contains(","+days+",", ","+strconv.Itoa(wd)+",")
	}
	// Fenster ueber Mitternacht: der Starttag zaehlt
	if nm >= fm {
		return strings.Contains(","+days+",", ","+strconv.Itoa(wd)+",")
	}
	if nm < tm {
		prev := wd - 1
		if prev == 0 {
			prev = 7
		}
		return strings.Contains(","+days+",", ","+strconv.Itoa(prev)+",")
	}
	return false
}

// rateOK: Token-Bucket je Kanal (Standard 60 pro Stunde, Einstellung des Accounts).
func (d *Dispatcher) rateOK(id int64, per float64) bool {
	if per <= 0 {
		return true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	b, ok := d.buckets[id]
	if !ok {
		b = &bucket{tokens: per, last: now}
		d.buckets[id] = b
	}
	b.tokens = min(per, b.tokens+now.Sub(b.last).Hours()*per)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// deliver verschickt einen Alert an alle zustaendigen Kanaele (in der Ruhezeit: fuer spaeter merken; Modul-Meldungen
// ausser Proxmox VE entfallen).
func (d *Dispatcher) deliver(ctx context.Context, a Alert) {
	if d.quiet(a) && ((IsModule(a.Kind) && !IsProxmox(a.Kind)) || a.Kind == KindQuota) {
		d.log.Debug("notification dropped (quiet hours)", "name", a.Check.Name, "kind", a.Kind)
		return // steht im Verlauf des Moduls; keine Sammelmeldung danach
	}
	if d.quiet(a) {
		d.hold(a)
		d.log.Debug("notification held (quiet hours)", "check", a.Check.Name, "kind", a.Kind)
		return
	}
	for _, ch := range d.channelsFor(ctx, a.Check) {
		if ok, why := flagsOK(a, ch); !ok {
			d.log.Debug("notification suppressed", "check", a.Check.Name, "channel", ch.Name, "why", why)
			continue
		}
		m := d.compose(ch.Lang, a)
		d.send(ctx, ch, m)
	}
}

// sendSummary fasst viele gleichzeitige Stoerungen (bzw. Entwarnungen) je Kanal zusammen.
func (d *Dispatcher) sendSummary(ctx context.Context, list0 []Alert, up bool) {
	perChannel := map[int64][]Alert{}
	chans := map[int64]*Channel{}
	for _, a := range list0 {
		if d.quiet(a) {
			d.hold(a)
			continue
		}
		for _, ch := range d.channelsFor(ctx, a.Check) {
			if ok, _ := flagsOK(a, ch); !ok {
				continue
			}
			perChannel[ch.ID] = append(perChannel[ch.ID], a)
			chans[ch.ID] = ch
		}
	}
	for id, list := range perChannel {
		ch := chans[id]
		if len(list) == 1 {
			d.send(ctx, ch, d.compose(ch.Lang, list[0]))
			continue
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Check.Name < list[j].Check.Name })
		lang := ch.Lang
		var lines []string
		for _, a := range list {
			lines = append(lines, d.i18n.T(lang, "notify.body.summary_item", "name", a.Check.Name, "message", a.Message))
		}
		uid := list[0].Check.UserID
		kind, prio, key, path := KindSummary, 5, "notify.subject.summary_down", "/healthchecks?state=down"
		if up {
			kind, prio, key, path = KindSummaryUp, 3, "notify.subject.summary_up", "/healthchecks"
		}
		m := Message{Kind: kind, Priority: prio, Time: d.now(), Language: lang, EventID: list[0].EventID, Check: CheckInfo{UserID: uid},
			Title: d.i18n.T(lang, key, "count", len(list)),
			Text:  strings.Join(lines, "\n") + "\n" + d.nodeLine(uid, lang), URL: d.listURL(uid, path)}
		m.Payload = map[string]any{"kind": string(kind), "count": len(list), "checks": names(list), "node": d.nodeName(uid), "time": m.Time.UTC().Format(time.RFC3339), "title": m.Title, "text": m.Text}
		d.send(ctx, ch, m)
	}
}

func names(list []Alert) []string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		out = append(out, a.Check.Name)
	}
	return out
}

func (d *Dispatcher) nodeName(uid int64) string {
	set := d.settings(uid)
	name := set(SetNodeName, "Node64")
	if loc := set(SetNodeLocation, ""); loc != "" {
		name += " (" + loc + ")"
	}
	return name
}

func (d *Dispatcher) nodeLine(uid int64, lang string) string {
	return d.i18n.T(lang, "notify.body.node", "node", d.nodeName(uid))
}

func (d *Dispatcher) baseURL(uid int64, path string) string {
	base := strings.TrimRight(d.settings(uid)(SetBaseURL, ""), "/")
	if base == "" {
		return ""
	}
	return base + path
}

// SetLinks setzt die Pfade fuer Links in Nachrichten (Standard: Seiten des Nodes). Der hub verlinkt
// die Seiten des Portals: check(token) fuer einen Check, list(query) fuer die Liste.
func (d *Dispatcher) SetLinks(check func(token string) string, list func(query string) string) {
	d.checkPath, d.listPath = check, list
}

func (d *Dispatcher) checkURL(uid int64, token string) string {
	if d.checkPath != nil {
		return d.baseURL(uid, d.checkPath(token))
	}
	return d.baseURL(uid, "/healthchecks/"+token)
}

// listURL: path ist ein Node-Pfad wie "/healthchecks?state=down"; auf dem hub zaehlt nur die Abfrage.
func (d *Dispatcher) listURL(uid int64, path string) string {
	if d.listPath != nil {
		q := ""
		if i := strings.Index(path, "?"); i >= 0 {
			q = path[i+1:]
		}
		return d.baseURL(uid, d.listPath(q))
	}
	return d.baseURL(uid, path)
}

// compose formuliert die Nachricht in der Sprache des Kanals.
func (d *Dispatcher) compose(lang string, a Alert) Message {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	uid := a.Check.UserID
	m := Message{Kind: a.Kind, Time: a.Time, Check: a.Check, EventID: a.EventID, Language: lang, Priority: 3,
		URL: d.checkURL(uid, a.Check.Token)}
	if m.Time.IsZero() {
		m.Time = d.now()
	}
	if IsProxmox(a.Kind) {
		return d.composeProxmox(lang, a, m)
	}
	if IsModule(a.Kind) {
		return d.composeDynDNS(lang, a, m)
	}
	if a.Kind == KindQuota {
		return d.composeQuota(lang, a, m)
	}
	typeName := t("hc.type." + a.Check.Type)
	var lines []string
	switch a.Kind {
	case KindDown:
		m.Title, m.Priority = t("notify.subject.down", "name", a.Check.Name), 5
	case KindReminder:
		m.Title, m.Priority = t("notify.subject.reminder", "name", a.Check.Name, "duration", d.i18n.FormatDuration(lang, a.Duration)), 4
	case KindUp:
		m.Title, m.Priority = t("notify.subject.up", "name", a.Check.Name), 3
	case KindFlappingStart:
		m.Title, m.Priority = t("notify.subject.flapping_start", "name", a.Check.Name), 4
	case KindFlappingEnd:
		m.Title, m.Priority = t("notify.subject.flapping_end", "name", a.Check.Name), 3
	case KindDegraded:
		m.Title, m.Priority = t("notify.subject.degraded", "name", a.Check.Name), 4
	case KindDegradedEnd:
		m.Title, m.Priority = t("notify.subject.degraded_end", "name", a.Check.Name), 3
	case KindUnchecked:
		m.Title, m.Priority = t("notify.subject.unchecked", "name", a.Check.Name), 4
	case KindRechecked:
		m.Title, m.Priority = t("notify.subject.rechecked", "name", a.Check.Name), 3
	case KindTest:
		m.Title, m.Priority = t("notify.subject.test"), 2
		m.Text = t("notify.body.test", "channel", a.Check.Name) + "\n" + d.nodeLine(uid, lang)
		m.Payload = map[string]any{"kind": "test", "node": d.nodeName(uid), "time": m.Time.UTC().Format(time.RFC3339)}
		return m
	default:
		m.Title = string(a.Kind) + ": " + a.Check.Name
	}
	lines = append(lines, t("notify.body.check", "name", a.Check.Name, "type", typeName))
	if a.Check.Target != "" {
		lines = append(lines, t("notify.body.target", "target", a.Check.Target))
	}
	if a.Reason != "" && a.Kind != KindUp && a.Kind != KindFlappingEnd && a.Kind != KindUnchecked && a.Kind != KindRechecked {
		lines = append(lines, t("notify.body.reason", "reason", d.reasonText(lang, a.Reason)))
	}
	if a.Message != "" {
		lines = append(lines, t("notify.body.message", "message", a.Message))
	}
	if a.Kind == KindUp && a.Duration > 0 {
		lines = append(lines, t("notify.body.duration", "duration", d.i18n.FormatDuration(lang, a.Duration)))
	}
	if a.Flaps > 0 {
		lines = append(lines, t("notify.body.flaps", "count", a.Flaps))
	}
	lines = append(lines, t("notify.body.time", "time", d.i18n.FormatDateTime(lang, m.Time, d.location(uid))), d.nodeLine(uid, lang))
	m.Text = strings.Join(lines, "\n")
	status := "down"
	if a.Kind == KindUp || a.Kind == KindFlappingEnd || a.Kind == KindDegradedEnd || a.Kind == KindRechecked {
		status = "up"
	}
	if a.Kind == KindDegraded {
		status = "degraded"
	}
	if a.Kind == KindUnchecked {
		status = "unchecked"
	}
	m.Payload = map[string]any{
		"event_id": a.EventID, "kind": string(a.Kind), "status": status, "time": m.Time.UTC().Format(time.RFC3339),
		"check":  map[string]any{"token": a.Check.Token, "name": a.Check.Name, "type": a.Check.Type, "target": a.Check.Target, "critical": a.Check.Critical},
		"reason": a.Reason, "message": a.Message, "duration_seconds": int(a.Duration.Seconds()), "flaps": a.Flaps,
		"node": map[string]any{"name": d.settings(uid)(SetNodeName, ""), "location": d.settings(uid)(SetNodeLocation, "")}, "url": m.URL,
		"title": m.Title, "text": m.Text,
	}
	return m
}

// composeDynDNS formuliert Meldungen der Module DynDNS und DNS64 (Name = Ziel, Adressfamilie, Server oder
// Liste; Message = Einzelheiten).
func (d *Dispatcher) composeDynDNS(lang string, a Alert, m Message) Message {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	uid := a.Check.UserID
	m.URL = d.baseURL(uid, "/dyndns")
	if IsDNS64(a.Kind) {
		m.URL = d.baseURL(uid, "/dns64")
	}
	if IsCert(a.Kind) {
		m.URL = d.baseURL(uid, "/certificates")
	}
	if IsCDN64(a.Kind) {
		m.URL = d.baseURL(uid, "/cdn64")
	}
	if IsCluster(a.Kind) {
		m.URL = d.baseURL(uid, "/cluster")
	}
	if IsUpdate(a.Kind) {
		m.URL = d.baseURL(uid, "/settings#about")
	}
	if IsHoneypot(a.Kind) {
		m.URL = d.baseURL(uid, "/honeypot")
	}
	if a.Kind == KindHoneypotWatch {
		m.URL = d.baseURL(uid, "/honeypot/watch")
	}
	m.Title, m.Priority = t("notify.subject."+string(a.Kind), "name", a.Check.Name), 4
	if a.Kind == KindDynIP || a.Kind == KindDynOK || a.Kind == KindDNS64Up || a.Kind == KindCertOK || a.Kind == KindCDNOnlineUp || a.Kind == KindClusterUp || a.Kind == KindHoneypotNew || a.Kind == KindUpdateOK {
		m.Priority = 2
	}
	var lines []string
	if key := a.Data["text"]; key != "" { // Text des Moduls als Schluessel mit Werten (Sprache des Kanals)
		args := make([]any, 0, 2*len(a.Data))
		for k, v := range a.Data {
			if k != "text" {
				args = append(args, k, v)
			}
		}
		lines = append(lines, t(key, args...))
	} else if a.Message != "" {
		lines = append(lines, a.Message)
	}
	if a.Reason != "" {
		lines = append(lines, t("notify.body.reason", "reason", d.reasonText(lang, a.Reason)))
	}
	lines = append(lines, t("notify.body.time", "time", d.i18n.FormatDateTime(lang, m.Time, d.location(uid))), d.nodeLine(uid, lang))
	m.Text = strings.Join(lines, "\n")
	m.Payload = map[string]any{"event_id": a.EventID, "kind": string(a.Kind), "time": m.Time.UTC().Format(time.RFC3339), "name": a.Check.Name,
		"reason": a.Reason, "message": a.Message, "url": m.URL, "title": m.Title, "text": m.Text,
		"node": map[string]any{"name": d.settings(uid)(SetNodeName, ""), "location": d.settings(uid)(SetNodeLocation, "")}}
	return m
}

// reasonText uebersetzt einen Grund, der ein Code ist (hc.reasons.<code> bzw. notify.reason.<code>, z. B. timeout,
// traffic); Fehlertexte bleiben, wie sie sind.
func (d *Dispatcher) reasonText(lang, r string) string {
	if r == "" || strings.ContainsAny(r, " :/.") {
		return r
	}
	for _, k := range []string{"hc.reasons." + r, "notify.reason." + r} {
		if v := d.i18n.T(lang, k); v != k {
			return v
		}
	}
	return r
}

// composeProxmox formuliert Meldungen der Proxmox-VE-Ueberwachung: Titel notify.subject.<kind> mit dem Namen
// (System bzw. „System – Gast“), Text pve.ev.<what-Art>.<what> mit Name, Typ, Wert, Grenze und Detail (z. B.
// qmpstatus beim Absturz). Data: what, type (qemu, lxc, node; leer = System), value, limit, detail, system, path.
// Ein Absturz ist eine Stoerung hoher Prioritaet (5).
func (d *Dispatcher) composeProxmox(lang string, a Alert, m Message) Message {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	uid := a.Check.UserID
	data := a.Data
	if data == nil {
		data = map[string]string{}
	}
	m.URL = d.baseURL(uid, proxmoxPath(data["path"]))
	what := data["what"]
	subject := "notify.subject." + string(a.Kind)
	if data["source"] == "docker" { // Docker-Hosts laufen ueber dieselbe Ueberwachung, Betreff „Docker: …“
		subject = "notify.subject.docker_" + strings.TrimPrefix(string(a.Kind), "proxmox_")
	}
	m.Title = t(subject, "name", a.Check.Name)
	switch a.Kind {
	case KindProxmoxDown:
		m.Priority = 4
		if what == "crashed" || what == "unreachable" || what == "docker_unreachable" {
			m.Priority = 5
		}
	case KindProxmoxThreshold:
		m.Priority = 4
	case KindProxmoxRestarted:
		m.Priority = 3
	default:
		m.Priority = 2
	}
	lines := []string{d.proxmoxEventText(lang, a)}
	if a.Message != "" {
		lines = append(lines, t("notify.body.message", "message", a.Message))
	}
	if a.Kind == KindProxmoxUp && a.Duration > 0 {
		lines = append(lines, t("notify.body.duration", "duration", d.i18n.FormatDuration(lang, a.Duration)))
	}
	lines = append(lines, t("notify.body.time", "time", d.i18n.FormatDateTime(lang, m.Time, d.location(uid))), d.nodeLine(uid, lang))
	m.Text = strings.Join(lines, "\n")
	m.Payload = map[string]any{"event_id": a.EventID, "kind": string(a.Kind), "time": m.Time.UTC().Format(time.RFC3339), "name": a.Check.Name,
		"proxmox": data, "message": a.Message, "url": m.URL, "title": m.Title, "text": m.Text,
		"node": map[string]any{"name": d.settings(uid)(SetNodeName, ""), "location": d.settings(uid)(SetNodeLocation, "")}}
	return m
}

// proxmoxPath begrenzt den Link einer Proxmox-Meldung auf die Proxmox-Seiten des Nodes (sonst die Uebersicht).
func proxmoxPath(path string) string {
	if strings.HasPrefix(path, "/healthchecks/docker") { // Docker-Hosts (gleiche Ueberwachung, eigene Seiten)
		return path
	}
	if !strings.HasPrefix(path, "/healthchecks/proxmox") {
		return "/healthchecks/proxmox"
	}
	return path
}

// proxmoxEventText: Text eines Proxmox-Ereignisses (pve.ev.<Art>.<Ursache>) in der Sprache des Kanals.
func (d *Dispatcher) proxmoxEventText(lang string, a Alert) string {
	data := a.Data
	if data == nil {
		data = map[string]string{}
	}
	typ := ""
	if data["type"] != "" {
		typ = d.i18n.T(lang, "pve.type."+data["type"])
	}
	kind := strings.TrimPrefix(string(a.Kind), "proxmox_")
	what := data["what"]
	if what == "" {
		what = "guest"
		if data["type"] == "node" {
			what = "node"
		}
	}
	name := data["name"]
	if name == "" {
		name = a.Check.Name
	}
	return d.i18n.T(lang, "pve.ev."+kind+"."+what, "name", name, "type", typ, "value", data["value"], "limit", data["limit"],
		"detail", data["detail"], "system", data["system"])
}

// composeQuota: Tageskontingent der Online-Checks erreicht (Message = "verbraucht/Limit").
func (d *Dispatcher) composeQuota(lang string, a Alert, m Message) Message {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	uid := a.Check.UserID
	used, limit, _ := strings.Cut(a.Message, "/")
	m.URL, m.Priority = d.listURL(uid, "/healthchecks"), 4
	m.Title = t("notify.subject.quota")
	m.Text = strings.Join([]string{t("notify.body.quota_used", "used", used, "limit", limit), t("notify.body.quota_pause"), t("notify.body.quota_local"),
		t("notify.body.time", "time", d.i18n.FormatDateTime(lang, m.Time, d.location(uid)))}, "\n")
	m.Payload = map[string]any{"event_id": a.EventID, "kind": string(a.Kind), "time": m.Time.UTC().Format(time.RFC3339), "used": used, "limit": limit,
		"url": m.URL, "title": m.Title, "text": m.Text}
	return m
}

// send verschickt und protokolliert.
func (d *Dispatcher) send(ctx context.Context, ch *Channel, m Message) {
	var s Sender
	ok := false
	if send, _, _ := d.hooks(); ch.Execution == "server" && !d.sendServerChannels.Load() && send != nil && apiType(ch.Type) {
		s, ok = apiSender(send), true // Server-Kanal direkt ueber die ipv64-API (nur Local-, Direct- und unverknuepft)
	} else {
		if ch.Execution == "server" && !d.sendServerChannels.Load() {
			// anderer Portal-Kanal (z. B. Webhook, Telegram): die Node sendet selbst mit den Werten aus dem Sync;
			// fehlt ein Geheimnis, das nur bei ipv64 liegt, ist der Weg nicht verfuegbar (Kanal nicht gestoert)
			cp := *ch
			cp.Config = make(map[string]string, len(ch.Config))
			for k, v := range ch.Config {
				cp.Config[k] = v
			}
			if err := cp.Validate(); err != nil {
				d.record(ctx, ch, m, fmt.Errorf("%w: %v (only stored at ipv64)", ErrUnavailable, err))
				return
			}
		}
		s, ok = d.senders[ch.Type]
	}
	if !ok {
		d.record(ctx, ch, m, fmt.Errorf("no sender for type %s", ch.Type))
		return
	}
	if per := d.intSetting(m.Check.UserID, SetRatePerHour, 60); m.Kind != KindTest && !d.rateOK(ch.ID, float64(per)) {
		// im Protokoll vermerken, den Kanal aber nicht als fehlerhaft markieren (er funktioniert ja)
		d.log.Warn("notification rate limited", "channel", ch.Name, "kind", m.Kind, "per_hour", per)
		_ = d.st.AddDelivery(ctx, Delivery{EventID: m.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: string(m.Kind), CheckToken: m.Check.Token, Subject: m.Title, OK: false, Error: fmt.Sprintf("rate limited (%d per hour)", per)})
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := s.Send(sctx, ch, m)
	d.record(ctx, ch, m, retryNote(err, 0))
	if IsTemporary(err) {
		d.retry(ch, s, m, 0) // voruebergehender Fehler: spaeter erneut (retry.go)
	}
}

// apiType: Kanaltypen, die die ipv64-API zustellt (die anderen Portal-Kanaele sendet die Node selbst).
func apiType(t Type) bool { return t == TypeIPv64Mail || t == TypeIPv64SMS || t == TypeApp }

// apiSender macht aus der Versandfunktion einen Sender.
type apiSender func(ctx context.Context, ch *Channel, m Message) error

func (f apiSender) Send(ctx context.Context, ch *Channel, m Message) error { return f(ctx, ch, m) }

func (d *Dispatcher) record(ctx context.Context, ch *Channel, m Message, err error) {
	if errors.Is(err, ErrUnavailable) { // nicht der Kanal ist gestoert, der Weg fehlt noch
		d.log.Info("notification not sent, path not available", "channel", ch.Name, "kind", m.Kind, "err", RedactURLs(err.Error()))
		_ = d.st.AddDelivery(ctx, Delivery{EventID: m.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: string(m.Kind), CheckToken: m.Check.Token, Subject: m.Title, OK: false, Error: RedactURLs(err.Error())})
		return
	}
	errText := ""
	if err != nil {
		errText = RedactURLs(err.Error())
		if len(errText) > 500 {
			errText = errText[:500]
		}
		if userTarget(ch.Type) { // Ziel frei waehlbar: Antworttexte fremder Server nur kurz und ohne Geheimnisse
			errText = errorText(err)
		}
		d.log.Warn("notification failed", "channel", ch.Name, "type", ch.Type, "kind", m.Kind, "err", errText)
	} else {
		d.log.Info("notification sent", "channel", ch.Name, "type", ch.Type, "kind", m.Kind, "check", m.Check.Name)
	}
	_ = d.st.AddDelivery(ctx, Delivery{EventID: m.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: string(m.Kind), CheckToken: m.Check.Token, Subject: m.Title, OK: err == nil, Error: errText})
	_ = d.st.Touch(ctx, ch.ID, errText)
}

// userTarget: Kanaltypen, deren Ziel (Server, URL, Mailserver) der Nutzer frei angibt.
func userTarget(t Type) bool {
	switch t {
	case TypeWebhook, TypeNtfy, TypeGotify, TypeIGotify, TypeSMTP, TypeMatrix, TypeSlack, TypeTeams, TypeDiscord, TypeSecNtfy:
		return true
	}
	return false
}

// errorText: gespeicherter Fehlertext solcher Kanaele (gesperrtes Ziel nur allgemein, sonst ohne URLs und
// Geheimnisse, hoechstens 300 Bytes).
func errorText(err error) string {
	if errors.Is(err, ErrPrivateTarget) {
		return ErrPrivateTarget.Error()
	}
	s := RedactSecrets(RedactURLs(err.Error()))
	if len(s) > 300 {
		s = s[:300]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// urlRe findet Adressen in Fehlertexten (Fehler von net/http enthalten die komplette URL).
var urlRe = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"'<>]+`)

// RedactURLs kuerzt Adressen in einem Text auf Schema und Host: Webhook-, Telegram-, Discord- und Slack-URLs
// enthalten Tokens, die so weder ins Log noch in die Zustellliste oder zum hub gelangen.
func RedactURLs(s string) string {
	return urlRe.ReplaceAllStringFunc(s, func(raw string) string {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return "[url]"
		}
		if u.Path == "" && u.RawQuery == "" && u.User == nil && u.Fragment == "" {
			return raw
		}
		return u.Scheme + "://" + u.Host + "/…"
	})
}

// Test schickt sofort eine Testnachricht ueber einen Kanal.
func (d *Dispatcher) Test(ctx context.Context, ch *Channel) error {
	s, ok := d.senders[ch.Type]
	if !ok {
		return fmt.Errorf("no sender for type %s", ch.Type)
	}
	m := d.compose(ch.Lang, Alert{Kind: KindTest, Check: CheckInfo{UserID: ch.UserID, Name: ch.Name}, EventID: "test-" + strconv.FormatInt(d.now().UnixNano(), 36)})
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := s.Send(sctx, ch, m)
	d.record(ctx, ch, m, err)
	if err != nil {
		return redactedErr{err} // fuer Anzeige und API ohne Tokens aus der Kanal-URL
	}
	return nil
}

// redactedErr gibt den Fehlertext ohne Tokens in Adressen aus; errors.Is/As sehen weiter den Originalfehler.
type redactedErr struct{ err error }

func (e redactedErr) Error() string { return RedactURLs(e.err.Error()) }
func (e redactedErr) Unwrap() error { return e.err }
