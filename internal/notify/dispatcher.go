package notify

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	pending []Alert
	timer   *time.Timer
	buckets map[int64]*bucket
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
	// Hooks fuer Tests
	now func() time.Time
	// sendServerChannels: Server-Kanaele trotzdem lokal senden (Node-Einstellung)
	sendServerChannels bool
	serverSends        func() bool
}

// SetSendServerChannels schaltet den lokalen Versand ueber Server-Kanaele.
func (d *Dispatcher) SetSendServerChannels(on bool) { d.sendServerChannels = on }

// SetServerSends meldet, ob gerade der ipv64-hub die Benachrichtigungen uebernimmt (verknuepft und verbunden).
// Dann sendet die Node ihre eigenen Kanaele nicht selbst, sondern erhaelt Sendeauftraege vom hub.
func (d *Dispatcher) SetServerSends(fn func() bool) { d.serverSends = fn }

type bucket struct {
	tokens float64
	last   time.Time
}

// NewDispatcher ist der Dispatcher des Nodes (ein Account).
func NewDispatcher(st *Store, senders map[Type]Sender, bundle *i18n.Bundle, settings Settings, log *slog.Logger) *Dispatcher {
	return NewMultiDispatcher(st, senders, bundle, func(int64) Settings { return settings }, log)
}

// NewMultiDispatcher ist der Dispatcher des Servers: Kanaele und Einstellungen je Account.
func NewMultiDispatcher(st ChannelStore, senders map[Type]Sender, bundle *i18n.Bundle, settingsFor SettingsFor, log *slog.Logger) *Dispatcher {
	return &Dispatcher{st: st, senders: senders, i18n: bundle, settingsFor: settingsFor, log: log.With("module", "notify"),
		queue: make(chan Alert, 1000), buckets: map[int64]*bucket{}, now: func() time.Time { return time.Now() }}
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

func (d *Dispatcher) intSetting(key string, def int) int {
	n, err := strconv.Atoi(d.settings(0)(key, strconv.Itoa(def)))
	if err != nil {
		return def
	}
	return n
}

// run sammelt Alerts kurz, damit viele gleichzeitige Stoerungen zu einer
// Sammelmeldung werden, und verschickt dann.
func (d *Dispatcher) run() {
	defer d.wg.Done()
	var flush <-chan time.Time
	for {
		select {
		case <-d.ctx.Done():
			d.flush(context.Background())
			return
		case a := <-d.queue:
			d.mu.Lock()
			d.pending = append(d.pending, a)
			d.mu.Unlock()
			if flush == nil {
				window := time.Duration(d.intSetting(SetBatchWindow, 10)) * time.Second
				if window <= 0 {
					window = time.Millisecond
				}
				flush = time.After(window)
			}
		case <-flush:
			flush = nil
			d.flush(d.ctx)
		}
	}
}

// flush verschickt alle gesammelten Alerts.
func (d *Dispatcher) flush(ctx context.Context) {
	d.mu.Lock()
	batch := d.pending
	d.pending = nil
	d.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	threshold := d.intSetting(SetBatchThreshold, 3)
	var downs, rest []Alert
	for _, a := range batch {
		if a.Kind == KindDown {
			downs = append(downs, a)
		} else {
			rest = append(rest, a)
		}
	}
	if threshold > 1 && len(downs) >= threshold {
		d.sendSummary(ctx, downs)
	} else {
		rest = append(downs, rest...)
	}
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
	for _, ch := range all {
		if !ch.Enabled {
			continue
		}
		if ch.Execution == "server" && !d.sendServerChannels {
			continue // vom ipv64-hub gesendet
		}
		if !d.sendServerChannels && d.serverSends != nil && d.serverSends() {
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
	return out
}

func isDownKind(k Kind) bool {
	return k == KindDown || k == KindReminder || k == KindFlappingStart || k == KindSummary || k == KindDegraded
}

// allowed prueft die Flags von Check und Kanal sowie Ruhezeiten.
func (d *Dispatcher) allowed(a Alert, ch *Channel) (bool, string) {
	down := isDownKind(a.Kind)
	if a.Kind != KindTest {
		if (a.Kind == KindDegraded || a.Kind == KindDegradedEnd) && !a.Check.NotifyDegraded {
			return false, "notify_degraded off"
		}
		if down && (!a.Check.NotifyDown || !ch.NotifyDown) {
			return false, "notify_down off"
		}
		if !down && (!a.Check.NotifyUp || !ch.NotifyUp) {
			return false, "notify_up off"
		}
		if !a.Check.Critical && d.inQuietHours(a.Check.UserID, d.now()) {
			return false, "quiet hours"
		}
	}
	return true, ""
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

// rateOK: Token-Bucket je Kanal (Standard 60 pro Stunde).
func (d *Dispatcher) rateOK(id int64) bool {
	per := float64(d.intSetting(SetRatePerHour, 60))
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

// deliver verschickt einen Alert an alle zustaendigen Kanaele.
func (d *Dispatcher) deliver(ctx context.Context, a Alert) {
	for _, ch := range d.channelsFor(ctx, a.Check) {
		if ok, why := d.allowed(a, ch); !ok {
			d.log.Debug("notification suppressed", "check", a.Check.Name, "channel", ch.Name, "why", why)
			continue
		}
		m := d.compose(ch.Lang, a)
		d.send(ctx, ch, m)
	}
}

// sendSummary fasst viele gleichzeitige Stoerungen je Kanal zusammen.
func (d *Dispatcher) sendSummary(ctx context.Context, downs []Alert) {
	perChannel := map[int64][]Alert{}
	chans := map[int64]*Channel{}
	for _, a := range downs {
		for _, ch := range d.channelsFor(ctx, a.Check) {
			if ok, _ := d.allowed(a, ch); !ok {
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
		m := Message{Kind: KindSummary, Priority: 5, Time: d.now(), Language: lang, EventID: list[0].EventID, Check: CheckInfo{UserID: uid},
			Title: d.i18n.T(lang, "notify.subject.summary_down", "count", len(list)),
			Text:  strings.Join(lines, "\n") + "\n" + d.nodeLine(uid, lang), URL: d.baseURL(uid, "/healthchecks?state=down")}
		m.Payload = map[string]any{"kind": "summary", "count": len(list), "checks": names(list), "node": d.nodeName(uid), "time": m.Time.UTC().Format(time.RFC3339)}
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

// compose formuliert die Nachricht in der Sprache des Kanals.
func (d *Dispatcher) compose(lang string, a Alert) Message {
	t := func(key string, args ...any) string { return d.i18n.T(lang, key, args...) }
	uid := a.Check.UserID
	m := Message{Kind: a.Kind, Time: a.Time, Check: a.Check, EventID: a.EventID, Language: lang, Priority: 3,
		URL: d.baseURL(uid, "/healthchecks/"+a.Check.Token)}
	if m.Time.IsZero() {
		m.Time = d.now()
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
	if a.Reason != "" && a.Kind != KindUp && a.Kind != KindFlappingEnd {
		lines = append(lines, t("notify.body.reason", "reason", a.Reason))
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
	if a.Kind == KindUp || a.Kind == KindFlappingEnd || a.Kind == KindDegradedEnd {
		status = "up"
	}
	if a.Kind == KindDegraded {
		status = "degraded"
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

// send verschickt und protokolliert.
func (d *Dispatcher) send(ctx context.Context, ch *Channel, m Message) {
	s, ok := d.senders[ch.Type]
	if !ok {
		d.record(ctx, ch, m, fmt.Errorf("no sender for type %s", ch.Type))
		return
	}
	if m.Kind != KindTest && !d.rateOK(ch.ID) {
		d.record(ctx, ch, m, fmt.Errorf("rate limited (%s per hour)", d.settings(0)(SetRatePerHour, "60")))
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err := s.Send(sctx, ch, m)
	d.record(ctx, ch, m, err)
}

func (d *Dispatcher) record(ctx context.Context, ch *Channel, m Message, err error) {
	errText := ""
	if err != nil {
		errText = err.Error()
		if len(errText) > 500 {
			errText = errText[:500]
		}
		d.log.Warn("notification failed", "channel", ch.Name, "type", ch.Type, "kind", m.Kind, "err", errText)
	} else {
		d.log.Info("notification sent", "channel", ch.Name, "type", ch.Type, "kind", m.Kind, "check", m.Check.Name)
	}
	_ = d.st.AddDelivery(ctx, Delivery{EventID: m.EventID, ChannelID: ch.ID, Channel: ch.Name, Kind: string(m.Kind), CheckToken: m.Check.Token, Subject: m.Title, OK: err == nil, Error: errText})
	_ = d.st.Touch(ctx, ch.ID, errText)
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
	return err
}
