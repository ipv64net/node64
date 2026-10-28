// Package checker ist die Rolle "checker" des hub: fuehrt die Online-Checks
// des eigenen Standorts aus, haelt die Zuteilung (Slots) aktuell, nimmt
// Konfigurationsaenderungen und Heartbeats auf und verdichtet Messdaten.
package checker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	hubnotify "github.com/ipv64net/node64/internal/hub/notify"
	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/wire"
)

// Checker haelt Scheduler und Hintergrundschleifen einer Instanz.
type Checker struct {
	st       *store.Store
	log      *slog.Logger
	location string
	version  string
	roles    string
	workers  int

	sched   *scheduler.Scheduler
	started time.Time
	// Benachrichtigungen (nil = nur Log)
	dispatcher *notify.Dispatcher
	nfStore    *hubnotify.Store
	reminders  map[string]time.Time

	mu       sync.Mutex
	slotIdx  int
	slotMod  int
	loaded   map[string]int64 // token -> revision
	liveLocs map[string]bool  // Standorte mit lebendem hub (Push-Auswertung)
	lastLog  int64
	lastPush time.Time
	wg       sync.WaitGroup
	cancel   context.CancelFunc
	throttle *throttle // Bremse je Zielhost und Server (throttle.go)
}

// New erzeugt den Checker.
func New(st *store.Store, log *slog.Logger, location, version, roles string, workers int) *Checker {
	return &Checker{st: st, log: log.With("module", "checker"), location: location, version: version, roles: roles, workers: workers,
		loaded: map[string]int64{}, slotMod: 1, reminders: map[string]time.Time{}}
}

// SetNotifier haengt Dispatcher und Kanal-Store an; der Store ruft OnOverall.
func (c *Checker) SetNotifier(d *notify.Dispatcher, nf *hubnotify.Store) {
	c.dispatcher, c.nfStore = d, nf
	c.st.OnOverall = c.onOverall
	c.st.OnQuotaReached = c.quotaReached
}

// quotaReached meldet einmal je Account und Tag, dass das Tageskontingent der Online-Checks erreicht ist
// (Standardkanaele des Accounts; die Online-Checks pausieren bis Mitternacht).
func (c *Checker) quotaReached(userID int64, today, limit int) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		id := c.st.ClaimQuotaNotice(ctx, userID)
		if id == "" {
			return // schon gemeldet (heute oder vom anderen hub)
		}
		c.log.Info("daily quota reached, notifying", "user", userID, "used", today, "limit", limit)
		c.dispatcher.Dispatch(notify.Alert{EventID: id, Kind: notify.KindQuota, Time: time.Now().UTC(), Message: fmt.Sprintf("%d/%d", today, limit),
			Check: notify.CheckInfo{UserID: userID, Name: "Healthchecks", NotifyDown: true, NotifyUp: true}})
	}()
}

// onOverall setzt einen Wechsel des Gesamtzustands in einen Alert um.
func (c *Checker) onOverall(e store.OverallEvent) {
	kind := notify.Kind(e.Kind)
	switch kind {
	case notify.KindDown, notify.KindUp, notify.KindFlappingStart, notify.KindFlappingEnd, notify.KindDegraded, notify.KindDegradedEnd, notify.KindUnchecked, notify.KindRechecked:
	default:
		return
	}
	if kind == notify.KindUp {
		c.mu.Lock()
		delete(c.reminders, e.Token)
		c.mu.Unlock()
	}
	if c.dispatcher == nil {
		c.log.Info("notification", "check", e.Name, "kind", kind, "reason", e.Reason, "message", e.Message)
		return
	}
	c.dispatcher.Dispatch(notify.Alert{EventID: e.EventID, Kind: kind, Time: e.Time, Reason: e.Reason, Message: e.Message, Duration: e.Duration,
		Check: notify.CheckInfo{UserID: e.UserID, Token: e.Token, Name: e.Name, Type: e.Type, Target: e.Target, Critical: e.Critical, Channels: e.Channels,
			NotifyDown: e.NotifyDown, NotifyUp: e.NotifyUp, NotifyDegraded: e.NotifyDegraded, DirectNode: e.DirectNode}})
}

// remind schickt Erinnerungen fuer laenger gestoerte Checks (repeat_minutes);
// nur der Housekeeper, damit es sie nur einmal gibt.
func (c *Checker) remind(ctx context.Context) {
	if c.dispatcher == nil {
		return
	}
	list, err := c.st.DueReminders(ctx)
	if err != nil {
		c.log.Warn("reminders query failed", "err", err)
		return
	}
	now := time.Now().UTC()
	for _, e := range list {
		if e.Execution == "online" && c.st.DailyBlocked(e.UserID) {
			continue // Tageskontingent erschoepft: nicht gemessen, also auch nicht "noch gestoert" erinnern
		}
		if e.DirectNode != "" && c.st.InMaintenanceOf(e.UserID, e.Token, now) {
			continue // lokaler Check in der Wartung: keine Erinnerung (wie auf der Node)
		}
		c.mu.Lock()
		last, ok := c.reminders[e.Token]
		if !ok {
			last = e.Time // down_since
		}
		due := !last.IsZero() && now.Sub(last) >= e.Duration // Duration = repeat
		if due {
			c.reminders[e.Token] = now
		}
		c.mu.Unlock()
		if !due {
			continue
		}
		c.dispatcher.Dispatch(notify.Alert{EventID: scheduler.NewID(), Kind: notify.KindReminder, Time: now, Reason: e.Reason, Message: e.Message, Duration: now.Sub(e.Time),
			Check: notify.CheckInfo{UserID: e.UserID, Token: e.Token, Name: e.Name, Type: e.Type, Target: e.Target, Critical: e.Critical, Channels: e.Channels,
				NotifyDown: e.NotifyDown, NotifyUp: e.NotifyUp, NotifyDegraded: e.NotifyDegraded, DirectNode: e.DirectNode}})
	}
}

// notifier: Ereignisse je Messstelle sind still; Alarme kommen aus dem
// Gesamtzustand (store.Reverdict). Hier nur Debug-Log.
type notifier struct{ log *slog.Logger }

func (n notifier) Notify(_ context.Context, e scheduler.Event, c scheduler.Check) {
	n.log.Debug("source event", "check", c.Name, "kind", e.Kind, "from", e.From, "to", e.To, "reason", e.Reason)
}

// Start laedt die Checks und startet alle Schleifen.
func (c *Checker) Start(ctx context.Context) error {
	ctx, c.cancel = context.WithCancel(ctx)
	c.started = time.Now().UTC()
	if err := c.st.Heartbeat(ctx, c.roles, c.version, 0, c.started); err != nil {
		return err
	}
	if err := c.st.ReloadMaintenance(ctx); err != nil {
		c.log.Warn("maintenance reload failed", "err", err)
	}
	if id, err := c.st.MaxConfigLogID(ctx); err == nil {
		c.lastLog = id
	}
	c.lastPush = time.Now().UTC()
	runner := checks.NewRunner()
	runner.DenyPrivate = true // nur oeffentliche Ziele, auch nach Aufloesung/Weiterleitung (internes Netz der hubs)
	if c.throttle == nil {
		c.throttle = newThrottle(0, 0, c.log)
	}
	c.sched = scheduler.New(c.st, notifier{c.log}, runner, c.log, scheduler.Options{Workers: c.workers, Allow: c.st.AllowRun, Throttle: c.throttle.allow})
	nodes, _ := c.st.LiveNodes(ctx)
	c.slotIdx, c.slotMod = c.st.SlotShare(nodes)
	if len(nodes) > 0 {
		c.liveLocs = locsOf(nodes)
	}
	if err := c.reloadAll(ctx); err != nil {
		return err
	}
	c.sched.Start(ctx)
	c.wg.Add(5)
	go c.heartbeatLoop(ctx)
	go c.configLoop(ctx)
	go c.pushLoop(ctx)
	go c.housekeepingLoop(ctx)
	go c.testrunLoop(ctx, runner)
	return nil
}

// testrunLoop fuehrt Testlaeufe des Umhaengens (hc2_testruns) fuer diesen Standort aus (alle 2 s).
func (c *Checker) testrunLoop(ctx context.Context, runner *checks.Runner) {
	defer c.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	expire := time.NewTicker(30 * time.Second)
	defer expire.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-expire.C:
			c.st.ExpireTestruns(ctx)
		case <-t.C:
			list, err := c.st.PendingTestruns(ctx, c.location)
			if err != nil {
				c.log.Warn("testruns query failed", "err", err)
				continue
			}
			for _, tr := range list {
				out := c.runTest(ctx, runner, tr.Definition)
				if err := c.st.TestrunResult(ctx, tr.ID, c.location, out); err != nil {
					c.log.Warn("testrun result failed", "id", tr.ID, "err", err)
				}
				c.log.Info("testrun done", "id", tr.ID, "token", tr.Token, "ok", out.OK)
			}
		}
	}
}

// runTest fuehrt eine Check-Definition (wire.Check als JSON) einmal aus.
func (c *Checker) runTest(ctx context.Context, runner *checks.Runner, raw json.RawMessage) store.TestrunOutcome {
	out := store.TestrunOutcome{Time: time.Now().UTC()}
	var w wire.Check
	if err := json.Unmarshal(raw, &w); err != nil {
		out.Error = "invalid definition: " + err.Error()
		return out
	}
	def := checks.Definition{Token: w.Token, Type: checks.Type(w.Type), Target: w.Target, Params: w.Params, IPMode: checks.IPMode(w.IPMode),
		Timeouts: checks.Timeouts{Connect: time.Duration(w.ConnectTimeoutSeconds * float64(time.Second)), Total: time.Duration(w.TimeoutSeconds * float64(time.Second))}}
	if def.Timeouts.Connect <= 0 {
		def.Timeouts.Connect = checks.DefaultConnectTimeout
	}
	if def.Timeouts.Total <= 0 {
		def.Timeouts.Total = checks.DefaultTotalTimeout
	}
	def.Timeouts.Connect, def.Timeouts.Total = min(def.Timeouts.Connect, store.MaxConnectTimeout), min(def.Timeouts.Total, store.MaxTotalTimeout)
	if err := checks.Validate(def); err != nil {
		out.Error = err.Error()
		return out
	}
	if store.PrivateTarget(string(def.Type), def.Target) || (def.Type == checks.TypeDNS && checks.DNSNeedsNode(def.Params)) {
		out.Error = "online checks cannot target private addresses"
		return out
	}
	if def.Type == checks.TypePush {
		out.OK = true // nichts zu messen
		return out
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := runner.Run(rctx, def)
	list := make([]map[string]any, 0, len(results))
	out.OK = len(results) > 0
	for _, r := range results {
		if r.Status != checks.Up {
			out.OK = false
		}
		list = append(list, map[string]any{"status": r.Status, "latency_ms": r.LatencyMS(), "reason": r.Reason, "message": r.Message, "family": r.Family, "time": r.Time})
	}
	out.Results, _ = json.Marshal(list)
	return out
}

// Stop haelt alles an und meldet die Instanz ab.
func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	if c.sched != nil {
		c.sched.Stop()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.st.Leave(ctx)
}

// Count liefert die Anzahl geladener Checks.
func (c *Checker) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.loaded)
}

// Started ist der Startzeitpunkt.
func (c *Checker) Started() time.Time { return c.started }

// Scheduler gibt den Scheduler frei (Gateway: Testlaeufe, Kommandos).
func (c *Checker) Scheduler() *scheduler.Scheduler { return c.sched }

// reloadAll laedt die Zuteilung komplett neu: neue/geaenderte Checks rein,
// nicht mehr zugeteilte raus.
func (c *Checker) reloadAll(ctx context.Context) error {
	c.mu.Lock()
	idx, mod := c.slotIdx, c.slotMod
	c.mu.Unlock()
	list, err := c.st.LoadChecks(ctx, mod, idx)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	added, updated := 0, 0
	for _, ck := range list {
		if !ck.MeasuredHere(c.location, c.live()) {
			continue
		}
		want[ck.Token] = true
		c.st.Remember(ck)
		c.mu.Lock()
		rev, known := c.loaded[ck.Token]
		c.loaded[ck.Token] = ck.Revision
		c.mu.Unlock()
		if known && rev == ck.Revision {
			continue
		}
		if known {
			updated++
			c.sched.Upsert(ck.SchedulerCheck(), nil) // Zustand behalten
		} else {
			added++
			c.sched.Upsert(ck.SchedulerCheck(), ck.Runtime)
		}
	}
	removed := 0
	c.mu.Lock()
	for token := range c.loaded {
		if !want[token] {
			delete(c.loaded, token)
			c.sched.Remove(token)
			c.st.Forget(token)
			removed++
		}
	}
	n := len(c.loaded)
	c.mu.Unlock()
	c.st.Metrics.Set(n, 0, idx, mod)
	c.log.Info("checks loaded", "count", n, "added", added, "updated", updated, "removed", removed, "slot", idx, "of", mod)
	return nil
}

// applyCheck laedt einen einzelnen Check nach einer Aenderung.
func (c *Checker) applyCheck(ctx context.Context, token string) {
	ck, err := c.st.LoadCheck(ctx, token)
	if err != nil {
		c.log.Error("load check failed", "token", token, "err", err)
		return
	}
	c.mu.Lock()
	idx, mod := c.slotIdx, c.slotMod
	_, known := c.loaded[token]
	c.mu.Unlock()
	mine := ck != nil && ck.MeasuredHere(c.location, c.live()) && ck.Slot%mod == idx
	switch {
	case mine && known:
		c.st.Remember(ck)
		c.mu.Lock()
		c.loaded[token] = ck.Revision
		c.mu.Unlock()
		c.sched.Upsert(ck.SchedulerCheck(), nil)
		c.log.Info("check updated", "token", token, "name", ck.Name, "revision", ck.Revision)
	case mine && !known:
		c.st.Remember(ck)
		c.mu.Lock()
		c.loaded[token] = ck.Revision
		c.mu.Unlock()
		c.sched.Upsert(ck.SchedulerCheck(), ck.Runtime)
		c.log.Info("check added", "token", token, "name", ck.Name)
	case !mine && known:
		c.mu.Lock()
		delete(c.loaded, token)
		c.mu.Unlock()
		c.sched.Remove(token)
		c.st.Forget(token)
		c.log.Info("check removed", "token", token)
	}
	c.mu.Lock()
	n := len(c.loaded)
	c.mu.Unlock()
	c.st.Metrics.Set(n, 0, idx, mod)
}

func locsOf(nodes []store.HubInstance) map[string]bool {
	m := map[string]bool{}
	for _, n := range nodes {
		m[n.Location] = true
	}
	return m
}

func sameLocs(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// live liefert die lebenden Standorte (Kopie); vor dem ersten Heartbeat nil.
func (c *Checker) live() map[string]bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.liveLocs == nil {
		return nil
	}
	m := make(map[string]bool, len(c.liveLocs))
	for k, v := range c.liveLocs {
		m[k] = v
	}
	return m
}

func (c *Checker) heartbeatLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.st.Heartbeat(ctx, c.roles, c.version, 0, c.started); err != nil {
				c.log.Warn("heartbeat failed", "err", err)
				continue
			}
			nodes, err := c.st.LiveNodes(ctx)
			if err != nil {
				continue
			}
			idx, mod := c.st.SlotShare(nodes)
			locs := locsOf(nodes)
			c.mu.Lock()
			changed := idx != c.slotIdx || mod != c.slotMod || !sameLocs(locs, c.liveLocs)
			c.slotIdx, c.slotMod, c.liveLocs = idx, mod, locs
			c.mu.Unlock()
			if changed {
				c.log.Info("slot share changed", "slot", idx, "of", mod, "nodes", len(nodes))
				if err := c.reloadAll(ctx); err != nil {
					c.log.Error("reload failed", "err", err)
				}
			}
		}
	}
}

// configLoop pollt hc2_config_log alle 2 s (Redis beschleunigt das spaeter nur).
func (c *Checker) configLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			changes, err := c.st.ConfigChanges(ctx, c.lastLog, 500)
			if err != nil {
				c.log.Warn("config log poll failed", "err", err)
				continue
			}
			maint := false
			for _, ch := range changes {
				c.lastLog = ch.ID
				switch ch.Entity {
				case "check":
					c.applyCheck(ctx, ch.EntityID)
				case "maintenance":
					maint = true
				case "channel", "settings":
					if c.nfStore != nil {
						c.nfStore.Invalidate(ch.UserID)
					}
				}
			}
			if maint {
				if err := c.st.ReloadMaintenance(ctx); err != nil {
					c.log.Warn("maintenance reload failed", "err", err)
				}
			}
		}
	}
}

// pushLoop holt Heartbeats, die ueber health.php in die Datenbank kamen, und
// gibt sie an den Scheduler (nur Push-Checks dieser Messstelle).
func (c *Checker) pushLoop(ctx context.Context) {
	defer c.wg.Done()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rows, err := c.st.Pushes(ctx, c.lastPush)
			if err != nil {
				c.log.Warn("push poll failed", "err", err)
				continue
			}
			for _, p := range rows {
				if p.ReceivedAt.After(c.lastPush) {
					c.lastPush = p.ReceivedAt
				}
				c.mu.Lock()
				_, mine := c.loaded[p.Token]
				c.mu.Unlock()
				if !mine {
					continue
				}
				c.sched.Push(ctx, p.Token, p.Status, p.Message, map[string]any{"via": "db"})
			}
		}
	}
}

// housekeepingLoop: stuendliche Verdichtung alle 5 min, Wartungsfenster
// minuetlich, taegliche Aufgaben durch den Housekeeper.
func (c *Checker) housekeepingLoop(ctx context.Context) {
	defer c.wg.Done()
	minute := time.NewTicker(time.Minute)
	defer minute.Stop()
	five := time.NewTicker(5 * time.Minute)
	defer five.Stop()
	lastDaily := ""
	// "nicht geprueft" erst 10 min nach dem Start und nach dem letzten Datenbankfehler: vorher sind die Zustaende
	// der Nodes noch nicht wieder gemeldet (sonst kaeme fuer jeden Check eine Meldung)
	started, dbErrAt, dbErrs := time.Now(), time.Time{}, c.st.Metrics.DBErrorCount()
	for {
		select {
		case <-ctx.Done():
			return
		case <-minute.C:
			if err := c.st.ReloadMaintenance(ctx); err != nil {
				c.log.Warn("maintenance reload failed", "err", err)
			}
			if nodes, err := c.st.LiveNodes(ctx); err == nil && c.st.IsHousekeeper(nodes) {
				c.remind(ctx)
				if e := c.st.Metrics.DBErrorCount(); e != dbErrs {
					dbErrs, dbErrAt = e, time.Now()
				}
				if time.Since(started) < 10*time.Minute || time.Since(dbErrAt) < 10*time.Minute {
					// noch in der Anlaufzeit bzw. kurz nach einem Datenbankfehler
				} else if n, err := c.st.UncheckedSweep(ctx); err != nil {
					c.log.Warn("unchecked sweep failed", "err", err)
				} else if n > 0 {
					c.log.Info("checks without measurements re-evaluated", "count", n)
				}
			}
		case <-five.C:
			now := time.Now().UTC()
			if err := c.st.AggregateHourly(ctx, now); err != nil {
				c.log.Error("hourly aggregation failed", "err", err)
			}
			nodes, err := c.st.LiveNodes(ctx)
			if err != nil || !c.st.IsHousekeeper(nodes) {
				continue
			}
			c.st.Metrics.Set(c.Count(), len(nodes), c.slotIdx, c.slotMod)
			if n, err := c.st.CleanupStaleSources(ctx, now); err != nil {
				c.log.Warn("cleaning up stale sources failed", "err", err)
			} else if n > 0 {
				c.log.Info("removed stale sources", "count", n)
			}
			if n, err := c.st.CloseDeletedIncidents(ctx); err != nil {
				c.log.Warn("closing incidents of deleted checks failed", "err", err)
			} else if n > 0 {
				c.log.Info("closed incidents of deleted checks", "count", n)
			}
			if err := c.st.AggregateHourlyShared(ctx, now); err != nil {
				c.log.Error("hourly aggregation (nodes/push) failed", "err", err)
			}
			day := now.Format("2006-01-02")
			if lastDaily == day || now.Hour() < 0 {
				continue
			}
			// einmal taeglich (erste Fuenf-Minuten-Runde des Tages, bei Start sofort)
			if err := c.st.RotatePartitions(ctx, now, store.RawKeepDays); err != nil {
				c.log.Error("partition rotation failed", "err", err)
			}
			if err := c.st.AggregateDaily(ctx, now); err != nil {
				c.log.Error("daily aggregation failed", "err", err)
			}
			c.st.Cleanup(ctx, now)
			c.st.PruneUsage(ctx)
			lastDaily = day
		}
	}
}
