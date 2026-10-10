// Package checker ist die Rolle "checker" des hub: fuehrt die Online-Checks
// des eigenen Standorts aus, haelt die Zuteilung (Slots) aktuell, nimmt
// Konfigurationsaenderungen und Heartbeats auf und verdichtet Messdaten.
package checker

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/ipv64net/agent/internal/checks"
	hubnotify "github.com/ipv64net/agent/internal/hub/notify"
	"github.com/ipv64net/agent/internal/hub/store"
	"github.com/ipv64net/agent/internal/notify"
	"github.com/ipv64net/agent/internal/scheduler"
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
	lastLog  int64
	lastPush time.Time
	wg       sync.WaitGroup
	cancel   context.CancelFunc
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
}

// onOverall setzt einen Wechsel des Gesamtzustands in einen Alert um.
func (c *Checker) onOverall(e store.OverallEvent) {
	kind := notify.Kind(e.Kind)
	switch kind {
	case notify.KindDown, notify.KindUp, notify.KindFlappingStart, notify.KindFlappingEnd, notify.KindDegraded, notify.KindDegradedEnd:
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
			NotifyDown: e.NotifyDown, NotifyUp: e.NotifyUp, NotifyDegraded: e.NotifyDegraded}})
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
				NotifyDown: e.NotifyDown, NotifyUp: e.NotifyUp, NotifyDegraded: e.NotifyDegraded}})
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
	c.sched = scheduler.New(c.st, notifier{c.log}, runner, c.log, scheduler.Options{Workers: c.workers})
	nodes, _ := c.st.LiveNodes(ctx)
	c.slotIdx, c.slotMod = c.st.SlotShare(nodes)
	if err := c.reloadAll(ctx); err != nil {
		return err
	}
	c.sched.Start(ctx)
	c.wg.Add(4)
	go c.heartbeatLoop(ctx)
	go c.configLoop(ctx)
	go c.pushLoop(ctx)
	go c.housekeepingLoop(ctx)
	return nil
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
		if !ck.MeasuredHere(c.location) {
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
	mine := ck != nil && ck.MeasuredHere(c.location) && ck.Slot%mod == idx
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
			c.mu.Lock()
			changed := idx != c.slotIdx || mod != c.slotMod
			c.slotIdx, c.slotMod = idx, mod
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
			day := now.Format("2006-01-02")
			if lastDaily == day || now.Hour() < 0 {
				continue
			}
			// einmal taeglich (erste Fuenf-Minuten-Runde des Tages, bei Start sofort)
			if err := c.st.RotatePartitions(ctx, now, 8); err != nil {
				c.log.Error("partition rotation failed", "err", err)
			}
			if err := c.st.AggregateDaily(ctx, now); err != nil {
				c.log.Error("daily aggregation failed", "err", err)
			}
			c.st.Cleanup(ctx, now)
			lastDaily = day
		}
	}
}
