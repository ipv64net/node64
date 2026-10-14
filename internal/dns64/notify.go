package dns64

import (
	"context"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/notify"
)

// Benachrichtigungen ueber die Standardkanaele des Kerns (immer lokal, in der Ruhezeit verworfen):
// Upstream-Server laenger gestoert bzw. wieder da, Blockliste mehrmals nicht ladbar.

const (
	setNotifyUpstream = "dns64.notify_upstream"
	setNotifyLists    = "dns64.notify_lists"

	monitorEvery  = 30 * time.Second
	upstreamGrace = 3 * time.Minute // erst melden, wenn ein Server so lange gestoert ist
	listFailures  = 3               // erst melden nach so vielen Fehlversuchen hintereinander
)

// SetNotifier installiert den Versand (Dispatcher des Kerns).
func (m *Module) SetNotifier(f func(notify.Alert)) { m.notifier = f }

// monitor merkt sich, was schon gemeldet wurde.
type monitor struct {
	badSince map[string]time.Time // URL -> gestoert seit
	upSent   map[string]bool      // URL -> Stoerung gemeldet
	listSent map[string]bool      // URL -> Liste gemeldet
	send     func(kind notify.Kind, name, reason, msg string)
}

func newMonitor(send func(kind notify.Kind, name, reason, msg string)) *monitor {
	return &monitor{badSince: map[string]time.Time{}, upSent: map[string]bool{}, listSent: map[string]bool{}, send: send}
}

func upName(s upstream.Stats) string {
	if l := protoLabel(s.Proto); l != "" {
		return s.Name + " (" + l + ")"
	}
	return s.Name
}

// check vergleicht den aktuellen Zustand mit dem gemeldeten. upOn/listsOn: Meldungen eingeschaltet.
func (x *monitor) check(now time.Time, ups []upstream.Stats, lists []filter.ListStatus, upOn, listsOn bool) {
	for _, s := range ups {
		bad := s.Requests > 0 && !s.Healthy
		switch {
		case bad && x.badSince[s.URL].IsZero():
			x.badSince[s.URL] = now
		case bad && !x.upSent[s.URL] && now.Sub(x.badSince[s.URL]) >= upstreamGrace:
			x.upSent[s.URL] = true
			if upOn {
				x.send(notify.KindDNS64Down, upName(s), s.LastError, s.URL)
			}
		case !bad:
			if x.upSent[s.URL] && upOn {
				x.send(notify.KindDNS64Up, upName(s), "", s.URL)
			}
			delete(x.badSince, s.URL)
			delete(x.upSent, s.URL)
		}
	}
	for _, l := range lists {
		switch {
		case l.Failures >= listFailures && !x.listSent[l.URL]:
			x.listSent[l.URL] = true
			if listsOn {
				x.send(notify.KindDNS64Lists, l.Name, l.Error, l.URL)
			}
		case l.Failures == 0:
			delete(x.listSent, l.URL)
		}
	}
}

// runMonitor prueft alle 30 s die Upstreams und Blocklisten des laufenden Resolvers.
func (m *Module) runMonitor(ctx context.Context, e *engine) {
	x := newMonitor(func(kind notify.Kind, name, reason, msg string) {
		if m.notifier == nil {
			return
		}
		now := time.Now().UTC()
		m.log.Info("notification", "kind", kind, "name", name, "reason", reason)
		m.notifier(notify.Alert{EventID: "dns64-" + string(kind) + "-" + strconv.FormatInt(now.UnixNano(), 36), Kind: kind, Time: now,
			Check: notify.CheckInfo{Name: name, NotifyDown: true, NotifyUp: true, Local: true}, Reason: reason, Message: msg})
	})
	t := time.NewTicker(monitorEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		m.acmeDue(ctx)
		lists, _ := e.lists.Status()
		x.check(time.Now(), e.up.Stats(), lists, m.core.SettingOr(ctx, setNotifyUpstream, "1") == "1", m.core.SettingOr(ctx, setNotifyLists, "1") == "1")
	}
}
