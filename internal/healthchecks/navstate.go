package healthchecks

import (
	"context"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Punkt neben "Healthchecks" in der Navigation (module.NavStateProvider), wie die Zaehler der Startseite: gestoert
// (auch flatternd und abhaengig gestoert) rot; eingeschraenkt, stabilisierend und seit 3 Intervallen ohne Messung
// gelb; pausiert, noch nie gemessen und im Wartungsfenster zaehlen nicht. Ohne Checks kein Punkt. Die Liste kommt aus
// der Datenbank, deshalb hoechstens alle navStateEvery neu gerechnet (sonst bei jedem Seitenaufbau).

const navStateEvery = 10 * time.Second

type navCache struct {
	mu sync.Mutex
	at time.Time
	v  string
}

// navStates ordnet jedem Modul seinen Zwischenstand zu (wie statusStates, ohne Feld im Modul).
var navStates sync.Map // *Module -> *navCache

// NavState liefert module.NavOK, NavWarn, NavCrit oder "" (keine Checks).
func (m *Module) NavState() string {
	c, _ := navStates.LoadOrStore(m, &navCache{})
	nc := c.(*navCache)
	nc.mu.Lock()
	defer nc.mu.Unlock()
	now := time.Now()
	if !nc.at.IsZero() && now.Sub(nc.at) >= 0 && now.Sub(nc.at) < navStateEvery {
		return nc.v
	}
	nc.at, nc.v = now, m.navState(context.Background(), now)
	return nc.v
}

func (m *Module) navState(ctx context.Context, now time.Time) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	list, err := m.st.Checks(ctx)
	if err != nil || len(list) == 0 {
		return ""
	}
	out := module.NavOK
	for _, c := range list {
		if c.Paused || m.st.InMaintenance(ctx, c.Token, now) {
			continue
		}
		rt := m.liveRuntime(c)
		if rt.State == scheduler.StatePaused || rt.State == scheduler.StatePending {
			continue
		}
		if m.unchecked(c, rt.LastCheck, string(rt.State), now) {
			out = module.NavWarn // unbekannt, ob der Dienst erreichbar ist
			continue
		}
		switch rt.State {
		case scheduler.StateDown, scheduler.StateFlapping, scheduler.StateDependent:
			return module.NavCrit
		case scheduler.StateDegraded, scheduler.StateStabilizing:
			out = module.NavWarn
		}
	}
	return out
}
