package monitor64

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Punkt neben "Monitor64" in der Navigation: gruen, gelb (Warnung/Unbekannt), rot (Kritisch/nicht erreichbar);
// pausierte Hosts, Wartung und reine Anzeige-Dienste zaehlen nicht, ohne Hosts kein Punkt.
func TestNavState(t *testing.T) {
	m, _, _ := newTestModule(t)
	set := func(views ...*HostView) {
		m.rtMu.Lock()
		m.rts = map[string]*hostRT{}
		for i, v := range views {
			rt := &hostRT{host: v.Host}
			rt.setView(v)
			m.rts[string(rune('a'+i))] = rt
		}
		m.rtMu.Unlock()
	}
	h := func() *Host { return &Host{Name: "x"} }
	svc := func(st eval.State, show bool) []SvcView { return []SvcView{{Key: "k", State: st, ShowOnly: show}} }
	ok := &HostView{Host: h(), View: eval.ViewOK, Services: svc(eval.OK, false)}
	for _, c := range []struct {
		name  string
		views []*HostView
		want  string
	}{
		{"keine Hosts", nil, ""},
		{"alles ok", []*HostView{ok}, module.NavOK},
		{"Warnung", []*HostView{ok, {Host: h(), Services: svc(eval.Warn, false)}}, module.NavWarn},
		{"Unbekannt", []*HostView{{Host: h(), Services: svc(eval.Unknown, false)}}, module.NavWarn},
		{"Kritisch", []*HostView{{Host: h(), Services: svc(eval.Warn, false)}, {Host: h(), Services: svc(eval.Crit, false)}}, module.NavCrit},
		{"nicht erreichbar", []*HostView{ok, {Host: h(), View: eval.ViewUnreachable}}, module.NavCrit},
		{"nur anzeigen", []*HostView{{Host: h(), Services: svc(eval.Crit, true)}}, module.NavOK},
		{"pausiert", []*HostView{ok, {Host: &Host{Paused: true}, View: eval.ViewUnreachable}}, module.NavOK},
		{"Wartung", []*HostView{ok, {Host: h(), Maint: &eval.Window{End: time.Now().Add(time.Hour)}, Services: svc(eval.Crit, false)}}, module.NavOK},
	} {
		set(c.views...)
		if got := m.NavState(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
