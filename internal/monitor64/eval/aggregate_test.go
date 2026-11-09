package eval

import (
	"slices"
	"testing"
)

func ms(name string, s State, notify bool) MetricStatus {
	return MetricStatus{Name: name, Status: Status{State: s}, Notify: notify}
}

func TestServiceState(t *testing.T) {
	cases := []struct {
		name        string
		in          []MetricStatus
		state       State
		cause       int
		notify      State
		notifyCause int
		showOnly    bool
	}{
		{"leer", nil, OK, -1, OK, -1, true},
		{"alles OK", []MetricStatus{ms("in", OK, true), ms("out", OK, true)}, OK, -1, OK, -1, false},
		{"schlimmste gewinnt", []MetricStatus{ms("in", Warn, true), ms("errrate", Crit, true), ms("out", Warn, true)}, Crit, 1, Crit, 1, false},
		{"Gleichstand: erste", []MetricStatus{ms("a", Warn, true), ms("b", Warn, true)}, Warn, 0, Warn, 0, false},
		{"Unbekannt vor Warnung", []MetricStatus{ms("a", Warn, true), ms("b", Unknown, true)}, Unknown, 1, Unknown, 1, false},
		{"nur anzeigen zaehlt nicht fuer Meldung", []MetricStatus{ms("temp", Crit, false), ms("wear", Warn, true)}, Crit, 0, Warn, 1, false},
		{"alles nur anzeigen", []MetricStatus{ms("temp", Crit, false)}, Crit, 0, OK, -1, true},
	}
	for _, c := range cases {
		r := ServiceState(c.in)
		if r.State != c.state || r.Cause != c.cause || r.Notify != c.notify || r.NotifyCause != c.notifyCause || r.ShowOnly != c.showOnly {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

func TestHostState(t *testing.T) {
	acc := func(fails ...int) []Access {
		names := []string{"Agent", "SSH", "API"}
		var out []Access
		for i, f := range fails {
			out = append(out, Access{Name: names[i], Failures: f})
		}
		return out
	}
	cases := []struct {
		name   string
		in     HostInput
		view   HostView
		state  State
		unr    bool
		failed []string
	}{
		{"alles gut", HostInput{Accesses: acc(0, 0), Services: []State{OK, Warn}}, ViewWarn, Warn, false, nil},
		{"ohne Zugang erreichbar", HostInput{Services: []State{Crit}}, ViewCrit, Crit, false, nil},
		{"ein Zugang eine Runde aus", HostInput{Accesses: acc(1, 0), Services: []State{OK}}, ViewOK, OK, false, nil},
		{"ein Zugang zwei Runden aus", HostInput{Accesses: acc(2, 0), Services: []State{OK}}, ViewWarn, Warn, false, []string{"Agent"}},
		{"Zugang aus, Dienst kritisch", HostInput{Accesses: acc(0, 5), Services: []State{Crit}}, ViewCrit, Crit, false, []string{"SSH"}},
		{"alle eine Runde aus", HostInput{Accesses: acc(1, 1), Services: []State{OK}}, ViewOK, OK, false, nil},
		{"alle zwei Runden aus", HostInput{Accesses: acc(2, 3), Services: []State{Unknown}}, ViewUnreachable, Crit, true, nil},
		{"einziger Zugang aus", HostInput{Accesses: acc(2)}, ViewUnreachable, Crit, true, nil},
		{"Wartung geht vor", HostInput{Maintenance: true, Accesses: acc(2, 2)}, ViewMaintenance, Crit, true, nil},
		{"Wartung mit Problemen", HostInput{Maintenance: true, Accesses: acc(0), Services: []State{Crit}}, ViewMaintenance, Crit, false, nil},
		{"Unbekannt", HostInput{Accesses: acc(0), Services: []State{Unknown, Warn}}, ViewUnknown, Unknown, false, nil},
	}
	for _, c := range cases {
		r := HostState(c.in)
		if r.View != c.view || r.State != c.state || r.Unreachable != c.unr || !slices.Equal(r.FailedAccess, c.failed) {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
	if AccessServiceKey("SSH") != "access:ssh" {
		t.Fatal("AccessServiceKey")
	}
}
