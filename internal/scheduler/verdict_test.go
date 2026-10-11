package scheduler

import (
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

func TestOverall(t *testing.T) {
	src := func(st State, fresh bool) SourceState {
		ls := checks.Up
		if st == StateDown {
			ls = checks.Down
		}
		return SourceState{State: st, LastStatus: ls, Fresh: fresh}
	}
	cases := []struct {
		name   string
		policy string
		in     []SourceState
		want   State
	}{
		{"single up", "all", []SourceState{src(StateUp, true)}, StateUp},
		{"single down", "all", []SourceState{src(StateDown, true)}, StateDown},
		{"all: one of three down -> degraded", "all", []SourceState{src(StateDown, true), src(StateUp, true), src(StateUp, true)}, StateDegraded},
		{"all: all down", "all", []SourceState{src(StateDown, true), src(StateDown, true), src(StateDown, true)}, StateDown},
		{"any: one down -> down", "any", []SourceState{src(StateDown, true), src(StateUp, true)}, StateDown},
		{"majority: 1 of 3", "majority", []SourceState{src(StateDown, true), src(StateUp, true), src(StateUp, true)}, StateDegraded},
		{"majority: 2 of 3", "majority", []SourceState{src(StateDown, true), src(StateDown, true), src(StateUp, true)}, StateDown},
		{"majority: 1 of 2 is not majority", "majority", []SourceState{src(StateDown, true), src(StateUp, true)}, StateDegraded},
		{"offline node ignored", "all", []SourceState{src(StateDown, false), src(StateUp, true)}, StateUp},
		{"all without data -> pending", "all", []SourceState{src(StateDown, false), src(StatePending, true)}, StatePending},
		{"paused ignored, remaining down", "all", []SourceState{src(StatePaused, true), src(StateDown, true)}, StateDown},
		{"stabilizing counts as up", "all", []SourceState{src(StateStabilizing, true), src(StateDown, true)}, StateDegraded},
		{"flapping down decides", "all", []SourceState{{State: StateFlapping, LastStatus: checks.Down, Fresh: true}}, StateFlapping},
		{"unknown policy behaves like all", "", []SourceState{src(StateDown, true), src(StateUp, true)}, StateDegraded},
	}
	for _, c := range cases {
		if got := Overall(c.policy, c.in); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}
