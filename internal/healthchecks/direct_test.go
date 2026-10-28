package healthchecks

import (
	"context"
	"testing"
)

// Nur Checks, die allein diese Node misst (lokal, eigener Check, keine weiteren Messstellen), meldet die Node selbst
// (notify.CheckInfo.Direct); Online/Hybrid, fremde und Checks mehrerer Nodes bleiben beim hub bzw. der Gruppe.
func TestAlertInfoDirect(t *testing.T) {
	m, _ := newTestModule(t)
	me := "selfnode0000000000000000000000cc"
	if err := m.core.SetSetting(context.Background(), "node.id", me); err != nil {
		t.Fatal(err)
	}
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	for _, tc := range []struct {
		name string
		c    Check
		want bool
	}{
		{"local", Check{Execution: "local", Owner: "self"}, true},
		{"defaults", Check{}, true},
		{"only this node listed", Check{Execution: "local", Owner: "self", Nodes: []string{me}}, true},
		{"several nodes", Check{Execution: "local", Owner: "self", Nodes: []string{me, "other"}}, false},
		{"other node measures", Check{Execution: "local", Owner: "self", Nodes: []string{"other"}}, false},
		{"hybrid", Check{Execution: "both", Owner: "self"}, false},
		{"online", Check{Execution: "online", Owner: "online"}, false},
		{"foreign", Check{Execution: "local", Owner: "other"}, false},
	} {
		c := tc.c
		if got := alertInfo(&c).Direct; got != tc.want {
			t.Errorf("%s: direct %v, want %v", tc.name, got, tc.want)
		}
	}
}
