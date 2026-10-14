package healthchecks

import "testing"

// Anzeige "wo wird gemessen": richtet sich nach Ausfuehrungsort und messenden Nodes, nicht nach dem Besitz.
func TestWhere(t *testing.T) {
	self.Lock()
	old := self.id
	self.id = "me"
	self.Unlock()
	defer func() { self.Lock(); self.id = old; self.Unlock() }()
	cases := []struct {
		c    Check
		want string
	}{
		{Check{Execution: "online", Owner: "online"}, "hc.where.online"},
		{Check{Execution: "both", Owner: "other", Nodes: []string{"pi"}}, "hc.where.hybrid"},       // andere Node + ipv64
		{Check{Execution: "both", Owner: "other", Nodes: []string{"pi", "me"}}, "hc.where.hybrid"}, // misst mit
		{Check{Execution: "local", Owner: "other", Nodes: []string{"me"}}, "hc.where.local"},       // Besitz woanders, misst hier
		{Check{Execution: "local", Owner: "other", Nodes: []string{"pi"}}, "hc.where.other"},       // nur andere Node
		{Check{Execution: "local", Owner: "self"}, "hc.where.local"},                               // standalone
	}
	for i, tc := range cases {
		if got := tc.c.Where().Key; got != tc.want {
			t.Errorf("case %d: %s, want %s", i, got, tc.want)
		}
	}
	if w := (&Check{Execution: "both", Owner: "other", Nodes: []string{"pi"}}).Where(); w.Hint != "hc.where.hybrid_other" {
		t.Errorf("hybrid on another node: hint %s", w.Hint)
	}
}
