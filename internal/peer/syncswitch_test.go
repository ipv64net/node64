package peer

import (
	"context"
	"testing"
)

// switchOn: Schalter "modul" bzw. "modul/bereich" auf einer Node.
func switchOn(t *testing.T, n *testNode, id string) bool {
	t.Helper()
	on, ok := n.m.switchValue(context.Background(), id)
	if !ok {
		t.Fatalf("%s: switch %s unknown", n.m.d.NodeName(), id)
	}
	return on
}

// Schalter gelten fuer den ganzen Cluster: Ein- und Ausschalten auf einer Node erreicht alle, die beitretende Node
// uebernimmt die Schalter des Clusters.
func TestClusterSwitches(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	for _, n := range []*testNode{a, b, c} {
		newProv(n)
	}
	code, _, _ := a.m.StartPairing()
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	for _, m := range a.m.SyncModules(ctx) {
		if m.ID == switchModule {
			t.Fatal("the switches themselves must not be listed")
		}
	}

	// A schaltet ein: B uebernimmt
	if err := a.m.SetSync(ctx, "demo", "", true); err != nil {
		t.Fatal(err)
	}
	if err := a.m.SetSync(ctx, "demo", "a", true); err != nil {
		t.Fatal(err)
	}
	round2(a, b)
	if !switchOn(t, b, "demo") || !switchOn(t, b, "demo/a") || switchOn(t, b, "demo/b") {
		t.Fatal("switches of A must reach B")
	}
	// B schaltet aus: auch das Ausschalten erreicht A (obwohl der Bereich dann aus ist)
	if err := b.m.SetSync(ctx, "demo", "", false); err != nil {
		t.Fatal(err)
	}
	round2(a, b)
	if switchOn(t, a, "demo") || !switchOn(t, a, "demo/a") {
		t.Fatal("switching off on B must reach A")
	}
	// eingebautes Modul: Healthchecks-Bereich
	if err := b.m.SetSync(ctx, "healthchecks", "maintenance", false); err != nil {
		t.Fatal(err)
	}
	round2(a, b)
	if switchOn(t, a, "healthchecks/maintenance") {
		t.Fatal("healthchecks switch must reach A")
	}

	// C hatte vorher andere Schalter und tritt bei B bei: uebernimmt die des Clusters
	_ = c.m.setSyncLocal(ctx, "demo", "", true)
	_ = c.m.setSyncLocal(ctx, "demo", "b", true)
	_ = c.m.SetSync(ctx, "healthchecks", "maintenance", true) // vor dem Beitritt: gilt nicht fuer den Cluster
	code, _, _ = b.m.StartPairing()
	if err := c.m.Join(ctx, b.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")
	round2(a, b, c)
	round2(a, b, c)
	if switchOn(t, c, "demo") || switchOn(t, c, "demo/b") || !switchOn(t, c, "demo/a") || switchOn(t, c, "healthchecks/maintenance") {
		t.Fatal("joining node must adopt the switches of the cluster")
	}
	if switchOn(t, a, "demo") || switchOn(t, a, "healthchecks/maintenance") {
		t.Fatal("the joining node must not change the cluster")
	}
	// danach gilt eine Aenderung auf C fuer alle
	if err := c.m.SetSync(ctx, "demo", "b", true); err != nil {
		t.Fatal(err)
	}
	round2(a, b, c)
	round2(a, b, c)
	if !switchOn(t, a, "demo/b") || !switchOn(t, b, "demo/b") {
		t.Fatal("change on C must reach A and B")
	}
}
