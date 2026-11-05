package peer

import (
	"context"
	"testing"
	"time"
)

func init() { switchPullEvery = 0 } // Tests holen jede Runde ab

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

	// B hat (aus der Zeit vor dem Update) einen eigenen Schalter: der Beitritt von C ueber B aendert A nicht
	_, _ = b.m.setSyncLocal(ctx, "demo", "b", true)
	// C hatte vorher andere Schalter und tritt bei B bei: uebernimmt die von B
	_, _ = c.m.setSyncLocal(ctx, "demo", "", true)
	_, _ = c.m.setSyncLocal(ctx, "demo", "b", true)
	_ = c.m.SetSync(ctx, "healthchecks", "maintenance", true) // vor dem Beitritt: gilt nicht fuer den Cluster
	code, _, _ = b.m.StartPairing()
	if err := c.m.Join(ctx, b.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B", "C")
	round2(a, b, c)
	round2(a, b, c)
	if switchOn(t, c, "demo") || !switchOn(t, c, "demo/b") || !switchOn(t, c, "demo/a") || switchOn(t, c, "healthchecks/maintenance") {
		t.Fatal("joining node must adopt the switches of the accepting node")
	}
	if switchOn(t, a, "demo") || switchOn(t, a, "demo/b") || switchOn(t, a, "healthchecks/maintenance") {
		t.Fatal("the join must not change the other members")
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

	// C verlaesst den Cluster, schaltet allein aus und tritt wieder bei: uebernimmt den Stand des Clusters, auch wenn
	// der Eintrag dort von C selbst stammt
	if err := c.m.Leave(ctx); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	_, _ = c.m.setSyncLocal(ctx, "demo", "b", false)
	code, _, _ = a.m.StartPairing()
	if err := c.m.Join(ctx, a.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	round2(a, b, c)
	if !switchOn(t, c, "demo/b") {
		t.Fatal("re-joining node must adopt the switches of the cluster")
	}
}

// Ein Mitglied ohne das Modul reicht dessen Schalter weiter (nicht als geloescht).
func TestClusterSwitchUnknownModule(t *testing.T) {
	ctx := context.Background()
	a := newNode(t, "node-a", "A", 522)
	newProv(a)
	if _, err := a.m.setSyncLocal(ctx, "neu", "x", true); err != nil { // Modul "neu" gibt es hier nicht
		t.Fatal(err)
	}
	data, found, err := switchProvider{a.m}.ClusterGet(ctx, switchItem, "neu/x")
	if err != nil || !found || string(data) != `{"on":true}` {
		t.Fatalf("unknown module: %s %v %v", data, found, err)
	}
	// Uebernahme ohne Aenderung: kein Eintrag im Audit
	changed, _ := a.m.setSyncLocal(ctx, "neu", "x", true)
	if changed {
		t.Fatal("unchanged switch reported as changed")
	}
}

// Ein Anstoss, der auf ein laufendes Abholen des einen Wegs trifft, stoesst nach dem anderen Weg nicht an.
func TestPullAgainPerWay(t *testing.T) {
	a := newNode(t, "node-a", "A", 522)
	a.m.pullAgainLater("v2", "node-b")
	a.m.pullAgainNow("v1", "node-b")
	select {
	case id := <-a.m.pull.kick:
		t.Fatalf("v1 must not consume the v2 mark (kick %q)", id)
	case <-time.After(20 * time.Millisecond):
	}
	a.m.pullAgainNow("v2", "node-b")
	select {
	case <-a.m.pull.kick:
	default:
		t.Fatal("v2 must kick again")
	}
}
