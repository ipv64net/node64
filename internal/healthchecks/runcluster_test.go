package healthchecks

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// "Jetzt pruefen" ohne ipv64 (GitHub #271): misst eine andere Node des Clusters den Check, geht die Bitte ueber den
// Cluster an sie; die messende Node misst sofort, eine andere lehnt ab.
func TestRunNowViaCluster(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	me, other := "selfnode0000000000000000000000dd", "othernode000000000000000000000ee"
	if err := m.core.SetSetting(ctx, "node.id", me); err != nil {
		t.Fatal(err)
	}
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	m.SetLinked(func() bool { return true }) // zum Anlegen mit Liste der messenden Nodes
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "andere", "type": "icmp", "target": "10.0.0.2", "execution": "local", "nodes": []string{other}})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	list, _ := m.st.Checks(ctx)
	if len(list) != 1 || list[0].MeasuredHere() {
		t.Fatalf("checks: %+v", list)
	}
	c := list[0]
	m.SetLinked(func() bool { return false }) // ohne ipv64
	m.SetRunRemote(func(string) bool { t.Error("hub asked without link"); return false })

	if err := m.runNow(ctx, c); err == nil {
		t.Fatal("without cluster: error expected")
	}
	var mu sync.Mutex
	var asked []string
	fail := false
	m.cluster.RunNow = func(_ context.Context, node, token string) error {
		mu.Lock()
		defer mu.Unlock()
		asked = append(asked, node+"/"+token)
		if fail {
			return errors.New("unreachable")
		}
		return nil
	}
	if err := m.runNow(ctx, c); err != nil {
		t.Fatalf("via cluster: %v", err)
	}
	if len(asked) != 1 || asked[0] != other+"/"+c.Token {
		t.Fatalf("asked: %v", asked)
	}
	fail = true
	if err := m.runNow(ctx, c); err == nil {
		t.Fatal("cluster node unreachable: error expected")
	}

	// Empfaengerseite: diese Node misst den Check nicht -> Ablehnung; misst sie ihn, laeuft er sofort
	if err := m.HandleClusterRun(ctx, []byte(`{"token":"`+c.Token+`"}`)); err == nil {
		t.Fatal("check measured elsewhere must be refused")
	}
	if err := m.HandleClusterRun(ctx, []byte(`{}`)); err == nil {
		t.Fatal("missing token must be refused")
	}
	m.SetLinked(func() bool { return true })
	code, b = call(t, srv, "POST", "/api/checks", map[string]any{"name": "hier", "type": "icmp", "target": "10.0.0.3", "execution": "local", "nodes": []string{me}})
	if code != 201 {
		t.Fatalf("create: %d %s", code, b)
	}
	list, _ = m.st.Checks(ctx)
	var here *Check
	for _, x := range list {
		if x.MeasuredHere() {
			here = x
		}
	}
	if here == nil {
		t.Fatal("no check measured here")
	}
	if err := m.HandleClusterRun(ctx, []byte(`{"token":"`+here.Token+`"}`)); err != nil {
		t.Fatalf("run here: %v", err)
	}
}
