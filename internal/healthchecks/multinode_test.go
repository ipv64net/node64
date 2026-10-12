package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestMultiNodeMeasuredHere(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	me, other := "selfnode0000000000000000000000aa", "othernode000000000000000000000bb"
	if err := m.core.SetSetting(ctx, "node.id", me); err != nil {
		t.Fatal(err)
	}
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	m.SetLinked(func() bool { return true })

	create := func(body map[string]any) string {
		code, b := call(t, srv, "POST", "/api/checks", body)
		if code != 201 && code != 200 {
			t.Fatalf("create: %d %s", code, b)
		}
		var c struct {
			Token string
			Nodes []string
		}
		_ = json.Unmarshal(b, &c)
		return c.Token
	}
	both := create(map[string]any{"name": "beide", "type": "icmp", "target": "10.0.0.1", "execution": "local", "nodes": []string{me, other}})
	if _, ok := m.scheduler().Runtime(both); !ok {
		t.Fatal("check with this node in the list must be scheduled")
	}
	onlyOther := create(map[string]any{"name": "andere", "type": "icmp", "target": "10.0.0.2", "execution": "local", "nodes": []string{other}})
	if _, ok := m.scheduler().Runtime(onlyOther); ok {
		t.Fatal("check measured only by another node must not be scheduled here")
	}
	c, _ := m.st.Check(ctx, onlyOther)
	if c == nil || c.Foreign() || len(c.Nodes) != 1 {
		t.Fatalf("owner stays this node, nodes kept: %+v", c)
	}
	dock := create(map[string]any{"name": "dock", "type": "docker", "target": "x", "execution": "local", "nodes": []string{me, other}})
	if d, _ := m.st.Check(ctx, dock); d == nil || len(d.Nodes) != 0 {
		t.Fatalf("docker belongs to exactly one node: %+v", d)
	}
	if w := m.WireCheck(c, nil); len(w.Nodes) != 1 || w.Nodes[0] != other {
		t.Fatalf("wire nodes: %+v", w.Nodes)
	}
}

// Historie fremder Messstellen bleibt im Diagramm, wenn diese Node spaeter mitmisst.
func TestChartKeepsRemoteHistory(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	me := "selfnode0000000000000000000000cc"
	_ = m.core.SetSetting(ctx, "node.id", me)
	self.Lock()
	self.id = ""
	self.Unlock()
	t.Cleanup(func() { self.Lock(); self.id = ""; self.Unlock() })
	m.SetLinked(func() bool { return true })
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "q9", "type": "icmp", "target": "9.9.9.9", "execution": "online", "interval_seconds": 60})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var cj struct{ Token string }
	_ = json.Unmarshal(b, &cj)
	t0 := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	m.ApplyRemoteState(ctx, RemoteState{Token: cj.Token, State: "up", Since: t0, Time: t0, Status: "up", LatencyMS: 10, Source: "loc:fsn", SourceState: "up"})
	// jetzt misst diese Node mit (hybrid)
	c, _ := m.st.Check(ctx, cj.Token)
	c.Execution, c.Nodes = "both", []string{me}
	if err := m.st.Update(ctx, c); err != nil {
		t.Fatal(err)
	}
	t1 := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	m.ApplyRemoteState(ctx, RemoteState{Token: cj.Token, State: "up", Since: t0, Time: t1, Status: "up", LatencyMS: 12, Source: "loc:fsn", SourceState: "up"})
	code, b = call(t, srv, "GET", "/api/checks/"+cj.Token+"/chart?range=24h", nil)
	if code != 200 {
		t.Fatalf("chart: %d %s", code, b)
	}
	var out struct {
		Series []struct {
			Source string
			Points []json.RawMessage
		}
	}
	_ = json.Unmarshal(b, &out)
	for _, s := range out.Series {
		if s.Source == "loc:fsn" {
			if len(s.Points) != 2 {
				t.Fatalf("loc:fsn points: %d (old history lost?)", len(s.Points))
			}
			return
		}
	}
	t.Fatalf("no loc:fsn series: %s", b)
}
