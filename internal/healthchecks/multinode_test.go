package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
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
