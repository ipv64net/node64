package healthchecks

import (
	"encoding/json"
	"testing"
)

func TestAPIBulk(t *testing.T) {
	m, srv := newTestModule(t)
	var toks []string
	for _, name := range []string{"a", "b"} {
		code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": name, "type": "icmp", "target": "192.0.2.1", "interval_seconds": 60})
		if code != 201 && code != 200 {
			t.Fatalf("create: %d %s", code, b)
		}
		var c struct{ Token string }
		_ = json.Unmarshal(b, &c)
		toks = append(toks, c.Token)
	}
	var out struct {
		Done   int
		Failed []struct{ Token, Error string }
	}
	code, b := call(t, srv, "POST", "/api/checks/bulk", map[string]any{"action": "pause", "tokens": append(toks, "nichtda0000000000000000000000000")})
	_ = json.Unmarshal(b, &out)
	if code != 200 || out.Done != 2 || len(out.Failed) != 1 {
		t.Fatalf("pause: %d %s", code, b)
	}
	for _, tok := range toks {
		if c, _ := m.st.Check(t.Context(), tok); c == nil || !c.Paused {
			t.Fatalf("%s not paused", tok)
		}
	}
	code, b = call(t, srv, "POST", "/api/checks/bulk", map[string]any{"action": "tag", "tag": "prod", "tokens": toks})
	_ = json.Unmarshal(b, &out)
	if code != 200 || out.Done != 2 {
		t.Fatalf("tag: %d %s", code, b)
	}
	if c, _ := m.st.Check(t.Context(), toks[0]); c == nil || len(c.Tags) != 1 || c.Tags[0] != "prod" {
		t.Fatalf("tag missing: %+v", c)
	}
	if code, _ = call(t, srv, "POST", "/api/checks/bulk", map[string]any{"action": "explode", "tokens": toks}); code != 422 {
		t.Fatalf("unknown action: %d", code)
	}
}
