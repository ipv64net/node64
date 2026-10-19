package healthchecks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/wire"
)

// Der Testlauf prueft die Eingabe wie beim Speichern und gibt die Definition mit den Standorten an ipv64.
func TestOnlineTestFlow(t *testing.T) {
	m, srv := newTestModule(t)
	code, b := call(t, srv, "POST", "/api/checks/online-test", map[string]any{"name": "x", "type": "http", "target": "https://example.org"})
	if code != 422 || !strings.Contains(string(b), "ipv64 link") {
		t.Fatalf("standalone: %d %s", code, b)
	}
	m.SetLinked(func() bool { return true })
	var got wire.Check
	var gotLocs []string
	m.SetOnlineTest(func(_ context.Context, def wire.Check, locs []string) (*OnlineTest, error) {
		got, gotLocs = def, locs
		return &OnlineTest{Status: "ok", Results: []OnlineTestRow{{Location: "nbg", OK: true, Message: "ipv4 up 12.0 ms"}}}, nil
	})
	code, b = call(t, srv, "POST", "/api/checks/online-test", map[string]any{"name": "x", "type": "json", "target": "https://example.org/api",
		"params": map[string]any{"json_rules": []map[string]string{{"path": "status", "op": "eq", "value": "ok"}}}, "locations": []string{"nbg"}})
	var res OnlineTest
	if code != 200 || json.Unmarshal(b, &res) != nil || res.Status != "ok" || len(res.Results) != 1 {
		t.Fatalf("test: %d %s", code, b)
	}
	if got.Type != "json" || got.Target != "https://example.org/api" || len(gotLocs) != 1 || gotLocs[0] != "nbg" {
		t.Fatalf("definition: %+v %v", got, gotLocs)
	}
	// ungueltige Eingabe kommt gar nicht erst zu ipv64
	if code, b = call(t, srv, "POST", "/api/checks/online-test", map[string]any{"name": "x", "type": "json", "target": "https://example.org"}); code != 422 {
		t.Fatalf("invalid: %d %s", code, b)
	}
}
