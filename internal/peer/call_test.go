package peer

import (
	"context"
	"errors"
	"testing"
)

// Anfrage eines Moduls an eine andere Node: nur mit angemeldetem Modul und einem Bereich, der auf beiden Seiten an
// ist; die Absenderin kommt beim Handler an, Fehler gehen zurueck.
func TestModuleCall(t *testing.T) {
	ctx := context.Background()
	a, b := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522)
	newProv(a)
	newProv(b)
	pair(t, a, b)
	waitMembers(t, a, "B")
	var gotFrom string
	b.m.RegisterCall("demo", "echo", func(_ context.Context, from string, body []byte) (any, error) {
		gotFrom = from
		if string(body) == `{"fail":true}` {
			return nil, errors.New("nope")
		}
		return map[string]string{"body": string(body)}, nil
	})

	// Bereich aus: nicht beantwortet
	var out map[string]string
	if err := a.m.Call(ctx, "node-b", "demo", "echo", map[string]int{"x": 1}, &out); !errors.Is(err, ErrCallUnavailable) {
		t.Fatalf("area off: %v", err)
	}
	for _, n := range []*testNode{a, b} {
		_, _ = n.m.setSyncLocal(ctx, "demo", "", true)
		_, _ = n.m.setSyncLocal(ctx, "demo", "a", true)
	}
	round2(a, b)
	if err := a.m.Call(ctx, "node-b", "demo", "echo", map[string]int{"x": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if out["body"] != `{"x":1}` || gotFrom != "node-a" {
		t.Fatalf("answer %v from %q", out, gotFrom)
	}
	if err := a.m.Call(ctx, "node-b", "demo", "echo", map[string]bool{"fail": true}, &out); err == nil || err.Error() != "HTTP 400 nope" {
		t.Fatalf("handler error: %v", err)
	}
	// unbekannte Anfrage, unbekanntes Mitglied, ungueltiger Name
	if err := a.m.Call(ctx, "node-b", "demo", "other", nil, nil); !errors.Is(err, ErrCallUnavailable) {
		t.Fatalf("unknown call: %v", err)
	}
	if err := a.m.Call(ctx, "node-x", "demo", "echo", nil, nil); !errors.Is(err, ErrUnknownMember) {
		t.Fatalf("unknown member: %v", err)
	}
	if err := a.m.Call(ctx, "node-b", "demo", "../x", nil, nil); err == nil {
		t.Fatal("invalid name accepted")
	}
}
