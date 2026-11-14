package monitor64

import (
	"encoding/json"
	"strings"
	"testing"
)

// Rolle „Nur lesen“: Push-Token der Zugaenge fehlt in Host-Seite und API, der Rest der Einstellungen bleibt.
func TestRedactTokens(t *testing.T) {
	d := &hostDetail{Accesses: []accessState{
		{accessOut: accessOut{Type: "push", Config: json.RawMessage(`{"token":"geheim","interval":60}`)}},
		{accessOut: accessOut{Type: "ssh", Config: json.RawMessage(`{"user":"root"}`)}},
	}}
	d.redactTokens()
	if c := string(d.Accesses[0].Config); strings.Contains(c, "geheim") || !strings.Contains(c, `"interval":60`) {
		t.Fatalf("push: %s", c)
	}
	if c := string(d.Accesses[1].Config); c != `{"user":"root"}` {
		t.Fatalf("ssh: %s", c)
	}
}
