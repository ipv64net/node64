package healthchecks

import (
	"encoding/json"
	"strings"
	"testing"
)

// Rolle „Nur lesen“: Passwort, Kopfzeilen, Body und TCP-Send fallen weg, der Rest bleibt.
func TestRedactParams(t *testing.T) {
	p := json.RawMessage(`{"method":"GET","basic_user":"u","basic_password":"geheim","headers":{"Authorization":"Bearer x"}}`)
	out := string(redactParams(p))
	if strings.Contains(out, "geheim") || strings.Contains(out, "Bearer") || !strings.Contains(out, `"basic_user":"u"`) {
		t.Fatalf("redact: %s", out)
	}
	out = string(redactParams(json.RawMessage(`{"method":"POST","body":"{\"pw\":\"geheim\"}"}`)))
	if strings.Contains(out, "geheim") || !strings.Contains(out, `"method":"POST"`) {
		t.Fatalf("body: %s", out)
	}
	out = string(redactParams(json.RawMessage(`{"port":25,"send":"AUTH geheim","expect":"220"}`)))
	if strings.Contains(out, "geheim") || !strings.Contains(out, `"expect":"220"`) {
		t.Fatalf("send: %s", out)
	}
	if got := redactParams(json.RawMessage(`{"method":"GET"}`)); string(got) != `{"method":"GET"}` {
		t.Fatalf("unchanged: %s", got)
	}
	raw := redactCheckRaw(json.RawMessage(`{"token":"t1","params":{"basic_password":"geheim"}}`))
	if strings.Contains(string(raw), "geheim") || !strings.Contains(string(raw), `"token":"t1"`) {
		t.Fatalf("raw: %s", raw)
	}
}
