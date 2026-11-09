package monitor64

import (
	"encoding/json"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// Token des Push-Betriebs: nur gueltige uebernehmen, sonst behalten bzw. neu; ohne Push keiner.
func TestPushTokenRules(t *testing.T) {
	good, old := transport.NewPushToken(), transport.NewPushToken()
	if pushToken("", good, old, false) != "" {
		t.Fatal("token without push")
	}
	if pushToken("push", good, old, false) != good {
		t.Fatal("valid input token not taken")
	}
	if pushToken("push", "kurz", old, false) != old {
		t.Fatal("old token not kept")
	}
	if tok := pushToken("push", "", "", false); !transport.ValidPushToken(tok) {
		t.Fatal("no new token")
	}
	if tok := pushToken("push", good, old, true); tok == good || tok == old || !transport.ValidPushToken(tok) {
		t.Fatal("renew did not create a new token")
	}
}

func TestPushModeOnlyAgent(t *testing.T) {
	if _, err := cleanAccessConfig("ssh", json.RawMessage(`{"mode":"push"}`)); err == nil {
		t.Fatal("push mode accepted for ssh")
	}
	if _, err := cleanAccessConfig("agent", json.RawMessage(`{"mode":"pull"}`)); err == nil {
		t.Fatal("unknown mode accepted")
	}
	if _, err := cleanAccessConfig("agent", json.RawMessage(`{"token":"abc"}`)); err == nil {
		t.Fatal("token without push accepted")
	}
	if _, err := cleanAccessConfig("agent", json.RawMessage(`{"mode":"push"}`)); err != nil {
		t.Fatal(err)
	}
}
