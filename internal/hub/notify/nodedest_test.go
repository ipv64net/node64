package hubnotify

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

// Forum 5172: derselbe ntfy-Kanal auf zwei Nodes liegt im Portal zweimal (je Node, Geheimnisse jeweils neu
// verschluesselt). Das Ziel muss trotzdem gleich sein, damit der hub nur einen Sendeauftrag gibt.
func TestNodeDestSameTargetAcrossNodes(t *testing.T) {
	box, err := secrets.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{box: box}
	enc := func(token, topic string) string {
		b, _ := json.Marshal(map[string]string{"server": "https://ntfy.example", "topic": topic, "token": box.Encrypt(token), "user": ""})
		return string(b)
	}
	a, b := enc("tk_geheim", "alarm"), enc("tk_geheim", "alarm")
	if a == b {
		t.Fatal("test needs different ciphertexts")
	}
	ka, kb := s.nodeDest(notify.TypeNtfy, "de", a), s.nodeDest(notify.TypeNtfy, "", b) // leere Sprache gilt als "de"
	if ka == "" || ka != kb {
		t.Fatalf("same target on two nodes: %q vs %q", ka, kb)
	}
	if s.nodeDest(notify.TypeNtfy, "de", enc("tk_anders", "alarm")) == ka || s.nodeDest(notify.TypeNtfy, "de", enc("tk_geheim", "x")) == ka {
		t.Fatal("different target, same key")
	}
	if s.nodeDest(notify.TypeNtfy, "de", "") != "" || s.nodeDest(notify.TypeNtfy, "de", "{kaputt") != "" {
		t.Fatal("no or broken configuration must give no key")
	}
	if (&Store{}).nodeDest(notify.TypeNtfy, "de", a) != "" {
		t.Fatal("encrypted secret without key must give no key")
	}
}
