package notify

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

// Forum 5172: Zwei verknuepfte Nodes eines Clusters haben denselben ntfy-Kanal (Kopie ueber den Cluster oder auf
// beiden gleich angelegt). Beim hub sind das zwei Node-Kanaele (je Node einer); er gab fuer eine Stoerung beiden
// einen Sendeauftrag, und jede Node schickte dieselbe Meldung an dasselbe Topic - sie kam doppelt an. Gleiches Ziel
// (DestKey) bekommt eine Meldung nur einmal; ein anderes Ziel und Kanaele ohne bekanntes Ziel bleiben, wie sie sind.
func TestHubSendsNodeCopiesOnce(t *testing.T) {
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	ntfy := map[string]string{"server": "https://ntfy.example", "topic": "alarm", "priority_down": "4", "priority_up": "3"}
	same := DestKeyOf(TypeNtfy, "de", ntfy)
	other := DestKeyOf(TypeNtfy, "de", map[string]string{"server": "https://ntfy.example", "topic": "anderes"})
	ch := func(id int64, name, node, key string) *Channel {
		return &Channel{ID: id, Type: TypeNtfy, Name: name, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de",
			Execution: "node", NodeID: node, DestKey: key}
	}
	st := fakeChannels{list: []*Channel{
		ch(1, "ntfy", "raspi5", same), ch(2, "ntfy", "raspi4", same), // dieselbe Stelle auf beiden Nodes
		ch(3, "ntfy anders", "raspi4", other),
		ch(4, "geheim nur lokal", "raspi4", ""), ch(5, "geheim nur lokal", "raspi5", ""), // Ziel unbekannt: beide
	}}
	rec := &recorder{}
	settings := func(key, def string) string {
		if key == SetBatchWindow {
			return "0"
		}
		return def
	}
	d := NewMultiDispatcher(st, map[Type]Sender{TypeNtfy: rec}, bundle, func(int64) Settings { return settings }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.SetSendServerChannels(true) // wie im hub
	d.Start(context.Background())
	defer d.Stop()

	c := CheckInfo{UserID: 7, Token: "t", Name: "Gotify", NotifyDown: true, NotifyUp: true}
	d.Dispatch(Alert{EventID: "e1", Kind: KindDown, Check: c})
	waitMsgs(t, rec, 4)
	time.Sleep(150 * time.Millisecond)
	if got := rec.list(); len(got) != 4 {
		t.Fatalf("down: sends to %v, want 4 (ntfy once, ntfy anders, 2x unknown target)", targets(got))
	}
	if got := rec.list(); got[0].Check.Target != "ntfy" {
		t.Fatalf("first send %q", got[0].Check.Target)
	}

	// Kopie mit abgeschalteter Entwarnung: die andere Kopie meldet sie (Auswahl erst nach den Schaltern)
	st.list[0].NotifyUp = false
	d.Dispatch(Alert{EventID: "e2", Kind: KindUp, Check: c})
	waitMsgs(t, rec, 8)
	time.Sleep(150 * time.Millisecond)
	if got := rec.list(); len(got) != 8 {
		t.Fatalf("up: sends to %v, want 8 in total", targets(got))
	}
	st.list[0].NotifyUp = true

	// Direct: die messende Node sendet ihre Kopie selbst, der hub laesst auch die Kopie der anderen Node aus
	c.DirectNode = "raspi5"
	if got := chanNames(d.channelsFor(context.Background(), c)); !sameNames(got, "ntfy anders", "geheim nur lokal") {
		t.Fatalf("direct node raspi5: %v", got)
	}
}

func targets(list []Message) []string {
	out := make([]string, 0, len(list))
	for _, m := range list {
		out = append(out, m.Check.Target)
	}
	return out
}

func TestDestKeyOf(t *testing.T) {
	a := DestKeyOf(TypeNtfy, "de", map[string]string{"server": "https://n", "topic": "x", "token": ""})
	if a == "" || a != DestKeyOf(TypeNtfy, "de", map[string]string{"topic": "x", "server": "https://n"}) {
		t.Fatal("same target, different order or empty value: different key")
	}
	for name, b := range map[string]string{
		"topic": DestKeyOf(TypeNtfy, "de", map[string]string{"server": "https://n", "topic": "y"}),
		"lang":  DestKeyOf(TypeNtfy, "en", map[string]string{"server": "https://n", "topic": "x"}),
		"type":  DestKeyOf(TypeGotify, "de", map[string]string{"server": "https://n", "topic": "x"}),
	} {
		if b == a {
			t.Errorf("%s differs but key is the same", name)
		}
	}
	if DestKeyOf(TypeNtfy, "de", map[string]string{"token": " "}) != "" || DestKeyOf(TypeBrowser, "de", nil) != "" {
		t.Error("no configuration: key must be empty")
	}
}
