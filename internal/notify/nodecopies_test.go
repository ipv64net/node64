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
	ctx := context.Background()
	c.DirectNode = "raspi5"
	down := Alert{Kind: KindDown, Check: c}
	if got := chanNames(d.targetsFor(ctx, down)); !sameNames(got, "ntfy anders", "geheim nur lokal") {
		t.Fatalf("direct node raspi5: %v", got)
	}
	// Review: nutzt die messende Node ihre Kopie fuer diesen Alert nicht (kein Standard bzw. Entwarnung aus), sendet
	// der hub die Kopie der anderen Node - vorher bekam niemand die Meldung
	st.list[0].Default = false
	if got := chanNames(d.targetsFor(ctx, down)); !sameNames(got, "ntfy", "ntfy anders", "geheim nur lokal") || d.targetsFor(ctx, down)[0].NodeID != "raspi4" {
		t.Fatalf("own copy not chosen: %v", got)
	}
	st.list[0].Default, st.list[0].NotifyUp = true, false
	if got := chanNames(d.targetsFor(ctx, Alert{Kind: KindUp, Check: c})); !sameNames(got, "ntfy", "ntfy anders", "geheim nur lokal") {
		t.Fatalf("own copy without recovery: %v", got)
	}
	st.list[0].NotifyUp = true
}

// Review: Bei gleichem Ziel gewinnt ein erreichbarer Sender; sonst hing die Meldung als Sendeauftrag an einer Node,
// die gerade weg ist (Auftraege verfallen nach 1 h), und die Kopie der erreichbaren Node war verworfen.
func TestTargetsPreferReachable(t *testing.T) {
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	key := DestKeyOf(TypeNtfy, "de", map[string]string{"server": "https://ntfy.example", "topic": "alarm"})
	ch := func(id int64, node string) *Channel {
		return &Channel{ID: id, Type: TypeNtfy, Name: "ntfy", Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de",
			Execution: "node", NodeID: node, DestKey: key}
	}
	st := &reachChannels{fakeChannels: fakeChannels{list: []*Channel{ch(1, "weg"), ch(2, "da")}}, online: map[string]bool{"da": true}}
	d := NewMultiDispatcher(st, nil, bundle, func(int64) Settings { return func(_, def string) string { return def } }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.SetSendServerChannels(true)
	got := d.targetsFor(context.Background(), Alert{Kind: KindDown, Check: CheckInfo{UserID: 7, NotifyDown: true, NotifyUp: true}})
	if len(got) != 1 || got[0].NodeID != "da" {
		t.Fatalf("targets: %+v", got)
	}
	st.online["weg"] = true // beide erreichbar: der erste bleibt
	if got := d.targetsFor(context.Background(), Alert{Kind: KindDown, Check: CheckInfo{UserID: 7, NotifyDown: true, NotifyUp: true}}); len(got) != 1 || got[0].NodeID != "weg" {
		t.Fatalf("both online: %+v", got)
	}
}

type reachChannels struct {
	fakeChannels
	online map[string]bool
}

func (r *reachChannels) ChannelReachable(_ context.Context, ch *Channel) bool {
	return r.online[ch.NodeID]
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
