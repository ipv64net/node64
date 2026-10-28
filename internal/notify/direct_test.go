package notify

import (
	"context"
	"io"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

func chanNames(list []*Channel) []string {
	out := make([]string, 0, len(list))
	for _, ch := range list {
		out = append(out, ch.Name)
	}
	sort.Strings(out)
	return out
}

func sameNames(a []string, b ...string) bool {
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Node: Checks, die nur diese Node misst (Direct), sendet sie selbst – ipv64-Kanaele ueber die API und eigene
// Kanaele; andere Portal-Kanaele bleiben beim hub. Nur wenn der hub es kann (SetHubDirect) und ein API-Key da ist.
func TestDirectChannelSelection(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	ctx := context.Background()
	addChannel(t, st, "own", true) // eigener Kanal der Node (Execution node)
	for _, c := range []*Channel{
		{Type: TypeIPv64Mail, Name: "ipv64-mail", Config: map[string]string{"email": "a@example.com"}, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 42},
		{Type: TypeWebhook, Name: "portal-hook", Config: map[string]string{"url": "http://x/", "method": "POST"}, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 3},
	} {
		if err := st.Insert(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	var hubSends, hubDirect, ready atomic.Bool
	hubSends.Store(true)
	ready.Store(true)
	var mu sync.Mutex
	var api []int64
	d.SetServerSends(hubSends.Load)
	d.SetHubDirect(hubDirect.Load)
	d.SetLinked(func() bool { return true })
	d.SetAPISender(func(_ context.Context, ch *Channel, _ Message) error {
		mu.Lock()
		api = append(api, ch.RemoteID)
		mu.Unlock()
		return nil
	}, ready.Load)

	plain := CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}
	direct := plain
	direct.Direct = true
	for _, tc := range []struct {
		name                  string
		c                     CheckInfo
		sends, hubDir, apiRdy bool
		want                  []string
	}{
		{"not direct: hub sends all", plain, true, true, true, nil},
		{"hub without feature", direct, true, false, true, nil},
		{"direct", direct, true, true, true, []string{"own", "ipv64-mail"}},
		{"direct without api key", direct, true, true, false, nil},
		{"direct, hub not connected", direct, false, true, true, []string{"own", "ipv64-mail"}},
		{"not direct, hub not connected", plain, false, true, true, []string{"own"}},
	} {
		hubSends.Store(tc.sends)
		hubDirect.Store(tc.hubDir)
		ready.Store(tc.apiRdy)
		if got := chanNames(d.channelsFor(ctx, tc.c)); !sameNames(got, tc.want...) {
			t.Errorf("%s: channels %v, want %v", tc.name, got, tc.want)
		}
	}
	// Modul-Meldungen (Local) bleiben wie bisher: auch Portal-Kanaele, die die Node pruefen kann
	local := direct
	local.Local = true
	hubSends.Store(true)
	hubDirect.Store(true)
	ready.Store(true)
	if got := chanNames(d.channelsFor(ctx, local)); !sameNames(got, "own", "ipv64-mail", "portal-hook") {
		t.Errorf("local: %v", got)
	}
	// die Node sendet auf Wunsch alles selbst (Einstellung): Direct aendert daran nichts
	d.SetSendServerChannels(true)
	if got := chanNames(d.channelsFor(ctx, direct)); !sameNames(got, "own", "ipv64-mail", "portal-hook") {
		t.Errorf("send server channels: %v", got)
	}
	d.SetSendServerChannels(false)

	// Ende zu Ende: ipv64-Mail ueber die API, eigener Kanal ueber den Sender, Portal-Webhook gar nicht
	d.Dispatch(Alert{EventID: "e1", Kind: KindDown, Check: direct})
	waitMsgs(t, rec, 1)
	time.Sleep(100 * time.Millisecond)
	if got := rec.list(); len(got) != 1 || got[0].Check.Target != "own" {
		t.Fatalf("local sends: %+v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(api) != 1 || api[0] != 42 {
		t.Fatalf("api sends: %v", api)
	}
}

// fakeChannels ist ein ChannelStore mit fester Kanalliste (hub).
type fakeChannels struct{ list []*Channel }

func (f fakeChannels) ChannelsFor(context.Context, int64) ([]*Channel, error) { return f.list, nil }
func (f fakeChannels) AddDelivery(context.Context, Delivery) error            { return nil }
func (f fakeChannels) Touch(context.Context, int64, string) error             { return nil }

// hub: bei einem Direct-Alert laesst er die ipv64-Kanaele und die Kanaele der messenden Node aus und sendet nur die
// uebrigen Portal-Kanaele und Kanaele anderer Nodes; ohne DirectNode alles wie bisher.
func TestHubSkipsDirectNodeChannels(t *testing.T) {
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	ch := func(id int64, typ Type, name, exec, node string) *Channel {
		return &Channel{ID: id, Type: typ, Name: name, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: exec, NodeID: node}
	}
	st := fakeChannels{list: []*Channel{
		ch(1, TypeIPv64Mail, "mail", "server", ""), ch(2, TypeIPv64SMS, "sms", "server", ""), ch(3, TypeApp, "app", "server", ""),
		ch(4, TypeWebhook, "hook", "server", ""), ch(5, TypeTelegram, "telegram", "server", ""),
		ch(6, TypeWebhook, "node-a", "node", "a"), ch(7, TypeBrowser, "node-b", "node", "b"),
	}}
	d := NewMultiDispatcher(st, map[Type]Sender{}, bundle, func(int64) Settings { return nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	d.SetSendServerChannels(true) // wie im hub
	ctx := context.Background()
	c := CheckInfo{UserID: 7, Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}
	if got := chanNames(d.channelsFor(ctx, c)); len(got) != 7 {
		t.Fatalf("without direct node: %v", got)
	}
	c.DirectNode = "a"
	if got := chanNames(d.channelsFor(ctx, c)); !sameNames(got, "hook", "telegram", "node-b") {
		t.Fatalf("direct node a: %v", got)
	}
}
