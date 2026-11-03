package notify

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Ohne Verknuepfung: ein in der Alarmierung gewaehlter ipv64-Kanal des Accounts (ID negativ) wird gesendet, auch wenn
// er kein Standardkanal ist; nicht gewaehlte Account-Kanaele bleiben aussen vor. Verknuepft gilt dieselbe Auswahl fuer
// den Platzhalter mit RemoteID.
func TestAccountChannelSelected(t *testing.T) {
	d, st, _ := testDispatcher(t, nil)
	ctx := context.Background()
	var mu sync.Mutex
	var sent []int64
	d.SetAPISender(func(_ context.Context, ch *Channel, m Message) error {
		mu.Lock()
		sent = append(sent, ch.RemoteID)
		mu.Unlock()
		return nil
	},
		func() bool { return true })
	d.SetLinked(func() bool { return false })
	d.SetRemoteChannels(func(context.Context) []*Channel {
		return []*Channel{
			{ID: -7, Type: TypeIPv64SMS, Name: "SMS", Enabled: true, Default: false, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 7},
			{ID: -8, Type: TypeIPv64Mail, Name: "Mail", Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 8},
		}
	})
	got := func(n int) []int64 {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			mu.Lock()
			l := len(sent)
			mu.Unlock()
			if l >= n {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		defer mu.Unlock()
		return append([]int64(nil), sent...)
	}
	d.Dispatch(Alert{EventID: "a1", Kind: KindDown, Check: CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true, Channels: []int64{-7}}})
	if s := got(1); len(s) != 1 || s[0] != 7 {
		t.Fatalf("gewaehlte SMS: %v", s)
	}
	// Verknuepft: Platzhalter mit RemoteID 7 erfuellt die alte Auswahl -7 (hier ohne hub: lokal zugestellt)
	ph := &Channel{Type: TypeWebhook, Name: "Platzhalter", Config: map[string]string{"url": "http://x/", "method": "POST"}, Enabled: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "node", RemoteID: 7}
	if err := st.Insert(ctx, ph); err != nil {
		t.Fatal(err)
	}
	if out := d.channelsFor(ctx, CheckInfo{Channels: []int64{-7}}); len(out) == 0 || out[0].RemoteID != 7 {
		t.Fatalf("Platzhalter nicht gewaehlt: %+v", out)
	}
}
