package notify

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// Direkter Versand ueber die ipv64-API: nur fuer Meldungen der Module (Local), nur mit Key; "Weg fehlt"
// markiert den Kanal nicht als gestoert; ohne Verknuepfung kommen die Kanaele aus der Liste des Accounts.
func TestAPISender(t *testing.T) {
	d, st, rec := testDispatcher(t, nil)
	ctx := context.Background()
	srv := &Channel{Type: TypeIPv64Mail, Name: "ipv64-Mail", Config: map[string]string{"email": "a@example.com"}, Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 42}
	if err := st.Insert(ctx, srv); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var sent []int64
	result := error(nil)
	ready := true
	set := func(r bool, e error) { mu.Lock(); ready, result = r, e; mu.Unlock() }
	d.SetAPISender(func(_ context.Context, ch *Channel, m Message) error {
		mu.Lock()
		defer mu.Unlock()
		sent = append(sent, ch.RemoteID)
		return result
	}, func() bool { mu.Lock(); defer mu.Unlock(); return ready })
	n := func() int { mu.Lock(); defer mu.Unlock(); return len(sent) }
	at := func(i int) int64 { mu.Lock(); defer mu.Unlock(); return sent[i] }
	wait := func(want int) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && n() < want {
			time.Sleep(10 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		if n() != want {
			t.Fatalf("api sends: got %d want %d", n(), want)
		}
	}

	// Healthchecks-Alert: Server-Kanal bleibt beim hub
	d.Dispatch(Alert{EventID: "h", Kind: KindDown, Check: CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}})
	time.Sleep(200 * time.Millisecond)
	if n() != 0 || len(rec.list()) != 0 {
		t.Fatalf("check alert must not use the api path: %d %v", n(), rec.list())
	}
	// Modul-Alert: ueber die API an den Server-Kanal
	local := CheckInfo{Name: "IPv4", NotifyDown: true, NotifyUp: true, Local: true}
	d.Dispatch(Alert{EventID: "l1", Kind: KindDynIP, Check: local})
	wait(1)
	if at(0) != 42 {
		t.Fatalf("remote id: %d", at(0))
	}
	// Route fehlt noch auf dem Server: protokolliert, Kanal nicht gestoert
	set(true, errors.Join(ErrUnavailable, errors.New("404")))
	d.Dispatch(Alert{EventID: "l2", Kind: KindDynFail, Check: local})
	wait(2)
	chans, _ := st.Channels(ctx)
	for _, c := range chans {
		if c.ID == srv.ID && c.LastError != "" {
			t.Fatalf("channel must not be marked failing: %q", c.LastError)
		}
	}
	// ohne Key: kein Versand ueber die API
	set(false, nil)
	d.Dispatch(Alert{EventID: "l3", Kind: KindDynIP, Check: local})
	time.Sleep(200 * time.Millisecond)
	if n() != 2 {
		t.Fatal("no api send without key")
	}
	// ohne Verknuepfung: Kanaele des Accounts aus der Liste (kein Platzhalter in der Datenbank)
	set(true, nil)
	_ = st.Delete(ctx, srv.ID)
	d.SetRemoteChannels(func(context.Context) []*Channel {
		return []*Channel{{ID: -7, Type: TypeIPv64SMS, Name: "SMS", Enabled: true, Default: true, NotifyDown: true, NotifyUp: true, Lang: "de", Execution: "server", RemoteID: 7}}
	})
	d.Dispatch(Alert{EventID: "l4", Kind: KindDynLimit, Check: local})
	wait(3)
	if at(2) != 7 {
		t.Fatalf("remote list: %d", at(2))
	}
}
