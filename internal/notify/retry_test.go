package notify

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

// flaky scheitert die ersten fails Male mit err und stellt danach zu.
type flaky struct {
	mu    sync.Mutex
	fails int
	err   error
	calls int
}

func (f *flaky) Send(context.Context, *Channel, Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls <= f.fails {
		return f.err
	}
	return nil
}

func (f *flaky) n() int { f.mu.Lock(); defer f.mu.Unlock(); return f.calls }

// Voruebergehende Fehler werden erneut zugestellt (bis zur Zustellung), endgueltige nicht.
func TestRetryTemporary(t *testing.T) {
	old := retryDelays
	retryDelays = []time.Duration{20 * time.Millisecond, 20 * time.Millisecond, 20 * time.Millisecond}
	t.Cleanup(func() { retryDelays = old })
	run := func(f *flaky) (*Store, *Channel) {
		st := testStore(t)
		bundle, _ := i18n.Load()
		get := func(key, def string) string {
			if key == SetBatchWindow {
				return "0"
			}
			return def
		}
		d := NewDispatcher(st, map[Type]Sender{TypeWebhook: f}, bundle, get, slog.New(slog.NewTextHandler(io.Discard, nil)))
		d.Start(context.Background())
		t.Cleanup(d.Stop)
		ch := addChannel(t, st, "hook", true)
		d.Dispatch(Alert{EventID: "e1", Kind: KindDown, Check: CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}})
		return st, ch
	}
	wait := func(f *flaky, want int) {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && f.n() < want {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(100 * time.Millisecond)
		if got := f.n(); got != want {
			t.Fatalf("attempts: got %d want %d", got, want)
		}
	}
	// zweimal voruebergehend gestoert, dann zugestellt: 3 Versuche, Kanal am Ende ohne Fehler
	f := &flaky{fails: 2, err: Temporary(errors.New("bridge HTTP 504"))}
	st, ch := run(f)
	wait(f, 3)
	chans, _ := st.Channels(context.Background())
	for _, c := range chans {
		if c.ID == ch.ID && c.LastError != "" {
			t.Fatalf("channel still failing after delivery: %q", c.LastError)
		}
	}
	// dauerhaft voruebergehend gestoert: 1 + 3 Versuche, dann Schluss
	f = &flaky{fails: 100, err: Temporary(errors.New("timeout"))}
	run(f)
	wait(f, 4)
	// endgueltiger Fehler: kein neuer Versuch
	f = &flaky{fails: 100, err: errors.New("bridge HTTP 400: bad address")}
	run(f)
	wait(f, 1)
}

// Wird der Kanal zwischen den Versuchen geloescht, abgeschaltet oder geaendert, gibt es keinen Versuch mit dem alten Stand.
func TestRetryReloadsChannel(t *testing.T) {
	old := retryDelays
	retryDelays = []time.Duration{100 * time.Millisecond, 100 * time.Millisecond, 100 * time.Millisecond}
	t.Cleanup(func() { retryDelays = old })
	for _, change := range []string{"delete", "update", "disable"} {
		st := testStore(t)
		bundle, _ := i18n.Load()
		get := func(key, def string) string {
			if key == SetBatchWindow {
				return "0"
			}
			return def
		}
		f := &flaky{fails: 100, err: Temporary(errors.New("timeout"))}
		d := NewDispatcher(st, map[Type]Sender{TypeWebhook: f}, bundle, get, slog.New(slog.NewTextHandler(io.Discard, nil)))
		d.Start(context.Background())
		ch := addChannel(t, st, "hook", true)
		d.Dispatch(Alert{EventID: "e1", Kind: KindDown, Check: CheckInfo{Token: "t", Name: "Web", NotifyDown: true, NotifyUp: true}})
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) && f.n() < 1 {
			time.Sleep(5 * time.Millisecond)
		}
		ctx := context.Background()
		var err error
		switch change {
		case "delete":
			err = st.Delete(ctx, ch.ID)
		case "update":
			ch.Config["url"] = "http://y/"
			err = st.Update(ctx, ch)
		case "disable":
			ch.Enabled = false
			err = st.Update(ctx, ch)
		}
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(400 * time.Millisecond)
		d.Stop()
		if got := f.n(); got != 1 {
			t.Fatalf("%s: attempts %d, want 1", change, got)
		}
	}
}
