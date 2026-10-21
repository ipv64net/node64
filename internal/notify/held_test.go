package notify

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

// Ruhezeit ist Ruhezeit: zurueckgehaltene Meldungen (Proxmox VE merkt sich „verschickt“) ueberstehen einen Neustart
// in der Ruhezeit und kommen danach als Sammelmeldung; danach ist der Speicher leer.
func TestHeldSurvivesRestart(t *testing.T) {
	settings := map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7",
		SetQuietTZ: "UTC", SetBaseURL: "https://node.example", SetBatchWindow: "0"}
	get := func(key, def string) string {
		if v, ok := settings[key]; ok {
			return v
		}
		return def
	}
	st := testStore(t)
	addChannel(t, st, "default", true)
	bundle, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	clk := &testClock{t: time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC)}
	start := func(rec *recorder) *Dispatcher {
		d := NewDispatcher(st, map[Type]Sender{TypeWebhook: rec}, bundle, get, slog.New(slog.NewTextHandler(io.Discard, nil)))
		d.now = clk.now
		d.Start(context.Background())
		return d
	}
	ctx := context.Background()
	heldCount := func(want int) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for {
			m, err := st.LoadHeld(ctx)
			if err == nil && len(m[0]) == want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("held: %+v %v, want %d", m, err, want)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	rec1 := &recorder{}
	d1 := start(rec1)
	app := CheckInfo{Name: "lab – app", Type: "proxmox", Target: "qemu/102", NotifyDown: true, NotifyUp: true, Local: true}
	d1.Dispatch(Alert{EventID: "h1", Kind: KindProxmoxDown, Check: app, Time: clk.now(),
		Data: map[string]string{"what": "stopped", "type": "qemu", "name": "app", "path": "/healthchecks/proxmox/system/3/res/qemu/102"}})
	heldCount(1)
	d1.Stop() // Neustart in der Ruhezeit
	if n := len(rec1.list()); n != 0 {
		t.Fatalf("sent during quiet hours: %d", n)
	}

	clk.set(time.Date(2026, 1, 8, 7, 1, 0, 0, time.UTC))
	rec2 := &recorder{}
	d2 := start(rec2)
	defer d2.Stop()
	m := waitMsgs(t, rec2, 1)[0]
	if m.Kind != KindSummary || !strings.Contains(m.Text, "lab – app") {
		t.Fatalf("digest after restart: %+v", m)
	}
	heldCount(0)
}
