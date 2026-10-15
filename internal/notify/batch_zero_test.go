package notify

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/i18n"
)

// Ohne Sammelfenster (0) kommen gleichzeitige Alerts trotzdem als eine Sammelmeldung.
func TestBatchWindowZeroStillSummarizes(t *testing.T) {
	st := testStore(t)
	bundle, _ := i18n.Load()
	rec := &recorder{}
	d := NewMultiDispatcher(st, map[Type]Sender{TypeWebhook: rec}, bundle, func(uid int64) Settings {
		return func(key, def string) string {
			switch key {
			case SetBatchWindow:
				return "0"
			case SetBatchThreshold:
				return "3"
			}
			return def
		}
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	addChannel(t, st, "default", true)
	d.Start(context.Background())
	defer d.Stop()
	for i := 0; i < 5; i++ {
		d.Dispatch(Alert{EventID: fmt.Sprint("s", i), Kind: KindDown, Check: CheckInfo{Token: fmt.Sprint("t", i), Name: fmt.Sprint("C", i), NotifyDown: true}})
	}
	time.Sleep(500 * time.Millisecond)
	msgs := rec.list()
	if len(msgs) != 1 || msgs[0].Kind != KindSummary {
		kinds := []Kind{}
		for _, m := range msgs {
			kinds = append(kinds, m.Kind)
		}
		t.Fatalf("want one summary, got %d messages %v", len(msgs), kinds)
	}
}
