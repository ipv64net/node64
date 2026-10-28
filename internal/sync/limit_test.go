package sync

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/wire"
)

// Stapel an den hub bleiben unter der Leselimite, uebergrosse Messpunkte werden gekuerzt.
func TestChunksAndShrink(t *testing.T) {
	big := strings.Repeat("x", 40<<10)
	var batch []wire.Measurement
	for i := 0; i < 500; i++ {
		batch = append(batch, wire.Measurement{Seq: int64(i + 1), Token: "tok", Message: strings.Repeat("m", 1500), Details: map[string]any{"body": big[:i*10]}})
	}
	batch[3].Details = map[string]any{"body": big}
	small := shrinkMeasurements(batch)
	if batch[3].Details["body"] != big {
		t.Fatal("input changed")
	}
	if small[3].Details["truncated"] != true || len(small[3].Message) != maxItemText {
		t.Fatalf("not shrunk: %v %d", small[3].Details, len(small[3].Message))
	}
	parts := chunks(small)
	if len(parts) < 2 {
		t.Fatalf("expected several parts, got %d", len(parts))
	}
	n := 0
	for _, p := range parts {
		b, _ := json.Marshal(map[string]any{"batch": p})
		if len(b) > maxUploadBytes+1024 {
			t.Fatalf("part too big: %d", len(b))
		}
		n += len(p)
	}
	if n != len(batch) || parts[0][0].Seq != 1 {
		t.Fatalf("items lost: %d", n)
	}
	if chunks([]wire.State(nil)) != nil {
		t.Fatal("empty input must give no parts")
	}
	if got := cutText("ääää", 3); got != "ä" {
		t.Fatalf("cut: %q", got)
	}
}
