package dns64

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/ports"
)

// Start mit einer Gruppe, die "Internet aus" haben kann: DNS64 meldet unter m.mu die Hinweisseite an, der Eingang
// oeffnet dafuer Port 80 und prueft die Ports aller Module - auch die von DNS64. Das darf nicht auf m.mu warten.
func TestStartWithHintRouteDoesNotDeadlock(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	g, err := m.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSchedule(ctx, groups.Schedule{GroupID: g.ID, Days: []int{1}, Start: "21:00", End: "07:00", Action: groups.ScheduleOff}); err != nil {
		t.Fatal(err)
	}
	check := func(ctx context.Context, _ []ports.Claim) error { _ = m.Ports(ctx, false); return nil }
	e, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPPort: freePort(t), Default: edge.DefaultNotFound}, noCerts{}, check, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	m.SetEdge(e)
	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()
	select {
	case err := <-done:
		if err != nil || m.running() == nil {
			t.Fatalf("start: %v %s", err, m.startError())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("start hangs (port check waits for m.mu)")
	}
	_ = m.Stop(ctx)
}
