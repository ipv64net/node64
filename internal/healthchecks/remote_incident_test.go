package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestRemoteIncident(t *testing.T) {
	m, srv := newTestModule(t)
	m.SetLinked(func() bool { return true })
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "online", "type": "icmp", "target": "9.9.9.9", "execution": "online", "interval_seconds": 60})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c struct{ Token string }
	_ = json.Unmarshal(b, &c)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-10 * time.Minute).Truncate(time.Second)
	m.ApplyRemoteState(ctx, RemoteState{Token: c.Token, State: "down", Since: t0, Time: t0, Status: "down", Reason: "timeout", Message: "x"})
	m.ApplyRemoteState(ctx, RemoteState{Token: c.Token, State: "down", Since: t0, Time: t0.Add(time.Minute), Status: "down", Reason: "timeout", Message: "x"})
	m.ApplyRemoteState(ctx, RemoteState{Token: c.Token, State: "degraded", Since: t0.Add(2 * time.Minute), Time: t0.Add(2 * time.Minute), Status: "up"})
	list, _ := m.st.Incidents(ctx, c.Token, 10)
	if len(list) != 1 || !list[0].Open || !list[0].StartedAt.Equal(t0) {
		t.Fatalf("after down: %+v", list)
	}
	t1 := t0.Add(5 * time.Minute)
	m.ApplyRemoteState(ctx, RemoteState{Token: c.Token, State: "up", Since: t1, Time: t1, Status: "up"})
	list, _ = m.st.Incidents(ctx, c.Token, 10)
	if len(list) != 1 || list[0].Open || !list[0].EndedAt.Equal(t1) {
		t.Fatalf("after up: %+v", list)
	}
}
