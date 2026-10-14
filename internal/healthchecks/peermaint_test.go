package healthchecks

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

func TestPeerMaintenance(t *testing.T) {
	m, srv := newTestModule(t)
	ctx := context.Background()
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	code, b := call(t, srv, "POST", "/api/maintenance", map[string]any{"name": "lokal", "start_at": start, "end_at": start.Add(time.Hour), "repeat": "none", "active": true})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var mw struct{ ID int64 }
	_ = json.Unmarshal(b, &mw)
	uid := m.MaintUID(ctx, "1")
	if uid == "" {
		var id int64
		_ = m.st.r.QueryRowContext(ctx, `SELECT id FROM hc_maintenance ORDER BY id LIMIT 1`).Scan(&id)
		t.Fatalf("local window without uid (id %d)", id)
	}
	if p, upd, _, _, err := m.PeerMaintenance(ctx, uid); err != nil || p == nil || p.Name != "lokal" || upd.IsZero() {
		t.Fatalf("peer view: %+v %v %v", p, upd, err)
	}
	count := func(where string, args ...any) int {
		var n int
		_ = m.st.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM hc_maintenance WHERE `+where, args...).Scan(&n)
		return n
	}
	t0 := time.Now().UTC().Truncate(time.Millisecond)
	win := func(uid, name string, remote int64) PeerMaint {
		return PeerMaint{UID: uid, Maintenance: wire.Maintenance{ID: remote, Name: name, StartAt: start, EndAt: start.Add(time.Hour), Repeat: "none", Tokens: []string{}, Active: true, Revision: 3}}
	}
	// neues Fenster einer anderen Node; aeltere Aenderung danach wird ignoriert
	if _, ok, err := m.ApplyPeerMaintenance(ctx, win("aaa", "von B", 0), t0, "node-b"); !ok || err != nil {
		t.Fatalf("apply new: %v %v", ok, err)
	}
	if _, ok, _ := m.ApplyPeerMaintenance(ctx, win("aaa", "alt", 0), t0.Add(-time.Minute), "node-b"); ok {
		t.Fatal("older change must not win")
	}
	// dasselbe hub-Fenster unter zwei Kennungen: nur eines bleibt
	if _, ok, _ := m.ApplyPeerMaintenance(ctx, win("yyy", "hub 55", 55), t0.Add(time.Second), "node-b"); !ok {
		t.Fatal("apply hub window")
	}
	if _, ok, _ := m.ApplyPeerMaintenance(ctx, win("zzz", "hub 55 neu", 55), t0.Add(2*time.Second), "node-c"); !ok {
		t.Fatal("apply hub window under other uid")
	}
	if n := count("remote_id = 55"); n != 1 {
		t.Fatalf("windows with remote 55: %d", n)
	}
	if n := count("remote_id = 55 AND uid = 'yyy' AND name = 'hub 55 neu'"); n != 1 {
		t.Fatal("first uid must stay, content must be updated")
	}
	// Loeschen ueber die andere Kennung (Server-ID passt), danach haelt der Loeschvermerk aeltere Aenderungen ab
	if _, ok, _ := m.DeletePeerMaintenance(ctx, "zzz", 55, t0.Add(3*time.Second), "node-c"); !ok {
		t.Fatal("delete via remote id")
	}
	if n := count("remote_id = 55"); n != 0 {
		t.Fatalf("still there: %d", n)
	}
	if _, _, del, rid, _ := m.PeerMaintenance(ctx, "yyy"); del.IsZero() || rid != 55 {
		t.Fatalf("tombstone: %v %d", del, rid)
	}
	if _, ok, _ := m.ApplyPeerMaintenance(ctx, win("yyy", "zurueck?", 55), t0.Add(2500*time.Millisecond), "node-b"); ok {
		t.Fatal("older change must not revive a deleted window")
	}
	// ohne Loeschvermerk ist eine Kennung schlicht unbekannt (keine Loeschung)
	if p, _, del, _, _ := m.PeerMaintenance(ctx, "unbekannt"); p != nil || !del.IsZero() {
		t.Fatal("unknown uid must be neither window nor deletion")
	}
}
