package peer

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

type testNode struct {
	m   *Manager
	srv *httptest.Server
	acc int64
}

func newNode(t *testing.T, id, name string, acc int64) *testNode {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "a.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	core_ms, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", core_ms); err != nil {
		t.Fatal(err)
	}
	ms, _ := Migrations()
	if err := core.Migrate(context.Background(), "peer", ms); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	n := &testNode{acc: acc}
	m, err := New(context.Background(), Deps{Core: core, Box: box, Log: log, Version: "test",
		NodeID: func() string { return id }, NodeName: func() string { return name }, AccountID: func() int64 { return n.acc }})
	if err != nil {
		t.Fatal(err)
	}
	n.m = m
	mux := http.NewServeMux()
	m.Register(mux)
	n.srv = httptest.NewServer(mux)
	t.Cleanup(n.srv.Close)
	return n
}

func names(t *testing.T, n *testNode) map[string]bool {
	t.Helper()
	list, err := n.m.Members(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, x := range list {
		out[x.Name] = true
	}
	return out
}

func waitMembers(t *testing.T, n *testNode, want ...string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		got := names(t, n)
		ok := len(got) == len(want)
		for _, w := range want {
			ok = ok && got[w]
		}
		if ok {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("members = %v, want %v", names(t, n), want)
}

func TestGroupPairing(t *testing.T) {
	ctx := context.Background()
	a, b, c := newNode(t, "node-a", "A", 522), newNode(t, "node-b", "B", 522), newNode(t, "node-c", "C", 522)
	other := newNode(t, "node-x", "X", 999)
	for _, n := range []*testNode{a, b, c, other} {
		newFake(n) // Healthchecks laeuft (ohne pingt die Gruppe nicht)
	}

	// falscher Code
	code, _, err := a.m.StartPairing()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.m.Join(ctx, a.srv.URL, "WRONGCOD", b.srv.URL); !errors.Is(err, ErrCode) {
		t.Fatalf("wrong code: %v", err)
	}
	// anderer Account: abgelehnt, Code bleibt gueltig
	if err := other.m.Join(ctx, a.srv.URL, code, other.srv.URL); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("other account: %v", err)
	}
	if c2, _ := a.m.PairingCode(); c2 != code {
		t.Fatal("a rejected node must not use up the code")
	}
	// B tritt bei
	if err := b.m.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	if c2, _ := a.m.PairingCode(); c2 != "" {
		t.Fatal("code must be single use")
	}
	waitMembers(t, a, "B")
	waitMembers(t, b, "A")
	// C tritt ueber B bei: A erfaehrt es von B, C kennt A und B
	code, _, _ = b.m.StartPairing()
	if err := c.m.Join(ctx, b.srv.URL, code, c.srv.URL); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, c, "A", "B")
	waitMembers(t, a, "B", "C")
	waitMembers(t, b, "A", "C")
	// signierte Anfragen funktionieren in alle Richtungen
	for _, n := range []*testNode{a, b, c} {
		n.m.pingAll(ctx)
		list, _ := n.m.Members(ctx)
		for _, x := range list {
			if !x.Online() || x.LastError != "" {
				t.Fatalf("%s -> %s: online=%v err=%q", n.m.d.NodeName(), x.Name, x.Online(), x.LastError)
			}
		}
	}
	// Account einer Node wechselt: ihre Anfragen werden abgelehnt
	c.acc = 999
	c.m.pingAll(ctx)
	list, _ := c.m.Members(ctx)
	for _, x := range list {
		if x.LastError == "" {
			t.Fatalf("after account change ping to %s must fail", x.Name)
		}
	}
	c.acc = 522
	// C wird entfernt: A und B vergessen C, C verlaesst die Gruppe
	if err := a.m.Remove(ctx, "node-c"); err != nil {
		t.Fatal(err)
	}
	waitMembers(t, a, "B")
	waitMembers(t, b, "A")
	waitMembers(t, c)
}

func TestNoAccountNoGroup(t *testing.T) {
	a := newNode(t, "node-a", "A", 0)
	if _, _, err := a.m.StartPairing(); !errors.Is(err, ErrNoAccount) {
		t.Fatalf("pairing without account: %v", err)
	}
}
