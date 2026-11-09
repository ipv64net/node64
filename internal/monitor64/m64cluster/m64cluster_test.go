package m64cluster

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

type node struct {
	id  string
	pm  *peer.Manager
	m   *monitor64.Module
	srv *httptest.Server
}

func newNode(t *testing.T, id, name string, boxKey byte) *node {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cm, _ := store.CoreMigrations()
	pmig, _ := peer.Migrations()
	nm, _ := notify.Migrations()
	for _, x := range []struct {
		name string
		ms   []store.Migration
	}{{"core", cm}, {"peer", pmig}, {"notify", nm}, {monitor64.Name, monitor64.Migrations()}} {
		if err := st.Migrate(ctx, x.name, x.ms); err != nil {
			t.Fatal(err)
		}
	}
	_ = st.SetSetting(ctx, "node.id", id)
	_ = st.SetSetting(ctx, "node.name", name)
	box, _ := secrets.New(bytes.Repeat([]byte{boxKey}, 32))
	n := &node{id: id}
	mux := http.NewServeMux()
	n.srv = httptest.NewUnstartedServer(mux)
	n.srv.StartTLS()
	t.Cleanup(n.srv.Close)
	port := n.srv.Listener.Addr().(*net.TCPAddr).Port
	n.pm, err = peer.New(ctx, peer.Deps{Core: st, Box: box, Log: log, Version: "test",
		NodeID: func() string { return id }, NodeName: func() string { return name }, AccountID: func() int64 { return 0 },
		HTTPSPort: func() int { return port }})
	if err != nil {
		t.Fatal(err)
	}
	n.pm.Register(mux)
	n.m = monitor64.New(st, log, box, dir, "test")
	Register(n.pm, n.m, func() string { return id })
	if err := n.m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = n.m.Stop(context.Background()) })
	return n
}

func hostsOf(t *testing.T, m *monitor64.Module) []map[string]any {
	t.Helper()
	raw, err := m.Export(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(raw)
	var out struct {
		Tables map[string][]map[string]any `json:"tables"`
	}
	_ = json.Unmarshal(b, &out)
	return out.Tables["m64_hosts"]
}

// Ueber den echten Cluster (TLS, signiert): Bereich monitor64 schaltbar, ein Host kommt mit seinem Zugang an, die
// beigetretene Node uebernimmt den Cluster-Schluessel nicht vorzeitig selbst, Anfragen zwischen den Nodes laufen.
func TestRealPeerSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := newNode(t, "node-a", "A", 1), newNode(t, "node-b", "B", 2)
	for _, n := range []*node{a, b} {
		if err := n.pm.SetSync(ctx, monitor64.ClusterModuleID, "", true); err != nil {
			t.Fatal(err)
		}
	}
	code, _, err := a.pm.StartPairing()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.pm.Join(ctx, a.srv.URL, code, b.srv.URL); err != nil {
		t.Fatal(err)
	}
	go a.pm.Run(ctx)
	go b.pm.Run(ctx)

	imp := `{"version":1,"tables":{"m64_hosts":[{"uid":"hostAAAAAAAA0001","name":"nas01","address":"10.0.0.5","kind":"ssh","group_name":"","tags":"[]",
		"interval_sec":60,"owner_node":"","preferred_node":"","backup_nodes":"[]","agent_autoupd":1,"paused":1,"notes":"","created_at":"2026-11-09T10:00:00.000Z",
		"created_by":"{}","updated_at":"` + time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + `","updated_by":"{}","deleted":0}]}}`
	if _, err := a.m.Import(ctx, json.RawMessage(imp)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var got []map[string]any
	for time.Now().Before(deadline) {
		if got = hostsOf(t, b.m); len(got) == 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if len(got) != 1 || got[0]["name"] != "nas01" || got[0]["preferred_node"] != "node-a" {
		t.Fatalf("host did not arrive over the cluster: %+v", got)
	}
	// Anfrage an die andere Node (Anstoss), unbekannte Anfrage wird abgelehnt
	var out map[string]bool
	if err := b.pm.Call(ctx, "node-a", monitor64.ClusterModuleID, "repoll", map[string]string{"host": "hostAAAAAAAA0001"}, &out); err != nil || !out["ok"] {
		t.Fatalf("call: %v %v", err, out)
	}
	if err := b.pm.Call(ctx, "node-a", monitor64.ClusterModuleID, "nope", nil, nil); err == nil {
		t.Fatal("unknown call accepted")
	}
	// Bereich aus: keine Anfragen mehr
	if err := a.pm.SetSync(ctx, monitor64.ClusterModuleID, "", false); err != nil {
		t.Fatal(err)
	}
	if err := b.pm.Call(ctx, "node-a", monitor64.ClusterModuleID, "repoll", map[string]string{"host": "hostAAAAAAAA0001"}, nil); err == nil ||
		!strings.Contains(err.Error(), "not available") {
		t.Fatalf("area off: %v", err)
	}
}
