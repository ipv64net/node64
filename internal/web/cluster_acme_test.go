package web

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

// certsNode: Zertifikatsverwaltung auf einem Store (ohne Web), mit ACME-Konto (Schluessel direkt gesetzt).
func certsNode(t *testing.T, st *store.Store, self, mail string) (*certs.Manager, *secrets.Box) {
	t.Helper()
	ctx := context.Background()
	ms, _ := certs.Migrations()
	if err := st.Migrate(ctx, "certs", ms); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	box, _ := secrets.New(raw)
	m, err := certs.New(ctx, certs.Deps{Store: st, Box: box})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	m.SetCluster(func() string { return self }, nil)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalECPrivateKey(k)
	if err := st.SetSetting(ctx, "certs.acme_key", box.Encrypt(string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))); err != nil {
		t.Fatal(err)
	}
	if err := m.SetAccount(ctx, mail, true); err != nil {
		t.Fatal(err)
	}
	return m, box
}

// Verschiedene ACME-Konten im Cluster: die Seite Cluster zeigt beide zur Wahl, die Wahl (Seite oder API) uebernimmt
// das gewaehlte und vermerkt das verworfene im Audit-Log.
func TestClusterACMEChoice(t *testing.T) {
	ctx := context.Background()
	var mgr *certs.Manager
	var box *secrets.Box
	a := newTestAppDeps(t, func(d *Deps) {
		ms, _ := peer.Migrations()
		if err := d.Store.Migrate(ctx, "peer", ms); err != nil {
			t.Fatal(err)
		}
		pm, err := peer.New(ctx, peer.Deps{Core: d.Store, Log: d.Log.Slog(), Version: "test",
			NodeID: func() string { return "node-a" }, NodeName: func() string { return "Node A" }, AccountID: func() int64 { return 0 }})
		if err != nil {
			t.Fatal(err)
		}
		d.Peer = pm
		mgr, box = certsNode(t, d.Store, "node-a", "a@example.org")
		d.Certs = mgr
	})
	if _, err := a.store.Writer().ExecContext(ctx, `INSERT INTO peer_members (node_id, name, url, pubkey, account_id, added_at, added_by, sync)
		VALUES ('node-b', 'Node B', 'https://192.168.1.20:8443', 'cHVi', 0, '2026-10-19T10:00:00Z', 'test', 'certs/acme')`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	stB, err := store.Open(ctx, filepath.Join(dir, "b.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stB.Close() })
	cm, _ := store.CoreMigrations()
	if err := stB.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	b, boxB := certsNode(t, stB, "node-b", "b@example.org")
	keyB, _ := boxB.Decrypt(stB.SettingOr(ctx, "certs.acme_key", ""))
	keyA, _ := box.Decrypt(a.store.SettingOr(ctx, "certs.acme_key", ""))

	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/cluster")
	if strings.Contains(body, `id="acme"`) {
		t.Fatal("no choice without a conflict")
	}
	data, _, err := b.ClusterGet(ctx, certs.ItemACME, "account")
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.ClusterApply(ctx, certs.ItemACME, "account", data, false); !errors.Is(err, certs.ErrAccountConflict) {
		t.Fatalf("conflict expected: %v", err)
	}
	_, body = a.get(t, "/cluster")
	for _, want := range []string{`id="acme"`, "Node B", "b@example.org", "a@example.org", "Diese Node", `action="/cluster/acme"`, "Dieses verwenden", "Let&#39;s Encrypt"} {
		if !strings.Contains(body, want) {
			t.Fatalf("cluster page misses %q", want)
		}
	}
	if strings.Contains(body, "cluster.acme") {
		t.Fatal("untranslated acme key")
	}
	list := mgr.AccountConflicts(ctx)
	if len(list) != 2 || list[1].Node != "node-b" {
		t.Fatalf("conflicts: %+v", list)
	}

	// Seite: unbekanntes Konto wird abgelehnt, nichts geaendert
	resp, _ := a.post(t, "/cluster/acme", url.Values{"_csrf": {csrfOf(t, body)}, "thumbprint": {"gibtsnicht"}})
	if k, _ := box.Decrypt(a.store.SettingOr(ctx, "certs.acme_key", "")); resp.StatusCode != http.StatusSeeOther || k != keyA {
		t.Fatalf("unknown choice: %d", resp.StatusCode)
	}

	// API: das Konto von B waehlen
	hash, _ := HashPassword("x")
	u, _ := a.store.CreateUser(ctx, "api", hash, "de", "UTC")
	key, _, _ := a.store.NewAPIKey(ctx, u.ID, "script")
	req, _ := http.NewRequest("POST", a.srv.URL+"/api/group/acme", strings.NewReader(`{"thumbprint":"`+list[1].Thumbprint+`"}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	resp, err = a.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if k, _ := box.Decrypt(a.store.SettingOr(ctx, "certs.acme_key", "")); resp.StatusCode != 200 || k != keyB || mgr.Account(ctx).Email != "b@example.org" {
		t.Fatalf("api choice: %d", resp.StatusCode)
	}
	if _, body = a.get(t, "/cluster"); strings.Contains(body, `id="acme"`) {
		t.Fatal("choice still shown after choosing")
	}
	entries, _ := a.store.AuditList(ctx, 50, 0)
	found := false
	for _, e := range entries {
		found = found || e.Action == "cert.account.choose" && strings.Contains(e.Details, "a@example.org")
	}
	if !found {
		t.Fatal("audit entry with the dropped account missing")
	}
}
