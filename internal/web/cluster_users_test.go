package web

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/usercluster"
)

// Die SSO-Einrichtung im Cluster nutzt dieselben Schluessel wie die Seite Anmeldung.
func TestUserClusterOIDCKeys(t *testing.T) {
	if usercluster.SetOIDCIssuer != setOIDCIssuer || usercluster.SetOIDCClient != setOIDCClient || usercluster.SetOIDCSecret != setOIDCSecret ||
		usercluster.SetOIDCLabel != setOIDCLabel || usercluster.SetOIDCScopes != setOIDCScopes {
		t.Fatal("usercluster and web/auth_oidc.go use different setting keys")
	}
}

// Gleichnamige, verschiedene Benutzer: die Seite Cluster zeigt beide Versionen, die Wahl uebernimmt die gewaehlte an
// Ort und Stelle (die eigene Sitzung bleibt) und steht im Audit-Log; danach Liste und Loeschen auf der Seite Anmeldung.
func TestClusterUserChoice(t *testing.T) {
	ctx := context.Background()
	var uc *usercluster.Cluster
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
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		d.Box, _ = secrets.New(raw)
		d.Peer = pm
		uc = usercluster.New(d.Store, d.Box, d.Log.Slog())
		usercluster.Register(pm, uc)
		d.Users = uc
	})
	if _, err := a.store.Writer().ExecContext(ctx, `INSERT INTO peer_members (node_id, name, url, pubkey, account_id, added_at, added_by, sync)
		VALUES ('node-b', 'Node B', 'https://192.168.1.20:8443', 'cHVi', 0, '2026-10-19T10:00:00Z', 'test', 'users/accounts')`); err != nil {
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
	boxB, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	ucB := usercluster.New(stB, boxB, nil)
	hashB, _ := HashPassword("passwort von node b")
	ub, _ := stB.CreateUser(ctx, "admin", hashB, "de", "UTC")

	me := loginAs(t, a, "admin", "sehr geheimes passwort")
	if _, body := a.get(t, "/cluster"); strings.Contains(body, `id="users"`) {
		t.Fatal("no choice without a conflict")
	}
	data, _, _ := ucB.ClusterGet(ctx, usercluster.ItemAccounts, ub.UID)
	if err := uc.ClusterApply(peer.WithClusterOrigin(ctx, "node-b", time.Now()), usercluster.ItemAccounts, ub.UID, data, false); !errors.Is(err, usercluster.ErrConflict) {
		t.Fatalf("conflict expected: %v", err)
	}
	_, body := a.get(t, "/cluster")
	for _, want := range []string{`id="users"`, "Benutzer im Cluster: bitte wählen", "Node B", "Diese Node", `action="/cluster/users"`, "Diese verwenden", ub.UID[:12]} {
		if !strings.Contains(body, want) {
			t.Fatalf("cluster page misses %q", want)
		}
	}
	if strings.Contains(body, "cluster.users") || strings.Contains(body, "cluster.mod.users") || strings.Contains(body, "cluster.item.user") {
		t.Fatal("untranslated key on the cluster page")
	}
	resp, _ := a.post(t, "/cluster/users", url.Values{"_csrf": {csrfOf(t, body)}, "uid": {ub.UID}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("choice: %d", resp.StatusCode)
	}
	got, _ := a.store.UserByID(ctx, me.ID)
	if got.UID != ub.UID || got.PasswordHash != hashB {
		t.Fatalf("user after choice: %+v", got)
	}
	resp, body = a.get(t, "/cluster") // eigene Sitzung bleibt
	if resp.StatusCode != 200 || strings.Contains(body, `id="users"`) {
		t.Fatalf("after choice: %d", resp.StatusCode)
	}
	entries, _ := a.store.AuditList(ctx, 50, 0)
	found := false
	for _, e := range entries {
		found = found || e.Action == "user.cluster.choose" && e.Target == "admin" && strings.Contains(e.Details, "self:")
	}
	if !found {
		t.Fatal("audit entry of the choice missing")
	}

	// Seite Anmeldung: Liste ab zwei Benutzern, den eigenen nicht loeschen, einen anderen schon
	_, body = a.get(t, "/settings/login")
	if strings.Contains(body, `id="users"`) {
		t.Fatal("no user list with a single user")
	}
	other, _ := a.store.CreateUser(ctx, "bob", hashB, "en", "UTC")
	_, body = a.get(t, "/settings/login")
	if !strings.Contains(body, `id="users"`) || !strings.Contains(body, "/settings/login/users/"+itoa(other.ID)+"/delete") ||
		strings.Contains(body, "/settings/login/users/"+itoa(me.ID)+"/delete") {
		t.Fatal("user list on the login page")
	}
	csrf := csrfOf(t, body)
	a.post(t, "/settings/login/users/"+itoa(me.ID)+"/delete", url.Values{"_csrf": {csrf}})
	if u, _ := a.store.UserByID(ctx, me.ID); u == nil {
		t.Fatal("own user must not be deleted")
	}
	a.post(t, "/settings/login/users/"+itoa(other.ID)+"/delete", url.Values{"_csrf": {csrf}})
	if u, _ := a.store.UserByID(ctx, other.ID); u != nil {
		t.Fatal("other user not deleted")
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
