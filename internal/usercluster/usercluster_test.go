package usercluster

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
)

type change struct {
	item, id string
	deleted  bool
}

// node ist eine Node ohne Netz: Store, Provider und die gemeldeten Aenderungen (wie der Hook an den Cluster).
type node struct {
	id  string
	st  *store.Store
	box *secrets.Box
	c   *Cluster
	mu  sync.Mutex
	log []change
}

func newTestNode(t *testing.T, id string) *node {
	t.Helper()
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := store.Open(context.Background(), filepath.Join(dir, "a.db"), filepath.Join(dir, "b"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ms, _ := store.CoreMigrations()
	if err := st.Migrate(context.Background(), "core", ms); err != nil {
		t.Fatal(err)
	}
	box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	n := &node{id: id, st: st, box: box, c: New(st, box, log)}
	st.SetLoginCluster(func(_ context.Context, item, id string, deleted bool) {
		n.mu.Lock()
		n.log = append(n.log, change{item, id, deleted})
		n.mu.Unlock()
	})
	return n
}

// take: gemeldete Aenderungen, je Eintrag nur der letzte Stand (wie das Protokoll des Clusters).
func (n *node) take() []change {
	n.mu.Lock()
	defer n.mu.Unlock()
	var out []change
	for _, c := range n.log {
		for i, o := range out {
			if o.item == c.item && o.id == c.id {
				out = append(out[:i], out[i+1:]...)
				break
			}
		}
		out = append(out, c)
	}
	n.log = nil
	return out
}

// transfer: die gemeldeten Aenderungen von a holt b ab (Stand holen, mit Herkunft a uebernehmen); Fehler je Kennung.
func transfer(t *testing.T, a, b *node) map[string]error {
	t.Helper()
	ctx := context.Background()
	errs := map[string]error{}
	for _, c := range a.take() {
		data, found, err := a.c.ClusterGet(ctx, c.item, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.c.ClusterApply(peer.WithClusterOrigin(ctx, a.id, time.Now()), c.item, c.id, data, c.deleted || !found); err != nil {
			errs[c.id] = err
		}
	}
	return errs
}

func (n *node) user(t *testing.T, name string) *store.User {
	t.Helper()
	u, err := n.st.UserByName(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func (n *node) sessions(t *testing.T, userID int64) int {
	t.Helper()
	var c int
	_ = n.st.Reader().QueryRow(`SELECT count(*) FROM sessions WHERE user_id = ?`, userID).Scan(&c)
	return c
}

func (n *node) addSession(t *testing.T, id string, userID int64) {
	t.Helper()
	now := time.Now()
	if err := n.st.CreateSession(context.Background(), &store.Session{ID: id, UserID: userID, CSRF: "x", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
}

func (n *node) audit(t *testing.T, action string) *store.AuditEntry {
	t.Helper()
	list, _ := n.st.AuditList(context.Background(), 100, 0)
	for _, e := range list {
		if e.Action == action {
			return &e
		}
	}
	return nil
}

// Benutzer mit Passwort-Hash, App-2FA und SSO-Verknuepfung kommt an; Passkeys bleiben je Node; Aenderungen auf der
// anderen Node kommen zurueck und beenden dort die Sitzungen; Audit mit Herkunft cluster.
func TestUserSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	u, _ := a.st.CreateUser(ctx, "dennis", "$argon2id$hash-a", "de", "Europe/Berlin")
	_ = a.st.SetUserTOTP(ctx, u.ID, "TOTPGEHEIM", "r1,r2")
	_ = a.st.LinkIdentity(ctx, u.ID, "oidc:https://auth.example", "sub-1", "dennis@example.org")
	_ = a.st.AddPasskey(ctx, store.Passkey{UserID: u.ID, Name: "Handy", RPID: "a.example", CredentialID: "cred-a", Data: "{}"})
	_, _ = b.st.CreateUser(ctx, "bob", "$argon2id$hash-b", "en", "UTC")
	b.take()

	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := b.user(t, "dennis")
	if got == nil || got.UID != u.UID || got.PasswordHash != "$argon2id$hash-a" || got.TOTPSecret != "TOTPGEHEIM" || got.Lang != "de" {
		t.Fatalf("user on B: %+v", got)
	}
	if rec, _ := b.st.UserTOTPRecovery(ctx, got.ID); rec != "r1,r2" {
		t.Fatalf("recovery codes on B: %q", rec)
	}
	if ids, _ := b.st.Identities(ctx, got.ID); len(ids) != 1 || ids[0].Subject != "sub-1" {
		t.Fatalf("sso identities on B: %+v", ids)
	}
	if pk, _ := b.st.Passkeys(ctx, got.ID, ""); len(pk) != 0 {
		t.Fatalf("passkeys stay on their node: %+v", pk)
	}
	if e := b.audit(t, "user.cluster.create"); e == nil || e.Origin != "cluster" || e.Actor != "node:node-a" || e.Target != "dennis" {
		t.Fatalf("audit on B: %+v", e)
	}
	if c := b.take(); len(c) != 1 || c[0] != (change{ItemAccounts, u.UID, false}) {
		t.Fatalf("B reports the applied user: %+v", c)
	}

	// Passwort auf B geaendert: A uebernimmt, Sitzungen von dennis auf A enden, Passkey auf A bleibt
	a.addSession(t, "sess-a", u.ID)
	a.take()
	_ = b.st.UpdateUserPassword(ctx, got.ID, "$argon2id$hash-neu")
	if errs := transfer(t, b, a); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := a.user(t, "dennis"); x.ID != u.ID || x.PasswordHash != "$argon2id$hash-neu" || x.TOTPSecret != "TOTPGEHEIM" {
		t.Fatalf("update on A: %+v", x)
	}
	if a.sessions(t, u.ID) != 0 {
		t.Fatal("sessions of the user end on A after a password change from the cluster")
	}
	if pk, _ := a.st.Passkeys(ctx, u.ID, ""); len(pk) != 1 {
		t.Fatal("passkey on A must stay")
	}
	if e := a.audit(t, "user.cluster.update"); e == nil || !strings.Contains(e.Details, "password") {
		t.Fatalf("audit on A: %+v", e)
	}
	// Verknuepfung auf A getrennt: auch auf B weg
	a.take()
	ids, _ := a.st.Identities(ctx, u.ID)
	_, _ = a.st.UnlinkIdentity(ctx, u.ID, ids[0].ID)
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if ids, _ := b.st.Identities(ctx, got.ID); len(ids) != 0 {
		t.Fatalf("unlinked identity on B: %+v", ids)
	}
}

// SSO-Einrichtung: Secret mit dem Schluessel der empfangenden Node, Rueckleit-Adresse bleibt je Node; Entfernen kommt an.
func TestSSOSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	for k, v := range map[string]string{SetOIDCIssuer: "https://auth.example", SetOIDCClient: "node64", SetOIDCSecret: a.box.Encrypt("s3cret"),
		SetOIDCLabel: "Authelia", SetOIDCScopes: "openid profile", "auth.oidc.base_url": "https://a.example"} {
		_ = a.st.SetSetting(ctx, k, v)
	}
	_ = b.st.SetSetting(ctx, "auth.oidc.base_url", "https://b.example")
	if ids, _ := a.c.ClusterIDs(ctx, ItemSSO); len(ids) != 1 {
		t.Fatalf("sso ids: %v", ids)
	}
	SSOChanged(ctx, a.st)
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	enc := b.st.SettingOr(ctx, SetOIDCSecret, "")
	if plain, _ := b.box.Decrypt(enc); plain != "s3cret" || strings.Contains(enc, "s3cret") || enc == a.st.SettingOr(ctx, SetOIDCSecret, "") {
		t.Fatalf("secret must be re-encrypted with B's key: %q", enc)
	}
	if b.st.SettingOr(ctx, SetOIDCIssuer, "") != "https://auth.example" || b.st.SettingOr(ctx, SetOIDCClient, "") != "node64" ||
		b.st.SettingOr(ctx, SetOIDCScopes, "") != "openid profile" || b.st.SettingOr(ctx, "auth.oidc.base_url", "") != "https://b.example" {
		t.Fatal("sso settings on B (base_url stays per node)")
	}
	if e := b.audit(t, "sso.cluster.update"); e == nil || e.Origin != "cluster" {
		t.Fatalf("audit: %+v", e)
	}
	// Entfernt auf A: auch auf B
	_ = a.st.SetSetting(ctx, SetOIDCIssuer, "")
	SSOChanged(ctx, a.st)
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if b.st.SettingOr(ctx, SetOIDCIssuer, "x") != "" || b.st.SettingOr(ctx, SetOIDCSecret, "x") != "" {
		t.Fatal("sso removed on B")
	}
}

// Exakt gleicher Benutzer unter verschiedenen Kennungen: beide Nodes landen bei der kleineren, ohne Loeschen.
func TestUserExactDuplicate(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	ua, _ := a.st.CreateUser(ctx, "admin", "$argon2id$same", "de", "UTC")
	ub, _ := b.st.CreateUser(ctx, "admin", "$argon2id$same", "de", "UTC")
	a.addSession(t, "sess-a", ua.ID)
	lo, hi := ua.UID, ub.UID
	if hi < lo {
		lo, hi = hi, lo
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if errs := transfer(t, b, a); len(errs) > 0 {
		t.Fatal(errs)
	}
	for _, n := range []*node{a, b} {
		if u := n.user(t, "admin"); u.UID != lo {
			t.Fatalf("%s: uid %s, want the smaller %s", n.id, u.UID, lo)
		}
		if n2, _ := n.st.UserCount(ctx); n2 != 1 {
			t.Fatalf("%s: %d users", n.id, n2)
		}
	}
	if a.user(t, "admin").ID != ua.ID || a.sessions(t, ua.ID) != 1 {
		t.Fatal("merge keeps the local user and its sessions")
	}
	if len(a.c.Conflicts(ctx)) != 0 || len(b.c.Conflicts(ctx)) != 0 {
		t.Fatal("no conflict for an exact duplicate")
	}
	// nur aehnlich (andere Sprache): kein Zusammenfuehren
	c, d := newTestNode(t, "node-c"), newTestNode(t, "node-d")
	_, _ = c.st.CreateUser(ctx, "admin", "$argon2id$same", "de", "UTC")
	_, _ = d.st.CreateUser(ctx, "admin", "$argon2id$same", "en", "UTC")
	if errs := transfer(t, c, d); len(errs) != 1 {
		t.Fatalf("similar users are not merged: %v", errs)
	}
}

// Gleichnamig, aber verschieden: nichts wird ueberschrieben, beide Nodes zeigen die Abweichung; die Wahl (fremde
// Version) ersetzt den Benutzer an Ort und Stelle, die eigene Sitzung bleibt, die andere Node uebernimmt.
func TestUserConflictChooseOther(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	ua, _ := a.st.CreateUser(ctx, "admin", "$argon2id$pw-a", "de", "UTC")
	ub, _ := b.st.CreateUser(ctx, "admin", "$argon2id$pw-b", "de", "UTC")
	_ = b.st.SetUserTOTP(ctx, ub.ID, "TOTPB", "")
	a.addSession(t, "mine", ua.ID)
	a.addSession(t, "other", ua.ID)
	for _, p := range [][2]*node{{a, b}, {b, a}} {
		errs := transfer(t, p[0], p[1])
		if len(errs) != 1 || !errors.Is(errs[p[0].user(t, "admin").UID], ErrConflict) {
			t.Fatalf("conflict expected on %s: %v", p[1].id, errs)
		}
	}
	if a.user(t, "admin").PasswordHash != "$argon2id$pw-a" || b.user(t, "admin").PasswordHash != "$argon2id$pw-b" {
		t.Fatal("each node keeps its user until a choice")
	}
	cs := a.c.Conflicts(ctx)
	if len(cs) != 1 || len(cs[0].Versions) != 2 || !cs[0].Versions[0].Own || cs[0].Versions[1].Node != "node-b" || !cs[0].Versions[1].TwoFA {
		t.Fatalf("conflicts on A: %+v", cs)
	}
	if a.audit(t, "user.cluster.conflict") == nil {
		t.Fatal("conflict in the audit log")
	}
	if _, _, err := a.c.Choose(ctx, "ffffffffffffffffffff", "mine"); !errors.Is(err, ErrChoice) {
		t.Fatalf("unknown choice: %v", err)
	}
	a.take()
	name, dropped, err := a.c.Choose(ctx, ub.UID, "mine")
	if err != nil || name != "admin" || len(dropped) != 1 || dropped[0].UID != ua.UID {
		t.Fatalf("choose: %s %+v %v", name, dropped, err)
	}
	got := a.user(t, "admin")
	if got.ID != ua.ID || got.UID != ub.UID || got.PasswordHash != "$argon2id$pw-b" || got.TOTPSecret != "TOTPB" {
		t.Fatalf("A after choice: %+v", got)
	}
	if a.sessions(t, ua.ID) != 1 {
		t.Fatal("the choosing session stays, the others end")
	}
	if len(a.c.Conflicts(ctx)) != 0 {
		t.Fatal("conflict resolved on A")
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if x := b.user(t, "admin"); x.ID != ub.ID || x.UID != ub.UID || x.PasswordHash != "$argon2id$pw-b" {
		t.Fatalf("B keeps its (chosen) user: %+v", x)
	}
	if len(b.c.Conflicts(ctx)) != 0 {
		t.Fatal("conflict resolved on B by the choice")
	}
	// spaete Aenderung der abgeloesten Version (alte Kennung von A) wird abgewiesen
	late, _, _ := b.c.ClusterGet(ctx, ItemAccounts, ub.UID)
	if err := b.c.ClusterApply(peer.WithClusterOrigin(ctx, "node-a", time.Now()), ItemAccounts, ua.UID, late, false); !errors.Is(err, ErrReplaced) {
		t.Fatalf("replaced version: %v", err)
	}
}

// Wahl der eigenen Version: die andere Node ersetzt ihren Benutzer an Ort und Stelle (Sitzungen enden dort).
func TestUserConflictChooseOwn(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	ua, _ := a.st.CreateUser(ctx, "admin", "$argon2id$pw-a", "de", "UTC")
	ub, _ := b.st.CreateUser(ctx, "admin", "$argon2id$pw-b", "de", "UTC")
	_ = b.st.AddPasskey(ctx, store.Passkey{UserID: ub.ID, Name: "Key", RPID: "b.example", CredentialID: "cred-b", Data: "{}"})
	b.addSession(t, "sb", ub.ID)
	transfer(t, b, a)
	a.take()
	if _, _, err := a.c.Choose(ctx, ua.UID, "x"); err != nil {
		t.Fatal(err)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	got := b.user(t, "admin")
	if got.ID != ub.ID || got.UID != ua.UID || got.PasswordHash != "$argon2id$pw-a" {
		t.Fatalf("B adopts the chosen user in place: %+v", got)
	}
	if pk, _ := b.st.Passkeys(ctx, ub.ID, ""); len(pk) != 1 {
		t.Fatal("passkey on B stays with the user")
	}
	if b.sessions(t, ub.ID) != 0 {
		t.Fatal("sessions on B end (password changed)")
	}
	if e := b.audit(t, "user.cluster.choice"); e == nil || e.Origin != "cluster" {
		t.Fatalf("audit on B: %+v", e)
	}
	if n, _ := b.st.UserCount(ctx); n != 1 {
		t.Fatalf("B: %d users", n)
	}
}

// Loeschen kommt an, aber nie fuer den letzten Benutzer einer Node.
func TestUserDeleteLastAdmin(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	x, _ := a.st.CreateUser(ctx, "anna", "$h1", "", "UTC")
	y, _ := a.st.CreateUser(ctx, "bert", "$h2", "", "UTC")
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if n, _ := b.st.UserCount(ctx); n != 2 {
		t.Fatalf("B: %d users", n)
	}
	if ok, err := a.st.DeleteUser(ctx, y.ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if b.user(t, "bert") != nil || b.audit(t, "user.cluster.delete") == nil {
		t.Fatal("deletion reaches B")
	}
	_, _ = a.st.DeleteUser(ctx, x.ID)
	errs := transfer(t, a, b)
	if !errors.Is(errs[x.UID], ErrLastUser) || b.user(t, "anna") == nil {
		t.Fatalf("last user on B stays: %v", errs)
	}
	if b.audit(t, "user.cluster.keep_last") == nil {
		t.Fatal("refusal in the audit log")
	}
}

// Ohne Einstellung ist der Bereich aus: die Node meldet ihn nicht im Ping, also wird nichts ausgetauscht.
func TestAreaOffByDefault(t *testing.T) {
	ctx := context.Background()
	a := newTestNode(t, "node-a")
	ms, _ := peer.Migrations()
	if err := a.st.Migrate(ctx, "peer", ms); err != nil {
		t.Fatal(err)
	}
	pm, err := peer.New(ctx, peer.Deps{Core: a.st, Log: slog.New(slog.DiscardHandler), Version: "test",
		NodeID: func() string { return "node-a" }, NodeName: func() string { return "A" }, AccountID: func() int64 { return 0 }})
	if err != nil {
		t.Fatal(err)
	}
	Register(pm, a.c)
	found := false
	for _, m := range pm.SyncModules(ctx) {
		if m.ID != ModuleID {
			continue
		}
		found = true
		if m.Enabled || len(m.Items) != 2 || m.Items[0].Enabled || m.Items[1].Enabled {
			t.Fatalf("users area must be off by default: %+v", m)
		}
	}
	if !found {
		t.Fatal("module not registered")
	}
	if err := pm.SetSync(ctx, ModuleID, ItemAccounts, true); err != nil {
		t.Fatal(err)
	}
}
