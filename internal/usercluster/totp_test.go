package usercluster

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/secrets"
)

func (n *node) totpStep(t *testing.T, id int64) int64 {
	t.Helper()
	var v int64
	_ = n.st.Reader().QueryRow(`SELECT totp_last_step FROM users WHERE id = ?`, id).Scan(&v)
	return v
}

// Wahl der eigenen Version mit einem hier nicht entschluesselbaren 2FA-Geheimnis: nichts wird geschrieben oder
// verteilt (sonst stuende der Chiffretext doppelt verschluesselt da und ginge danach als Klartext-Geheimnis hinaus).
func TestChooseOwnUnreadableTOTP(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$argon2id$pw-a", "de", "UTC")
	ub, _ := b.st.CreateUser(ctx, "admin", "$argon2id$pw-b", "de", "UTC")
	other, _ := secrets.Load(filepath.Join(t.TempDir(), "other.key"))
	if _, err := b.st.Writer().Exec(`UPDATE users SET totp_secret = ? WHERE id = ?`, other.Encrypt("FREMDGEHEIM"), ub.ID); err != nil {
		t.Fatal(err)
	}
	raw := b.rawTOTP(t, ub.ID)
	transfer(t, a, b) // gleicher Name, anderer Inhalt: zur Wahl auf B
	if len(b.c.Conflicts(ctx)) != 1 {
		t.Fatal("conflict expected")
	}
	b.take()
	if _, _, err := b.c.Choose(ctx, ub.UID, "x"); err == nil {
		t.Fatal("choosing a version with an unreadable 2fa secret must fail")
	}
	if got := b.rawTOTP(t, ub.ID); got != raw {
		t.Fatalf("unreadable secret rewritten: %q", got)
	}
	if c := b.take(); len(c) != 0 {
		t.Fatalf("nothing reported: %+v", c)
	}
	if data, found, err := b.c.ClusterGet(ctx, ItemAccounts, ub.UID); err == nil && found && strings.Contains(string(data), "enc:v1:") {
		t.Fatalf("ciphertext handed out as secret: %s", data)
	}
}

// Ein verbrauchter Zeitschritt der App-2FA gilt im Cluster ueberall: derselbe Code laesst sich auf einer anderen Node
// nicht erneut verwenden; ein aelterer Stand senkt den Schritt nie.
func TestTOTPStepSync(t *testing.T) {
	ctx := context.Background()
	a, b := newTestNode(t, "node-a"), newTestNode(t, "node-b")
	_, _ = a.st.CreateUser(ctx, "admin", "$h0", "", "UTC")
	u, _ := a.st.CreateUser(ctx, "anna", "$h1", "", "UTC")
	_ = a.st.SetUserTOTP(ctx, u.ID, "JBSWY3DPEHPK3PXP", "r1")
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	bu := b.user(t, "anna")
	stale, _, _ := b.c.ClusterGet(ctx, ItemAccounts, bu.UID) // Stand vor dem Anmelden
	b.take()

	if ok, _ := a.st.UseTOTPStep(ctx, u.ID, 1000); !ok {
		t.Fatal("step on A")
	}
	if errs := transfer(t, a, b); len(errs) > 0 {
		t.Fatal(errs)
	}
	if ok, _ := b.st.UseTOTPStep(ctx, bu.ID, 1000); ok {
		t.Fatal("the same code is accepted again on B")
	}
	if ok, _ := b.st.UseTOTPStep(ctx, bu.ID, 1001); !ok {
		t.Fatal("next step on B")
	}
	if errs := transfer(t, b, a); len(errs) > 0 {
		t.Fatal(errs)
	}
	if s := a.totpStep(t, u.ID); s != 1001 {
		t.Fatalf("step back on A: %d", s)
	}
	a.take()
	// aelterer Stand: der Schritt bleibt
	_ = apply(t, b, a, ItemAccounts, u.UID, stale)
	if s := a.totpStep(t, u.ID); s != 1001 {
		t.Fatalf("older state lowered the step: %d", s)
	}
	if e := a.audit(t, "user.cluster.update"); e != nil {
		t.Fatalf("a used step alone is not audited: %+v", e)
	}
}
