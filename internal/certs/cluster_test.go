package certs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// hookRec merkt sich die Meldungen an den Cluster ("bereich uid" bzw. "bereich uid deleted").
type hookRec struct {
	mu sync.Mutex
	ev []string
}

func (h *hookRec) has(s string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Contains(h.ev, s)
}

func clusterNode(t *testing.T, self string) (*env, *hookRec) {
	e := newEnv(t, nil)
	h := &hookRec{}
	e.m.SetCluster(func() string { return self }, func(_ context.Context, item, uid string, deleted bool) {
		s := item + " " + uid
		if deleted {
			s += " deleted"
		}
		h.mu.Lock()
		h.ev = append(h.ev, s)
		h.mu.Unlock()
	})
	return e, h
}

// syncItems: erster Abgleich wie im Cluster (alle Eintraege von from nach to).
func syncItems(t *testing.T, from, to *env, items ...string) {
	t.Helper()
	ctx := context.Background()
	for _, item := range items {
		ids, err := from.m.ClusterIDs(ctx, item)
		if err != nil {
			t.Fatal(err)
		}
		for _, uid := range ids {
			data, found, err := from.m.ClusterGet(ctx, item, uid)
			if err != nil || !found {
				t.Fatalf("get %s %s: %v %v", item, uid, found, err)
			}
			if err := to.m.ClusterApply(ctx, item, uid, data, false); err != nil {
				t.Fatalf("apply %s %s: %v", item, uid, err)
			}
		}
	}
}

// Node A -> Node B (anderer Schluessel, verschobene IDs): Zertifikate mit Schluessel sind auf B nutzbar, die
// Verweise zeigen auf B's IDs, Geheimes ist lesbar, B erneuert nicht selbst.
func TestClusterRoundTripAndRefs(t *testing.T) {
	ctx := context.Background()
	a, ha := clusterNode(t, "node-a")
	b, hb := clusterNode(t, "node-b")
	if err := b.m.SaveDNSAccount(ctx, &DNSAccount{Name: "Hetzner", Provider: "hetzner"}, map[string]string{"token": "h"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.m.CreateCA(ctx, CAInput{Name: "B-CA"}); err != nil {
		t.Fatal(err)
	}

	acc := &DNSAccount{Name: "Cloudflare", Provider: "cloudflare"}
	if err := a.m.SaveDNSAccount(ctx, acc, map[string]string{"token": "cf-secret-token"}); err != nil {
		t.Fatal(err)
	}
	ca, err := a.m.CreateCA(ctx, CAInput{Name: "Heimnetz"})
	if err != nil {
		t.Fatal(err)
	}
	cc, err := a.m.Create(ctx, Request{Names: []string{"nas.lan"}, Source: SourceCA, CAID: ca.ID, Days: 90})
	if err != nil {
		t.Fatal(err)
	}
	cc = wait(t, a.m, cc.ID)
	certPEM, keyPEM := selfSignedPEM(t, 60, "dns.example.org")
	up, err := a.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.w.ExecContext(ctx, `UPDATE certs SET source = 'dns', dns_account = ? WHERE id = ?`, acc.ID, up.ID); err != nil {
		t.Fatal(err)
	}
	accUID, caUID := a.m.uidOf(ctx, "cert_dns_accounts", acc.ID), a.m.uidOf(ctx, "cert_cas", ca.ID)
	if cc.UID == "" || up.UID == "" || accUID == "" || caUID == "" || cc.UID == up.UID {
		t.Fatalf("uids: %q %q %q %q", cc.UID, up.UID, accUID, caUID)
	}
	for _, s := range []string{"dns_accounts " + accUID, "cas " + caUID, "certificates " + cc.UID, "certificates " + up.UID} {
		if !ha.has(s) {
			t.Fatalf("hook %q missing: %v", s, ha.ev)
		}
	}

	// erst nur Zertifikate: die Verweise fehlen auf B
	syncItems(t, a, b, ItemCertificates)
	bc, err := b.m.Get(ctx, b.m.CertIDByUID(ctx, cc.UID))
	if err != nil {
		t.Fatal(err)
	}
	if bc.CAID != 0 || !bc.RefMissing || bc.RenewedBy != "node-a" || bc.Status != StatusValid || bc.UID != cc.UID {
		t.Fatalf("cert on b without CA: %+v", bc)
	}
	if b.m.ForName("nas.lan") == nil || b.m.ForName("dns.example.org") == nil {
		t.Fatal("certificates not usable on b")
	}
	if b.m.renewHere(ctx, bc) {
		t.Fatal("must not renew without the CA")
	}
	var ve *ValidationError
	if err := b.m.Renew(ctx, bc.ID); !errors.As(err, &ve) || ve.Field != "cluster" {
		t.Fatalf("renew without CA: %v", err)
	}
	if !hb.has("certificates " + cc.UID) {
		t.Fatal("apply must report to the cluster (origin comes with ctx)")
	}

	// dann die Bereiche: Verweise zeigen auf B's IDs
	syncItems(t, a, b, ItemDNSAccounts, ItemCAs)
	bc, _ = b.m.Get(ctx, bc.ID)
	bu, _ := b.m.Get(ctx, b.m.CertIDByUID(ctx, up.UID))
	bCA, bAcc := b.m.idOf(ctx, "cert_cas", caUID), b.m.idOf(ctx, "cert_dns_accounts", accUID)
	if bc.CAID != bCA || bCA == ca.ID || bc.RefMissing || bu.DNSAccount != bAcc || bAcc == acc.ID || bu.RefMissing {
		t.Fatalf("refs on b: ca %d/%d acc %d/%d %+v %+v", bc.CAID, bCA, bu.DNSAccount, bAcc, bc, bu)
	}
	if _, vals, err := b.m.dnsAccountRaw(ctx, bAcc); err != nil || vals["token"] != "cf-secret-token" {
		t.Fatalf("dns secret on b: %v %v", vals, err)
	}
	if _, err := b.m.loadCA(ctx, bCA, true); err != nil {
		t.Fatalf("CA key on b: %v", err)
	}
	// zweiter Abgleich legt nichts doppelt an
	syncItems(t, a, b, ItemDNSAccounts, ItemCAs, ItemCertificates)
	var n int
	_ = b.m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs`).Scan(&n)
	if n != 2 {
		t.Fatalf("certs on b: %d", n)
	}

	// Loeschen: Zugang weg -> Verweis leer, keine Erneuerung; Zertifikat weg
	if err := b.m.ClusterApply(ctx, ItemDNSAccounts, accUID, nil, true); err != nil {
		t.Fatal(err)
	}
	if bu, _ = b.m.Get(ctx, bu.ID); bu.DNSAccount != 0 || !bu.RefMissing || !hb.has("dns_accounts "+accUID+" deleted") {
		t.Fatalf("after deleting the dns account: %+v", bu)
	}
	if err := a.m.Delete(ctx, up.ID, false); err != nil {
		t.Fatal(err)
	}
	if !ha.has("certificates " + up.UID + " deleted") {
		t.Fatal("delete not reported")
	}
	if _, found, _ := a.m.ClusterGet(ctx, ItemCertificates, up.UID); found {
		t.Fatal("deleted certificate still found")
	}
	if err := b.m.ClusterApply(ctx, ItemCertificates, up.UID, nil, true); err != nil {
		t.Fatal(err)
	}
	if b.m.CertIDByUID(ctx, up.UID) != 0 || b.m.ForName("dns.example.org") != nil {
		t.Fatal("certificate not deleted on b")
	}
	// Loeschen eines Zugangs auf A wird gemeldet
	if err := a.m.DeleteDNSAccount(ctx, acc.ID); err != nil {
		t.Fatal(err)
	}
	if !ha.has("dns_accounts " + accUID + " deleted") {
		t.Fatal("dns account delete not reported")
	}
}

// Erneuerung: nur die Node, die zuletzt ausgestellt hat; eine andere uebernimmt erst kurz vor Ablauf und wird damit
// zustaendig.
func TestClusterRenewalRule(t *testing.T) {
	ctx := context.Background()
	a, _ := clusterNode(t, "node-a")
	b, hb := clusterNode(t, "node-b")

	day := 24 * time.Hour
	c := &Cert{Source: SourceSelf, hasCert: true, NotAfter: time.Now().Add(20 * day)}
	if !b.m.renewHere(ctx, c) {
		t.Fatal("own certificate")
	}
	c.RenewedBy = "node-a"
	if b.m.renewHere(ctx, c) {
		t.Fatal("other node renews (20 days left)")
	}
	c.NotAfter = time.Now().Add(5 * day)
	if !b.m.renewHere(ctx, c) {
		t.Fatal("takeover expected (5 days left)")
	}
	c.RefMissing = true
	if b.m.renewHere(ctx, c) {
		t.Fatal("no takeover without account/CA")
	}
	c.RefMissing, c.hasCert = false, false
	if b.m.renewHere(ctx, c) {
		t.Fatal("pending certificate belongs to the other node")
	}
	for _, self := range []string{"", "node-a", "node-b", "x"} {
		d := takeoverBefore(&Cert{Source: SourceIPv64}, self)
		if d > 10*day || d <= 9*day {
			t.Fatalf("takeover %s: %v", self, d)
		}
	}
	// ohne Let's-Encrypt-Bedingungen uebernimmt B kein Let's-Encrypt-Zertifikat (es kaeme nur ein Fehler)
	if b.m.canIssue(ctx, &Cert{Source: SourceIPv64}) || !b.m.canIssue(ctx, &Cert{Source: SourceIPv64, ACMECA: 1}) {
		t.Fatal("canIssue")
	}

	cc, err := a.m.Create(ctx, Request{Names: []string{"node.lan"}, Source: SourceSelf, Days: 30})
	if err != nil {
		t.Fatal(err)
	}
	cc = wait(t, a.m, cc.ID)
	syncItems(t, a, b, ItemCertificates)
	bid := b.m.CertIDByUID(ctx, cc.UID)
	bc, _ := b.m.Get(ctx, bid)
	if bc.RenewedBy != "node-a" || b.m.renewHere(ctx, bc) {
		t.Fatalf("b must leave renewal to a: %+v", bc)
	}
	// B stellt aus (von Hand oder Uebernahme): B wird zustaendig, die Aenderung geht an A
	before, _ := b.m.Chain(ctx, bid)
	if err := b.m.Renew(ctx, bid); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		if p, _ := b.m.Chain(ctx, bid); p != before {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	bc = wait(t, b.m, bid)
	if bc.RenewedBy != "" || !hb.has("certificates "+cc.UID) {
		t.Fatalf("b after renewal: %+v", bc)
	}
	syncItems(t, b, a, ItemCertificates)
	ac, _ := a.m.Get(ctx, cc.ID)
	pa, _ := a.m.Chain(ctx, cc.ID)
	pb, _ := b.m.Chain(ctx, bid)
	if ac.RenewedBy != "node-b" || pa != pb || pa == before {
		t.Fatalf("a after b renewed: %+v", ac)
	}
	if a.m.renewHere(ctx, ac) {
		t.Fatal("a must leave renewal to b now")
	}
}

// Gleicher Eintrag auf beiden Seiten mit verschiedener uid (z. B. dieselbe ACME-Stelle zweimal angelegt): beide
// enden bei der kleineren uid, nichts doppelt. Das ACME-Konto geht mit.
func TestClusterMergeAndAccount(t *testing.T) {
	ctx := context.Background()
	a, _ := clusterNode(t, "node-a")
	b, _ := clusterNode(t, "node-b")
	ca2 := newFakeCA(t)
	in := ACMECAInput{Name: "step-ca", Directory: ca2.url("/dir"), AcceptTOS: true}
	xa, err := a.m.AddACMECA(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	xb, err := b.m.AddACMECA(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	ua, ub := a.m.uidOf(ctx, "cert_acme_cas", xa.ID), b.m.uidOf(ctx, "cert_acme_cas", xb.ID)
	if ua == ub {
		t.Fatal("uids must differ")
	}
	if err := a.m.SetAccount(ctx, "ops@example.org", true); err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.accountKey(ctx); err != nil {
		t.Fatal(err)
	}
	syncItems(t, a, b, ItemACME)
	syncItems(t, b, a, ItemACME)
	want := min(ua, ub)
	for _, e := range []*env{a, b} {
		var n int
		var uid string
		_ = e.m.r.QueryRowContext(ctx, `SELECT COUNT(*), MIN(uid) FROM cert_acme_cas`).Scan(&n, &uid)
		if n != 1 || uid != want {
			t.Fatalf("merge: %d %q want %q", n, uid, want)
		}
	}
	acct := b.m.Account(ctx)
	ka, _ := a.box.Decrypt(a.st.SettingOr(ctx, setKey, ""))
	kb, _ := b.box.Decrypt(b.st.SettingOr(ctx, setKey, ""))
	if acct.Email != "ops@example.org" || !acct.TOSAccepted || ka == "" || ka != kb {
		t.Fatalf("account on b: %+v", acct)
	}
}

// Zertifikate, die ein Modul fuer sich haelt (DNS64 mit den IPs dieser Node), bleiben auf der Node.
func TestClusterSkipsOwned(t *testing.T) {
	ctx := context.Background()
	e, h := clusterNode(t, "node-a")
	caPEM, caKey := dns64LikeCA(t)
	ca, err := e.m.EnsureCA(ctx, "DNS64", caPEM, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.m.EnsureIssued(ctx, "dns64", ca.ID, []string{"192.168.10.30"}, 400)
	if err != nil {
		t.Fatal(err)
	}
	ids, _ := e.m.ClusterIDs(ctx, ItemCertificates)
	if slices.Contains(ids, c.UID) || h.has("certificates "+c.UID) {
		t.Fatalf("owned certificate in the cluster: %v %v", ids, h.ev)
	}
	if _, found, err := e.m.ClusterGet(ctx, ItemCertificates, c.UID); found || err != nil {
		t.Fatalf("owned get: %v %v", found, err)
	}
	if ids, _ := e.m.ClusterIDs(ctx, ItemCAs); !slices.Contains(ids, e.m.uidOf(ctx, "cert_cas", ca.ID)) {
		t.Fatal("the CA itself is shared")
	}
	if _, err := e.m.ClusterIDs(ctx, "nope"); !errors.Is(err, ErrClusterItem) {
		t.Fatal("unknown item")
	}
}

// Migration: vorhandene Eintraege bekommen eine uid, neue per Trigger.
func TestClusterMigrationUIDs(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	cm, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", cm); err != nil {
		t.Fatal(err)
	}
	ms, _ := Migrations()
	if err := st.Migrate(ctx, "certs", ms[:4]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := st.Writer().ExecContext(ctx, `INSERT INTO certs (names, source, created_at, updated_at) VALUES (?, 'upload', '', '')`, fmt.Sprintf("n%d.example.org", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Migrate(ctx, "certs", ms); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Writer().ExecContext(ctx, `INSERT INTO certs (names, source, created_at, updated_at) VALUES ('new.example.org', 'upload', '', '')`); err != nil {
		t.Fatal(err)
	}
	var n, distinct int
	_ = st.Reader().QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT uid) FROM certs WHERE length(uid) = 32`).Scan(&n, &distinct)
	if n != 4 || distinct != 4 {
		t.Fatalf("uids: %d %d", n, distinct)
	}
}
