package certs

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// syncRounds: Abgleich in beide Richtungen, mehrmals (wie im Cluster, bis sich nichts mehr aendert).
func syncRounds(t *testing.T, a, b *env, items ...string) {
	t.Helper()
	for i := 0; i < 3; i++ {
		syncItems(t, a, b, items...)
		syncItems(t, b, a, items...)
	}
}

// Genau gleiche Eintraege mit verschiedener uid enden auf beiden Nodes einmal (kleinere uid), Verweise zeigen auf
// den verbliebenen; Aehnliches (gleicher Name, anderer Schluessel bzw. Zugang) bleibt getrennt.
func TestClusterMergeExactDuplicates(t *testing.T) {
	ctx := context.Background()
	a, _ := clusterNode(t, "node-a")
	b, _ := clusterNode(t, "node-b")
	certPEM, keyPEM := selfSignedPEM(t, 60, "dup.example.org")
	caPEM, caKey := dns64LikeCA(t)
	type side struct {
		acc, ca int64
		up      *Cert
	}
	mk := func(e *env, token, name string) side {
		acc := &DNSAccount{Name: name, Provider: "cloudflare"} // anderer Name, derselbe Zugang
		if err := e.m.SaveDNSAccount(ctx, acc, map[string]string{"token": "same-token"}); err != nil {
			t.Fatal(err)
		}
		// gleicher Name und Anbieter, anderer Zugang
		if err := e.m.SaveDNSAccount(ctx, &DNSAccount{Name: "Hetzner", Provider: "hetzner"}, map[string]string{"token": token}); err != nil {
			t.Fatal(err)
		}
		ca, err := e.m.ImportCA(ctx, "Heimnetz", caPEM, caKey)
		if err != nil {
			t.Fatal(err)
		}
		up, err := e.m.Upload(ctx, certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.m.w.ExecContext(ctx, `UPDATE certs SET source = 'dns', dns_account = ? WHERE id = ?`, acc.ID, up.ID); err != nil {
			t.Fatal(err)
		}
		other, otherKey := selfSignedPEM(t, 60, "dup.example.org") // gleiche Namen, anderer Schluessel
		if _, err := e.m.Upload(ctx, other, otherKey); err != nil {
			t.Fatal(err)
		}
		cc, err := e.m.Create(ctx, Request{Names: []string{"nas.lan"}, Source: SourceCA, CAID: ca.ID, Days: 90})
		if err != nil {
			t.Fatal(err)
		}
		wait(t, e.m, cc.ID)
		return side{acc: acc.ID, ca: ca.ID, up: up}
	}
	sa, sb := mk(a, "token-a", "Cloudflare"), mk(b, "token-b", "CF privat")
	wantAcc := min(a.m.uidOf(ctx, "cert_dns_accounts", sa.acc), b.m.uidOf(ctx, "cert_dns_accounts", sb.acc))
	wantCA := min(a.m.uidOf(ctx, "cert_cas", sa.ca), b.m.uidOf(ctx, "cert_cas", sb.ca))
	wantUp := min(sa.up.UID, sb.up.UID)
	if sa.up.UID == sb.up.UID {
		t.Fatal("uids must differ")
	}

	syncRounds(t, a, b, ItemDNSAccounts, ItemCAs, ItemCertificates)

	for name, e := range map[string]*env{"a": a, "b": b} {
		count := func(table string) int {
			var n int
			_ = e.m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&n)
			return n
		}
		if n := count("cert_dns_accounts"); n != 3 {
			t.Fatalf("%s: dns accounts %d (want merged + 2 different)", name, n)
		}
		if n := count("cert_cas"); n != 1 {
			t.Fatalf("%s: cas %d", name, n)
		}
		if n := count("certs"); n != 5 {
			t.Fatalf("%s: certs %d (want dup once + 2 other keys + 2 issued)", name, n)
		}
		accID, caID := e.m.idOf(ctx, "cert_dns_accounts", wantAcc), e.m.idOf(ctx, "cert_cas", wantCA)
		up, err := e.m.Get(ctx, e.m.CertIDByUID(ctx, wantUp))
		if err != nil || accID == 0 || caID == 0 {
			t.Fatalf("%s: survivors missing: %v acc %d ca %d", name, err, accID, caID)
		}
		if up.DNSAccount != accID || up.RefMissing {
			t.Fatalf("%s: dup cert points to %d, want %d: %+v", name, up.DNSAccount, accID, up)
		}
		list, _ := e.m.List(ctx)
		issued := 0
		for _, c := range list {
			if c.Source == SourceCA {
				issued++
				if c.CAID != caID || c.RefMissing {
					t.Fatalf("%s: issued cert points to CA %d, want %d: %+v", name, c.CAID, caID, c)
				}
			}
		}
		if issued != 2 {
			t.Fatalf("%s: issued certs %d", name, issued)
		}
	}
}

// Dieselbe ACME-Stelle mit anderem EAB wird nicht zusammengefuehrt (und nicht ueberschrieben).
func TestClusterACMECADifferentEAB(t *testing.T) {
	ctx := context.Background()
	a, _ := clusterNode(t, "node-a")
	b, _ := clusterNode(t, "node-b")
	ca2 := newFakeCA(t)
	in := ACMECAInput{Name: "step-ca", Directory: ca2.url("/dir"), AcceptTOS: true}
	xa, err := a.m.AddACMECA(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.m.AddACMECA(ctx, in); err != nil {
		t.Fatal(err)
	}
	ua := a.m.uidOf(ctx, "cert_acme_cas", xa.ID)
	data, _, err := a.m.ClusterGet(ctx, ItemACME, ua)
	if err != nil {
		t.Fatal(err)
	}
	var x clusterACME
	_ = json.Unmarshal(data, &x)
	x.EABKID, x.EABHMAC = "kid-a", "aG1hYy1h"
	data, _ = json.Marshal(x)
	var ve *ValidationError
	if err := b.m.ClusterApply(ctx, ItemACME, ua, data, false); !errors.As(err, &ve) {
		t.Fatalf("different EAB must not merge: %v", err)
	}
	var n int
	var kid string
	_ = b.m.r.QueryRowContext(ctx, `SELECT COUNT(*), MAX(eab_kid) FROM cert_acme_cas`).Scan(&n, &kid)
	if n != 1 || kid != "" {
		t.Fatalf("b changed: %d %q", n, kid)
	}
}

// accountData: das Konto einer Node, wie es im Cluster hinausgeht.
func accountData(t *testing.T, e *env) json.RawMessage {
	t.Helper()
	data, found, err := e.m.ClusterGet(context.Background(), ItemACME, clusterAccount)
	if err != nil || !found {
		t.Fatalf("account: %v %v", found, err)
	}
	return data
}

func accountKeyOf(t *testing.T, e *env) string {
	t.Helper()
	k, err := e.box.Decrypt(e.st.SettingOr(context.Background(), setKey, ""))
	if err != nil || k == "" {
		t.Fatalf("account key: %v", err)
	}
	return k
}

func newAccount(t *testing.T, e *env, mail string) {
	t.Helper()
	ctx := context.Background()
	if err := e.m.SetAccount(ctx, mail, true); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.accountKey(ctx); err != nil {
		t.Fatal(err)
	}
}

// ACME-Konto: dasselbe Konto ist keine Abweichung; verschiedene werden nicht ueberschrieben, sondern zur Wahl
// gestellt; nach der Wahl gilt das gewaehlte auf beiden Nodes, ein spaet eintreffendes altes Konto aendert nichts.
func TestClusterACMEAccountChoice(t *testing.T) {
	ctx := context.Background()
	a, _ := clusterNode(t, "node-a")
	b, _ := clusterNode(t, "node-b")
	newAccount(t, a, "a@example.org")

	// B ohne Konto uebernimmt, danach ist es dasselbe
	if err := b.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, a), false); err != nil {
		t.Fatal(err)
	}
	if accountKeyOf(t, a) != accountKeyOf(t, b) {
		t.Fatal("account not adopted")
	}
	if err := a.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, b), false); err != nil || len(a.m.AccountConflicts(ctx)) != 0 {
		t.Fatalf("same account: %v %v", err, a.m.AccountConflicts(ctx))
	}

	// zwei verschiedene Konten
	c, hc := clusterNode(t, "node-c")
	d, _ := clusterNode(t, "node-d")
	newAccount(t, c, "c@example.org")
	newAccount(t, d, "d@example.org")
	kc, kd := accountKeyOf(t, c), accountKeyOf(t, d)
	oldC := accountData(t, c)
	if err := d.m.ClusterApply(ctx, ItemACME, clusterAccount, oldC, false); !errors.Is(err, ErrAccountConflict) {
		t.Fatalf("conflict expected: %v", err)
	}
	if err := c.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, d), false); !errors.Is(err, ErrAccountConflict) {
		t.Fatalf("conflict expected: %v", err)
	}
	if accountKeyOf(t, c) != kc || accountKeyOf(t, d) != kd || c.m.Account(ctx).Email != "c@example.org" || d.m.Account(ctx).Email != "d@example.org" {
		t.Fatal("nothing may be overwritten before the choice")
	}
	list := c.m.AccountConflicts(ctx)
	if len(list) != 2 || !list[0].Own || list[0].Email != "c@example.org" || list[1].Node != "node-d" || list[1].Email != "d@example.org" ||
		list[1].CA == "" || list[1].CreatedAt.IsZero() {
		t.Fatalf("conflicts on c: %+v", list)
	}
	if !hc.has("acme " + clusterAccount) {
		t.Fatal("own account must be announced again on a new conflict")
	}
	if _, err := c.m.ChooseAccount(ctx, "nope"); !errors.Is(err, ErrAccountChoice) {
		t.Fatalf("unknown choice: %v", err)
	}

	// Wahl auf C: das Konto von D gilt
	dropped, err := c.m.ChooseAccount(ctx, list[1].Thumbprint)
	if err != nil || len(dropped) != 1 || dropped[0].Email != "c@example.org" {
		t.Fatalf("choose: %v %+v", err, dropped)
	}
	if accountKeyOf(t, c) != kd || c.m.Account(ctx).Email != "d@example.org" || len(c.m.AccountConflicts(ctx)) != 0 {
		t.Fatal("choice not applied on c")
	}
	if err := d.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, c), false); err != nil {
		t.Fatal(err)
	}
	if accountKeyOf(t, d) != kd || len(d.m.AccountConflicts(ctx)) != 0 {
		t.Fatalf("d after the choice: %+v", d.m.AccountConflicts(ctx))
	}
	// das alte Konto von C kommt spaet noch einmal: bleibt verworfen
	if err := d.m.ClusterApply(ctx, ItemACME, clusterAccount, oldC, false); !errors.Is(err, ErrAccountReplaced) || accountKeyOf(t, d) != kd || len(d.m.AccountConflicts(ctx)) != 0 {
		t.Fatalf("old account again: %v", err)
	}

	// Wahl des eigenen Kontos: die andere Node uebernimmt es
	e, _ := clusterNode(t, "node-e")
	f, _ := clusterNode(t, "node-f")
	newAccount(t, e, "e@example.org")
	newAccount(t, f, "f@example.org")
	ke := accountKeyOf(t, e)
	if err := e.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, f), false); !errors.Is(err, ErrAccountConflict) {
		t.Fatal(err)
	}
	own := e.m.AccountConflicts(ctx)[0]
	if dropped, err := e.m.ChooseAccount(ctx, own.Thumbprint); err != nil || len(dropped) != 1 || dropped[0].Email != "f@example.org" {
		t.Fatalf("choose own: %v %+v", err, dropped)
	}
	if err := f.m.ClusterApply(ctx, ItemACME, clusterAccount, accountData(t, e), false); err != nil {
		t.Fatal(err)
	}
	if accountKeyOf(t, f) != ke || f.m.Account(ctx).Email != "e@example.org" || len(f.m.AccountConflicts(ctx)) != 0 {
		t.Fatal("f must adopt the chosen account")
	}
}
