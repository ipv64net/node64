package certs

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// Sicherung: von Node A nach Node B (anderer Schluessel): Schluessel und Zugangsdaten bleiben lesbar, der Verweis
// Zertifikat -> DNS-Zugang zeigt auf die neue ID, ein zweiter Import legt nichts doppelt an.
func TestBackupRoundTrip(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t, nil)
	acc := &DNSAccount{Name: "Cloudflare", Provider: "cloudflare"}
	if err := a.m.SaveDNSAccount(ctx, acc, map[string]string{"token": "cf-secret-token"}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := selfSignedPEM(t, 30, "backup.example.org")
	c, err := a.m.Upload(ctx, certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.m.w.ExecContext(ctx, `UPDATE certs SET dns_account = ? WHERE id = ?`, acc.ID, c.ID); err != nil {
		t.Fatal(err)
	}
	b, err := a.m.ExportAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b) // wie im Archiv
	if !strings.Contains(string(raw), "cf-secret-token") || !strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("secrets not in the backup")
	}

	nb := newEnv(t, nil) // andere Node, anderer Schluessel; ein eigener Zugang vorher verschiebt die IDs
	if err := nb.m.SaveDNSAccount(ctx, &DNSAccount{Name: "Hetzner", Provider: "hetzner"}, map[string]string{"token": "h"}); err != nil {
		t.Fatal(err)
	}
	var back Backup
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	res, err := nb.m.ImportAll(ctx, &back)
	if err != nil {
		t.Fatal(err)
	}
	if res.Added["certs"] != 1 || res.Added["cert_dns_accounts"] != 1 {
		t.Fatalf("import: %+v", res)
	}
	newID := res.CertIDs[c.ID]
	bb, err := nb.m.Bundle(ctx, newID)
	if err != nil || !strings.Contains(bb.KeyPEM, "PRIVATE KEY") {
		t.Fatalf("key on node B: %v", err)
	}
	got, err := nb.m.Get(ctx, newID)
	if err != nil {
		t.Fatal(err)
	}
	accB, vals, err := nb.m.dnsAccountRaw(ctx, got.DNSAccount)
	if err != nil || accB.Name != "Cloudflare" || vals["token"] != "cf-secret-token" {
		t.Fatalf("dns account on node B: %+v %v %v", accB, vals, err)
	}
	if nb.m.ForName("backup.example.org") == nil { // im Speicher, ohne Neustart
		t.Fatal("imported certificate not loaded")
	}
	nb.m.mu.Lock()
	held, loop := nb.m.holds[holdSelf], nb.m.stopLp != nil
	nb.m.mu.Unlock()
	if !held || !loop { // vorher ohne Zertifikate: Erneuerung muss jetzt laufen
		t.Fatalf("renewal not started after import: held %v loop %v", held, loop)
	}
	res2, err := nb.m.ImportAll(ctx, &back)
	if err != nil || len(res2.Added) != 0 || res2.Skipped["certs"] != 1 || res2.CertIDs[c.ID] != newID {
		t.Fatalf("second import: %+v %v", res2, err)
	}
	if _, err := nb.m.ImportAll(ctx, &Backup{Version: 99}); err == nil {
		t.Fatal("unknown version accepted")
	}
}
