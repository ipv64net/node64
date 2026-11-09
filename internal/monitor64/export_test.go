package monitor64

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/module"
)

type rot13 struct{}

func (rot13) Encrypt(p string) string { return "S:" + p }
func (rot13) Decrypt(v string) (string, error) {
	return strings.TrimPrefix(v, "S:"), nil
}

func TestExportImportRoundTrip(t *testing.T) {
	ctx := context.Background()
	src, _, _ := newTestModule(t)
	by := Actor{Kind: "user", Name: "dennis"}
	h := &Host{Name: "nas01", Address: "10.0.0.20", Group: "Keller", Tags: []string{"NAS", "backup"}, IntervalSec: 60}
	if err := src.store.SaveHost(ctx, h, by); err != nil {
		t.Fatal(err)
	}
	if err := src.store.SaveAccess(ctx, &Access{HostUID: h.UID, Type: "ssh", Config: []byte(`{"user":"monitor64"}`), Secret: src.box.Encrypt("geheim"), Enabled: true}, false, by); err != nil {
		t.Fatal(err)
	}
	if _, err := src.PublicKeyLine(ctx); err != nil { // Schluessel der Node anlegen
		t.Fatal(err)
	}
	// ohne Passwort: keine Geheimnisse im Export
	plain, err := src.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(plain)
	if strings.Contains(string(b), "geheim") || strings.Contains(string(b), "PRIVATE KEY") || strings.Contains(string(b), `"node_key"`) {
		t.Fatal("secret in export without password")
	}
	// mit Passwort: verschluesselt dabei, Import auf anderer Node
	sctx := module.WithSecretSealer(ctx, rot13{})
	sealed, err := src.Export(sctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed)
	dst, _, _ := newTestModule(t)
	n, err := dst.Import(sctx, raw)
	if err != nil || n != 2 {
		t.Fatalf("import n=%d err=%v", n, err)
	}
	hosts, _ := dst.store.Hosts(ctx)
	if len(hosts) != 1 || hosts[0].Name != "nas01" || strings.Join(hosts[0].Tags, ",") != "nas,backup" {
		t.Fatalf("hosts after import: %+v", hosts)
	}
	accs, _ := dst.store.Accesses(ctx, hosts[0].UID)
	if len(accs) != 1 {
		t.Fatal("access missing")
	}
	if p, err := dst.box.Decrypt(accs[0].Secret); err != nil || p != "geheim" {
		t.Fatalf("secret after import: %q %v", p, err)
	}
	l1, _ := src.PublicKeyLine(ctx)
	l2, _ := dst.PublicKeyLine(ctx)
	if strings.Fields(l1)[1] != strings.Fields(l2)[1] {
		t.Fatal("node key not imported")
	}
}
