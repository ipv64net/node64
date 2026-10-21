package healthchecks

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/module"
)

// Statusseiten ziehen mit Export/Import um: Gruppen, Eintraege und Logo; der Passwort-Hash nur mit Export-Passwort,
// sonst wird eine geschuetzte Seite ausgeschaltet angelegt.
func TestStatusPagesExportImport(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestModule(t)
	logo := []byte("\x89PNG\r\n\x1a\nlogo")
	p := &StatusPage{Slug: "lab", Title: "Labor", Enabled: true, Layout: "tiles", Groups: []StatusGroup{{Name: "Web", Items: []StatusItem{{Token: "abc", Label: "Seite"}}}}}
	if err := m.st.SaveStatusPage(ctx, p, "$2a$10$hash"); err != nil {
		t.Fatal(err)
	}
	if err := m.st.SetStatusLogo(ctx, p.ID, logo, "image/png"); err != nil {
		t.Fatal(err)
	}
	export := func(ctx context.Context) []byte {
		data, err := m.Export(ctx)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(data)
		return raw
	}

	// ohne Passwort: kein Hash in der Datei, Seite kommt ausgeschaltet an
	raw := export(ctx)
	if !strings.Contains(string(raw), `"status_pages":[`) || strings.Contains(string(raw), "$2a$") {
		t.Fatalf("export: %s", raw)
	}
	m2, _ := newTestModule(t)
	if _, err := m2.Import(ctx, raw); err == nil || !strings.Contains(err.Error(), "password not in the export") {
		t.Fatalf("import without password: %v", err)
	}
	got, err := m2.st.StatusPageBySlug(ctx, "lab")
	if err != nil || got.Enabled || got.Title != "Labor" || got.Layout != "tiles" || len(got.Groups) != 1 || got.Groups[0].Items[0].Token != "abc" {
		t.Fatalf("imported page: %+v %v", got, err)
	}
	if data, ctype, _, _ := m2.st.StatusLogo(ctx, got.ID); !bytes.Equal(data, logo) || ctype != "image/png" {
		t.Fatalf("logo: %q %s", data, ctype)
	}

	// mit Passwort: Hash verschluesselt dabei, Seite bleibt eingeschaltet und geschuetzt
	seal := pveBox(t, 9)
	sctx := module.WithSecretSealer(ctx, seal)
	raw = export(sctx)
	if strings.Contains(string(raw), "$2a$") || !strings.Contains(string(raw), `"password_hash":"enc:`) {
		t.Fatalf("export with password: %s", raw)
	}
	m3, _ := newTestModule(t)
	if _, err := m3.Import(sctx, raw); err != nil {
		t.Fatalf("import with password: %v", err)
	}
	got, _ = m3.st.StatusPageBySlug(ctx, "lab")
	if got == nil || !got.Enabled || m3.st.statusPasswordHash(ctx, got.ID) != "$2a$10$hash" {
		t.Fatalf("imported with password: %+v", got)
	}
	// erneuter Import: dieselbe Seite (Slug), keine zweite
	if _, err := m3.Import(sctx, raw); err != nil {
		t.Fatal(err)
	}
	if list, _ := m3.st.StatusPages(ctx); len(list) != 1 {
		t.Fatalf("pages after second import: %d", len(list))
	}
}
