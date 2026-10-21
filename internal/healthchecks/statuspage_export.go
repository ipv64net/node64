package healthchecks

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ipv64net/node64/internal/module"
)

// Export/Import der Statusseiten (Teil des Healthchecks-Exports): Seite mit Gruppen, Eintraegen und Logo. Der
// Passwort-Hash einer geschuetzten Seite nur beim Export mit Passwort (verschluesselt); ohne ihn wird eine
// geschuetzte Seite ausgeschaltet angelegt, damit sie nicht ungeschuetzt erreichbar ist. Ankuendigungen sind
// Verlauf dieser Node und fehlen.

type statusExportPage struct {
	StatusPage
	PasswordHash string `json:"password_hash,omitempty"` // nur mit Export-Passwort, verschluesselt
	Logo         []byte `json:"logo,omitempty"`          // base64 im JSON
	LogoType     string `json:"logo_type,omitempty"`
}

func (m *Module) statusExport(ctx context.Context) ([]statusExportPage, error) {
	list, err := m.st.StatusPages(ctx)
	if err != nil {
		return nil, err
	}
	seal := module.SecretSealerOf(ctx)
	out := []statusExportPage{}
	for _, x := range list {
		p, err := m.st.StatusPage(ctx, x.ID)
		if err != nil {
			return nil, err
		}
		e := statusExportPage{StatusPage: *p}
		e.Password = ""
		if h := m.st.statusPasswordHash(ctx, p.ID); h != "" && seal != nil {
			e.PasswordHash = seal.Encrypt(h)
		}
		if data, ctype, _, err := m.st.StatusLogo(ctx, p.ID); err == nil && data != nil {
			e.Logo, e.LogoType = data, ctype
		}
		out = append(out, e)
	}
	return out, nil
}

// statusImport legt Seiten an bzw. ersetzt sie (gleicher Slug) samt Gruppen; ein mitgeliefertes Logo wird
// uebernommen, ein vorhandenes bleibt sonst. Die Checks der Eintraege kommen vorher mit dem Import (gleicher Token).
func (m *Module) statusImport(ctx context.Context, in []statusExportPage) (int, error) {
	seal := module.SecretSealerOf(ctx)
	n := 0
	var problems []string
	for _, x := range in {
		p := x.StatusPage
		p.ID, p.Password = 0, ""
		if old, err := m.st.StatusPageBySlug(ctx, p.Slug); err == nil {
			p.ID = old.ID
		} else if !errors.Is(err, ErrStatusPageNotFound) {
			return n, err
		}
		hash := ""
		if x.PasswordHash != "" && seal != nil {
			if plain, err := seal.Decrypt(x.PasswordHash); err == nil {
				hash = plain
			}
		}
		if p.HasPassword && hash == "" && (p.ID == 0 || m.st.statusPasswordHash(ctx, p.ID) == "") {
			p.Enabled = false // geschuetzt, aber ohne Hash: nicht offen anlegen
			problems = append(problems, p.Slug+": password not in the export (export with password) – page switched off, set a password on the node")
		}
		if err := m.st.SaveStatusPage(ctx, &p, hash); err != nil {
			problems = append(problems, p.Slug+": "+err.Error())
			continue
		}
		n++
		if len(x.Logo) > 0 {
			if err := m.st.SetStatusLogo(ctx, p.ID, x.Logo, x.LogoType); err != nil {
				problems = append(problems, p.Slug+" logo: "+err.Error())
			}
		}
	}
	if len(problems) > 0 {
		return n, fmt.Errorf("status pages: %s", strings.Join(problems, "; "))
	}
	return n, nil
}
