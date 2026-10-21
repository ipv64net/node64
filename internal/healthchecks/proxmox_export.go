package healthchecks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/proxmox"
	"github.com/ipv64net/node64/internal/store"
)

// Export/Import der Proxmox-Systeme (Teil des Healthchecks-Exports): Systeme mit Einstellungen und Regeln, das
// Token-Secret nur beim Export mit Passwort (verschluesselt). Ohne Secret wird ein System abgeschaltet angelegt und
// zeigt „Secret fehlt“ – nach dem Eintragen laeuft es. Verlauf und Zustand gehoeren zur Node und fehlen.

type pveExportSystem struct {
	ID        int64               `json:"id"` // ID in der Quelle (Zuordnung der Checks „als Check“)
	Name      string              `json:"name"`
	Addresses []string            `json:"addresses"`
	TokenID   string              `json:"token_id"`
	Secret    string              `json:"secret,omitempty"` // nur mit Export-Passwort, verschluesselt
	PinSHA256 string              `json:"pin_sha256,omitempty"`
	Interval  int                 `json:"interval"`
	Enabled   bool                `json:"enabled"`
	Settings  []*proxmox.Settings `json:"settings"`
}

func (m *Module) pveExport(ctx context.Context) ([]pveExportSystem, error) {
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil, err
	}
	seal := module.SecretSealerOf(ctx)
	out := []pveExportSystem{}
	for _, sys := range list {
		x := pveExportSystem{ID: sys.ID, Name: sys.Name, Addresses: sys.Addresses, TokenID: sys.TokenID, PinSHA256: sys.PinSHA256,
			Interval: sys.Interval, Enabled: sys.Enabled, Settings: []*proxmox.Settings{}}
		if seal != nil && sys.Secret != "" {
			x.Secret = seal.Encrypt(sys.Secret)
		}
		if set, err := m.pve.st.Settings(ctx, sys.ID); err == nil {
			for _, it := range set.Items {
				if it.Muted || it.AsCheck || it.ExpectRunning != nil || it.Rules != (proxmox.RuleSet{}) {
					c := *it
					c.SeenRunning = false
					x.Settings = append(x.Settings, &c)
				}
			}
		}
		out = append(out, x)
	}
	return out, nil
}

// pveImport legt Systeme an bzw. aktualisiert sie (gleicher Name) und uebernimmt die Einstellungen. Checks „als
// Check“ (schon mit den Checks importiert) zeigen danach auf die System-ID dieser Node.
func (m *Module) pveImport(ctx context.Context, in []pveExportSystem) (int, error) {
	if len(in) == 0 {
		return 0, nil
	}
	existing, err := m.pve.st.Systems(ctx)
	if err != nil {
		return 0, err
	}
	// Zuordnung ueber den Namen (nicht eindeutig, Standard ist der erste Node, z. B. „pve“): gleichnamige vorhandene
	// Systeme werden ueber die Adressen unterschieden; passt keins eindeutig oder zielen mehrere Eintraege auf dasselbe
	// System, wird neu angelegt statt zusammengelegt.
	byName := map[string][]*proxmox.System{}
	for _, s := range existing {
		byName[strings.ToLower(s.Name)] = append(byName[strings.ToLower(s.Name)], s)
	}
	match := make([]int64, len(in))
	hits := map[int64]int{}
	for i, x := range in {
		cands := byName[strings.ToLower(x.Name)]
		if len(cands) > 1 {
			var same []*proxmox.System
			for _, c := range cands {
				if proxmox.SameEndpoint(&proxmox.System{Addresses: c.Addresses}, &proxmox.System{Addresses: x.Addresses}) {
					same = append(same, c)
				}
			}
			cands = same
		}
		if len(cands) == 1 {
			match[i] = cands[0].ID
			hits[cands[0].ID]++
		}
	}
	seal := module.SecretSealerOf(ctx)
	n := 0
	var problems []string
	for i, x := range in {
		secret := ""
		if x.Secret != "" && seal != nil {
			if plain, err := seal.Decrypt(x.Secret); err == nil {
				secret = plain
			}
		}
		sys := &proxmox.System{Name: x.Name, Addresses: x.Addresses, TokenID: x.TokenID, Secret: secret, PinSHA256: x.PinSHA256,
			Interval: x.Interval, Enabled: x.Enabled}
		if id := match[i]; id != 0 && hits[id] == 1 {
			sys.ID = id
		}
		switch {
		case m.pve.box == nil:
			problems = append(problems, x.Name+": "+proxmox.ErrNoBox.Error())
			continue
		case sys.ID != 0 || secret != "":
			if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
				problems = append(problems, x.Name+": "+err.Error())
				continue
			}
		default: // ohne Secret: abgeschaltet anlegen, Secret muss eingetragen werden
			if err := m.pveInsertNoSecret(ctx, sys); err != nil {
				problems = append(problems, x.Name+": "+err.Error())
				continue
			}
			problems = append(problems, x.Name+": token secret not in the export (export with password) – enter it on the node")
		}
		n++
		for _, it := range x.Settings {
			if it == nil || !proxmox.ValidKey(it.Key) {
				continue
			}
			st := *it
			st.SystemID = sys.ID
			if st.Rules.Channels != nil { // Kanal-IDs wie bei Checks auf die Kanaele dieser Node umschreiben
				ids := module.MapChannels(ctx, *st.Rules.Channels)
				st.Rules.Channels = &ids
			}
			if st.AsCheck {
				st.AsCheck = false
				if c, _ := m.st.Check(ctx, st.CheckToken); c != nil && c.Type == checks.TypeProxmox {
					var p checks.ProxmoxParams
					if json.Unmarshal(c.Params, &p) == nil && p.SystemID != sys.ID {
						p.SystemID = sys.ID
						c.Params, _ = json.Marshal(p)
						c.UpdatedBy = "import"
						if err := m.st.Update(ctx, c); err != nil {
							problems = append(problems, x.Name+": "+err.Error())
						}
					}
					st.AsCheck = true
				} else {
					st.CheckToken = ""
				}
			}
			if err := m.pve.st.SaveSettings(ctx, &st); err != nil {
				problems = append(problems, x.Name+" "+it.Key+": "+err.Error())
			}
		}
		// wie beim Speichern: abgeschaltet → Abfrage beenden, Stand verwerfen; Checks pausiert, solange abgeschaltet
		if !sys.Enabled {
			m.pveHalt(sys.ID)
			m.pveForget(ctx, sys.ID)
		}
		m.pveSyncChecks(ctx, sys, "import", true)
		if m.scheduler() != nil { // laeuft: Abfrage gleich (neu) starten
			if sys.Enabled {
				m.pveReload(ctx, sys.ID)
			}
			if s := m.scheduler(); s != nil {
				for _, c := range m.pveSystemChecks(ctx, sys.ID) {
					upsertSched(s, c, nil)
				}
			}
		}
	}
	if len(problems) > 0 {
		return n, fmt.Errorf("proxmox: %s", strings.Join(problems, "; "))
	}
	return n, nil
}

// pveInsertNoSecret legt ein System ohne Secret abgeschaltet an (Import ohne Passwort).
func (m *Module) pveInsertNoSecret(ctx context.Context, sys *proxmox.System) error {
	if err := proxmox.ValidateSystem(sys, false); err != nil {
		return err
	}
	addrs, _ := json.Marshal(sys.Addresses)
	now := store.Now()
	sys.Enabled = false
	res, err := m.core.Writer().ExecContext(ctx, `INSERT INTO pve_systems (name, addresses, token_id, secret, pin_sha256, interval_sec, enabled,
		created_at, updated_at) VALUES (?,?,?,'',?,?,0,?,?)`, sys.Name, string(addrs), sys.TokenID, sys.PinSHA256, sys.Interval, now, now)
	if err != nil {
		return err
	}
	sys.ID, _ = res.LastInsertId()
	return nil
}
