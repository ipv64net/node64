package healthchecks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/scheduler"
)

// Export/Import der Konfiguration (module.Exporter). Messdaten sind nicht
// enthalten, nur Checks, Wartungsfenster und Proxmox-Systeme (proxmox_export.go).

type exportFile struct {
	Checks      []checkJSON       `json:"checks"`
	Maintenance []Maintenance     `json:"maintenance"`
	Proxmox     []pveExportSystem `json:"proxmox,omitempty"`
}

func (m *Module) Export(ctx context.Context) (any, error) {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return nil, err
	}
	out := exportFile{Checks: []checkJSON{}, Maintenance: []Maintenance{}}
	for _, c := range list {
		j := checkJSON{Token: c.Token, Name: c.Name, Type: string(c.Type), Target: c.Target, Params: c.Params, Tags: c.Tags, Description: c.Description,
			IPMode: string(c.IPMode), Execution: c.Execution, Policy: c.Policy, Locations: c.Locations, Channels: c.Channels, Nodes: c.Nodes}
		group := c.Group
		j.Group = &group
		iv, riv, re, st, rp := int(c.Interval.Seconds()), int(c.RetryInterval.Seconds()), c.Retries, c.Stabilize, c.RepeatMinutes
		ct, tt := c.ConnectTimeout.Seconds(), c.TotalTimeout.Seconds()
		inv, pa, cr, nd, nu, parent, ndeg := c.Invert, c.Paused, c.Critical, c.NotifyDown, c.NotifyUp, c.Parent, c.NotifyDegraded
		j.NotifyDegraded = &ndeg
		j.IntervalSeconds, j.RetryIntervalSeconds, j.Retries, j.Stabilize, j.RepeatMinutes = &iv, &riv, &re, &st, &rp
		j.ConnectTimeoutSeconds, j.TimeoutSeconds = &ct, &tt
		j.Invert, j.Paused, j.Critical, j.NotifyDown, j.NotifyUp, j.Parent = &inv, &pa, &cr, &nd, &nu, &parent
		if j.Tags == nil {
			j.Tags = []string{}
		}
		if j.Channels == nil {
			j.Channels = []int64{}
		}
		if j.Locations == nil {
			j.Locations = []string{}
		}
		out.Checks = append(out.Checks, j)
	}
	if mw, err := m.st.MaintenanceList(ctx); err == nil && mw != nil {
		out.Maintenance = mw
	}
	px, err := m.pveExport(ctx)
	if err != nil {
		return nil, err
	}
	if len(px) > 0 {
		out.Proxmox = px
	}
	return out, nil
}

// Import legt Checks an oder aktualisiert sie anhand des Tokens; Wartungs-
// fenster werden ueber den Namen abgeglichen. Liefert die Anzahl Aenderungen.
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var in exportFile
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, fmt.Errorf("healthchecks: %w", err)
	}
	n := 0
	// Erst alle ohne Parent anlegen, damit Abhaengigkeiten aufloesbar sind
	for pass := 0; pass < 2; pass++ {
		for _, j := range in.Checks {
			hasParent := j.Parent != nil && *j.Parent != ""
			if (pass == 0) == hasParent {
				continue
			}
			var c *Check
			if tokenRe.MatchString(j.Token) {
				c, _ = m.st.Check(ctx, j.Token)
			}
			create := c == nil
			if create {
				c = &Check{Token: j.Token}
				if !tokenRe.MatchString(c.Token) {
					c.Token = NewToken()
				}
			}
			c.UpdatedBy = "import"
			j.Channels = module.MapChannels(ctx, j.Channels)
			if err := m.apply(c, j, create); err != nil {
				return n, fmt.Errorf("check %q: %w", j.Name, err)
			}
			if c.Parent != "" {
				if p, _ := m.st.Check(ctx, c.Parent); p == nil {
					c.Parent = ""
				}
			}
			var err error
			if create {
				err = m.st.Insert(ctx, c)
			} else {
				err = m.st.Update(ctx, c)
			}
			if err != nil {
				return n, err
			}
			n++
			if s := m.scheduler(); s != nil {
				if nc, _ := m.st.Check(ctx, c.Token); nc != nil {
					var rt *scheduler.Runtime
					if !create {
						if live, ok := s.Runtime(c.Token); ok {
							rt = &live
						}
					}
					upsertSched(s, nc, rt)
				}
			}
		}
	}
	existing, _ := m.st.MaintenanceList(ctx)
	byName := map[string]Maintenance{}
	for _, x := range existing {
		byName[x.Name] = x
	}
	for _, mw := range in.Maintenance {
		if mw.Name == "" || !mw.EndAt.After(mw.StartAt) {
			continue
		}
		if mw.Repeat == "" {
			mw.Repeat = "none"
		}
		var tokens []string
		for _, t := range mw.Tokens {
			if tokenRe.MatchString(t) {
				tokens = append(tokens, t)
			}
		}
		mw.Tokens = tokens
		if old, ok := byName[mw.Name]; ok {
			mw.ID = old.ID
			if err := m.st.MaintenanceUpdate(ctx, &mw); err != nil {
				return n, err
			}
		} else {
			mw.CreatedAt = time.Now()
			if err := m.st.MaintenanceInsert(ctx, &mw); err != nil {
				return n, err
			}
		}
		n++
	}
	k, err := m.pveImport(ctx, in.Proxmox)
	return n + k, err
}

var _ = checks.TypePush
