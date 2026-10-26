package healthchecks

import (
	"context"
	"strings"

	"github.com/ipv64net/node64/internal/module"
)

// Dashboard: Kachelzeilen fuer Proxmox VE und Docker unter den Healthchecks (nur mit eingerichteten Systemen).
// Ein System zaehlt nur mit eigenem Problem (nicht erreichbar, Node offline, Quorum weg) als gestoert; gestoerte
// Gaeste bzw. Container stehen allein in ihrer Kachel (sonst doppelt gezaehlt).

// BoardGroups liefert die Zeilen Proxmox VE und Docker fuer die Dashboard-Karte.
func (m *Module) BoardGroups(ctx context.Context) []module.BoardGroup {
	if m.pve == nil {
		return nil
	}
	list, err := m.pve.st.Systems(ctx)
	if err != nil || len(list) == 0 {
		return nil
	}
	var out []module.BoardGroup
	for _, docker := range []bool{false, true} {
		var ok, bad, running, guestsBad int
		var errs []string
		n := 0
		for _, sys := range list {
			if sys.IsDocker() != docker {
				continue
			}
			n++
			row := m.pveSysView(ctx, sys)
			switch {
			case row.SysProblem:
				bad++
				if row.Error != "" {
					errs = append(errs, sys.Name+": "+row.Error)
				}
			case row.State == "ok" || row.State == "warn": // warn ohne eigenes Problem: nur Gaeste gestoert
				ok++
			}
			running += row.Running
			guestsBad += row.Bad
		}
		if n == 0 {
			continue
		}
		g := module.BoardGroup{TitleKey: "nav.proxmox", Icon: "bi-hdd-rack", Path: pvePath, Tiles: []module.BoardTile{
			{LabelKey: "pve.card.systems_ok", Value: ok, Kind: "ok", Icon: "bi-hdd-rack"},
			{LabelKey: "pve.card.systems_bad", Value: bad, Kind: "down", Icon: "bi-exclamation-triangle"},
			{LabelKey: "pve.card.guests_running", Value: running, Kind: "info", Icon: "bi-play-circle"},
			{LabelKey: "pve.card.guests_bad", Value: guestsBad, Kind: "down", Icon: "bi-x-octagon"},
		}}
		last := pveSettingLast
		if docker {
			g = module.BoardGroup{TitleKey: "nav.docker", Icon: "bi-box-seam", Path: dockerPath, Tiles: []module.BoardTile{
				{LabelKey: "docker.card.hosts_ok", Value: ok, Kind: "ok", Icon: "bi-box-seam"},
				{LabelKey: "docker.card.hosts_bad", Value: bad, Kind: "down", Icon: "bi-exclamation-triangle"},
				{LabelKey: "docker.card.running", Value: running, Kind: "info", Icon: "bi-play-circle"},
				{LabelKey: "docker.card.bad", Value: guestsBad, Kind: "down", Icon: "bi-x-octagon"},
			}}
			last = dockerSettingLast
		}
		if inc := m.lastIncident(ctx, last); inc != nil {
			g.Last, g.LastAt, g.LastWhat = inc.Name, inc.Time, inc.What
		}
		g.Err = strings.Join(errs, " · ")
		out = append(out, g)
	}
	return out
}
