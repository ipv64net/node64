package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// boardModule: Modul mit Checks und einer Kachelzeile (wie Healthchecks mit Proxmox VE).
type boardModule struct{ pingModule }

func (boardModule) Info() module.Info {
	return module.Info{Name: "board", TitleKey: "nav.healthchecks", Path: "/board", Available: true}
}
func (boardModule) Dashboard(context.Context) (*module.DashboardInfo, error) {
	return &module.DashboardInfo{Module: "board", TitleKey: "nav.healthchecks", Path: "/board", OK: 3}, nil
}
func (boardModule) BoardGroups(context.Context) []module.BoardGroup {
	return []module.BoardGroup{{TitleKey: "nav.proxmox", Icon: "bi-hdd-rack", Path: "/board/pve", Err: "lab: nicht erreichbar",
		Last: "vm-101", LastAt: time.Now().Add(-time.Hour), Tiles: []module.BoardTile{
			{LabelKey: "pve.card.systems_ok", Value: 2, Kind: "ok", Icon: "bi-hdd-rack"},
			{LabelKey: "pve.card.guests_bad", Value: 7, Kind: "down", Icon: "bi-x-octagon", Path: "/board/pve?state=bad"}}}}
}

// Kachelzeilen unter den Checks: Titel mit Link, Kacheln mit Wert und Link, Hinweis und letzte Stoerung.
func TestDashboardBoardGroups(t *testing.T) {
	a := newTestAppWith(t, boardModule{})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, "board", true)
	a.registry.StartEnabled(ctx)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	resp, body := a.get(t, "/")
	if resp.StatusCode != 200 {
		t.Fatalf("dashboard: %d", resp.StatusCode)
	}
	for _, want := range []string{"Proxmox VE", `href="/board/pve"`, `class="card stat stat-ok" href="/board/pve"`, "Systeme ok", `<div class="stat-value">2</div>`,
		`href="/board/pve?state=bad"`, `<div class="stat-value">7</div>`, "lab: nicht erreichbar", "Letzte Störung: vm-101"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard misses %q", want)
		}
	}
}
