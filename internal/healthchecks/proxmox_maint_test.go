package healthchecks

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/proxmox"
)

// Node offline: System teilweise gestoert. „Offline ist richtig“ (Wartung) nimmt den Node aus dem Systemzustand, der
// Knopf geht in beide Richtungen (auch in der Node-Liste der Systemseite).
func TestPVENodeMaintenanceSystemState(t *testing.T) {
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	m, srv, _ := newPVEModule(t, pveCore(t), pveBox(t, 1))
	ctx := context.Background()
	id := pveCreate(t, srv, fsrv)
	sp := pveResPath(id, "")
	sys := &proxmox.System{ID: id, Enabled: true}
	fake.set("node/pve2", "status", "offline")
	pvePollNow(t, m, id)
	if row := m.pveSysView(ctx, sys); !row.SysProblem || row.NodesMissing() != 1 || row.State != "warn" {
		t.Fatalf("offline: %s %v missing=%d", row.State, row.SysProblem, row.NodesMissing())
	}
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"node/pve2"}, "back": {sp}}); resp.StatusCode != 303 {
		t.Fatalf("ack: %d", resp.StatusCode)
	}
	row := m.pveSysView(ctx, sys)
	if row.SysProblem || row.NodesMaint != 1 || row.NodesMissing() != 0 {
		t.Fatalf("Wartung: %s %v maint=%d missing=%d", row.State, row.SysProblem, row.NodesMaint, row.NodesMissing())
	}
	if _, body := pveGet(t, srv, sp); !strings.Contains(body, `name="key" value="node/pve2"><input type="hidden" name="undo" value="1">`) {
		t.Fatalf("Zuruecknehmen fehlt in der Node-Liste: %s", body)
	}
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"node/pve2"}, "undo": {"1"}, "back": {sp}}); resp.StatusCode != 303 {
		t.Fatalf("undo: %d", resp.StatusCode)
	}
	if row := m.pveSysView(ctx, sys); !row.SysProblem || row.NodesMaint != 0 {
		t.Fatalf("zurueckgenommen: %v maint=%d", row.SysProblem, row.NodesMaint)
	}
	// Gast: „gestoppt ist richtig“ laesst sich ebenso zuruecknehmen
	pvePost(t, srv, sp+"/ack", url.Values{"key": {"qemu/101"}, "back": {sp}})
	if resp, _ := pvePost(t, srv, sp+"/ack", url.Values{"key": {"qemu/101"}, "undo": {"1"}, "back": {sp}}); resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("X-Flash"), "success:pve.ack.undone") {
		t.Fatalf("Gast undo: %d %v", resp.StatusCode, resp.Header)
	}
	if set, _ := m.pve.st.Settings(ctx, id); set.Item("qemu/101").ExpectRunning != nil {
		t.Fatalf("Gast undo: %+v", set.Item("qemu/101"))
	}
}
