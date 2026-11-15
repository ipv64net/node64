package apis

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

// qemu_1.json ohne VM 101 (auf pve2 migriert)
const qemuWithout101 = `[
  {"vmid":102,"name":"win11","status":"stopped","cpu":0,"cpus":4,"mem":0,"maxmem":8589934592,"disk":0,"maxdisk":68719476736,"netin":0,"netout":0,"diskread":0,"diskwrite":0,"uptime":0},
  {"vmid":103,"name":"test","status":"stopped","cpus":1,"maxmem":1073741824,"maxdisk":8589934592,"uptime":0,"tags":"nomonitor"},
  {"vmid":104,"name":"db01","status":"stopped","lock":"backup","cpus":2,"maxmem":4294967296,"maxdisk":34359738368,"uptime":0}
]`

// /cluster/resources?type=vm nach der Migration: VM 101 laeuft auf pve2 (Zaehler weiter gestiegen), CT 200 auf pve1
const resourcesMoved = `[
  {"id":"qemu/101","type":"qemu","vmid":101,"name":"web01","node":"pve2","status":"running","cpu":0.05,"maxcpu":2,"mem":2147483648,"maxmem":4294967296,"disk":0,"maxdisk":34359738368,"netin":1075000000,"netout":537500000,"diskread":2000000000,"diskwrite":3000000000,"uptime":86460,"template":0,"tags":"prod;web","hastate":"started"},
  {"id":"qemu/102","type":"qemu","vmid":102,"name":"win11","node":"pve1","status":"stopped","maxcpu":4,"maxmem":8589934592,"maxdisk":68719476736,"template":0},
  {"id":"lxc/200","type":"lxc","vmid":200,"name":"pihole","node":"pve1","status":"running","cpu":0.0051,"maxcpu":1,"mem":134217728,"maxmem":536870912,"disk":1073741824,"maxdisk":8589934592,"uptime":3600,"template":0},
  {"id":"qemu/9000","type":"qemu","vmid":9000,"name":"debian-tpl","node":"pve2","status":"stopped","template":1}
]`

// #165: Ein uebernommener Gast, der auf eine andere Node migriert ist, kommt mit den Werten aus dem Cluster und der
// neuen Node zurueck (Zaehler laufen weiter); geloescht fehlt er; ohne Antwort des Clusters ist es ein Teilfehler nur
// fuer ihn. Nicht uebernommene Gaeste werden nicht gesucht.
func TestPVEFollowMoved(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	cfg.Seen, cfg.Tag = &ClusterSeen{}, "acc-pve1"
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)
	p.Follow([]string{"vm:101", "vm:102", "ct:200", "cpu", "store:local"})
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/cluster/resources?type=vm"); n != 0 {
		t.Fatalf("Cluster abgefragt, obwohl alle Gaeste da sind (%d)", n)
	}
	if cl, known := cfg.Seen.ClusterOf("acc-pve1"); !known || cl != "homelab" || p.Cluster() != "homelab" {
		t.Errorf("Cluster des Zugangs: %q %v / %q", cl, known, p.Cluster())
	}

	// Migration nach pve2
	f.ok("/nodes/pve1/qemu?full=1", qemuWithout101)
	f.ok("/cluster/resources?type=vm", resourcesMoved)
	f.ok("/nodes/pve2/qemu/101/config", `{"onboot":1}`)
	now = now.Add(time.Minute)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect nach Migration: %v", deErr(err))
	}
	vm := svcByKey(t, svcs, "vm:101")
	if vm.MovedTo != "pve2" || vm.Name != "web01 (VM 101)" || len(vm.Facts) != 0 || mustMetric(t, vm, "running").Value != 1 {
		t.Fatalf("vm:101 auf pve2 = %+v", vm)
	}
	if txt := de(vm.Text); !strings.Contains(txt, "läuft auf Node pve2") || !strings.Contains(txt, "soll laufen (HA)") {
		t.Errorf("vm:101 Text = %q", txt)
	}
	if m := mustMetric(t, vm, "net_in"); !near(m.Value, 10) { // 75 MB in 60 s = 10 Mbit/s: Zaehler der vorigen Runde gelten weiter
		t.Errorf("vm:101 net_in = %+v", m)
	}
	if hasSvc(svcs, "vm:9000") {
		t.Error("Vorlage verfolgt")
	}
	for _, s := range svcs {
		if s.MovedTo != "" && s.Key != "vm:101" {
			t.Errorf("%s faelschlich migriert", s.Key)
		}
	}

	// Config des migrierten Gasts kommt (beim naechsten Lesen, alle configEvery) von seiner neuen Node
	now = now.Add(configEvery)
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(deErr(err))
	}
	if f.count("/nodes/pve2/qemu/101/config") != 1 {
		t.Errorf("Config von pve2: %d", f.count("/nodes/pve2/qemu/101/config"))
	}

	// Cluster antwortet nicht: Teilfehler nur fuer den fehlenden Gast
	f.set("/cluster/resources?type=vm", http.StatusInternalServerError, "got timeout")
	now = now.Add(time.Minute)
	svcs, err = p.Collect(context.Background())
	pe := partialOf(t, err)
	if !pe.Affects("vm:101") || pe.Affects("vm:102") || pe.Affects("ct:200") || hasSvc(svcs, "vm:101") {
		t.Errorf("ohne Cluster: %v", pe.Prefixes)
	}

	// geloescht: fehlt ohne Fehler
	f.ok("/cluster/resources?type=vm", `[]`)
	now = now.Add(time.Minute)
	svcs, err = p.Collect(context.Background())
	if err != nil || hasSvc(svcs, "vm:101") {
		t.Errorf("geloescht: err=%v vm:101=%v", err, hasSvc(svcs, "vm:101"))
	}

	// nicht uebernommen: nicht gesucht
	p.Follow([]string{"vm:102"})
	before := f.count("/cluster/resources?type=vm")
	now = now.Add(time.Minute)
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.count("/cluster/resources?type=vm") != before {
		t.Error("Cluster ohne fehlenden uebernommenen Gast abgefragt")
	}
}

// #165: Soll-Zustand von HA-Gaesten aus der HA-Konfiguration (request_state; aeltere PVE: /cluster/ha/resources).
func TestPVEHASoll(t *testing.T) {
	stopped101 := `[{"vmid":101,"name":"web01","status":"stopped","cpus":2,"maxmem":4294967296,"maxdisk":34359738368,"uptime":0}]`
	ha := func(state, req string) string {
		r := ""
		if req != "" {
			r = `,"request_state":"` + req + `"`
		}
		return `[{"id":"quorum","type":"quorum","node":"pve1","status":"OK","quorate":1},
  {"id":"service:vm:101","type":"service","sid":"vm:101","node":"pve1","state":"` + state + `","crm_state":"` + state + `"` + r + `}]`
	}
	for _, c := range []struct {
		name, state, req, conf string
		down, locked           bool
		text                   string
	}{
		{name: "HA started, gestoppt", state: "stopped", req: "started", down: true, text: "soll laufen (HA)"},
		{name: "HA stopped", state: "stopped", req: "stopped", text: "darf aus sein (HA: stopped)"},
		{name: "HA disabled", state: "disabled", req: "disabled", text: "darf aus sein (HA: disabled)"},
		{name: "HA verschiebt", state: "relocate", req: "started", locked: true, text: "HA: relocate"},
		{name: "HA ignored: onboot", state: "ignored", req: "ignored", down: true, text: "beim Booten starten"},
		{name: "ohne request_state", state: "stopped", conf: `[{"sid":"vm:101","state":"stopped","type":"vm"}]`, text: "darf aus sein (HA: stopped)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, cfg := pveFake(t)
			cfg.Node = "pve1"
			now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
			p := newTestPVE(t, cfg, &now)
			f.ok("/nodes/pve1/qemu?full=1", stopped101)
			f.ok("/cluster/ha/status/current", ha(c.state, c.req))
			if c.conf != "" {
				f.ok("/cluster/ha/resources", c.conf)
			}
			svcs, err := p.Collect(context.Background())
			if err != nil {
				t.Fatal(deErr(err))
			}
			vm := svcByKey(t, svcs, "vm:101")
			if hasFact(vm, "guest_down") != c.down || (mustMetric(t, vm, "locked").Value == 1) != c.locked || !strings.Contains(de(vm.Text), c.text) {
				t.Errorf("vm:101 = %q, Facts %+v, locked %v", de(vm.Text), vm.Facts, mustMetric(t, vm, "locked").Value)
			}
			if c.conf == "" && f.count("/cluster/ha/resources") != 0 {
				t.Error("HA-Konfiguration abgefragt, obwohl request_state da ist")
			}
		})
	}
}
