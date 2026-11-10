package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// pveFake: Proxmox VE 8 mit drei Nodes (pve3 offline), Abfrage auf pve1.
func pveFake(t *testing.T) (*fakeAPI, PVEConfig) {
	f := pveRoutes(t)
	addr, pin := tlsServer(t, f)
	return f, PVEConfig{Addresses: []string{addr}, TokenID: "monitor64@pve!node64", Secret: testSecret, Pin: pin}
}

// pveRoutes: die aufgezeichneten Antworten von pveFake (ohne Server).
func pveRoutes(t *testing.T) *fakeAPI {
	f := newFakeAPI(t)
	f.ok("/version", "@pve/version.json")
	f.ok("/cluster/status", "@pve/cluster_status.json")
	f.ok("/cluster/resources", "@pve/cluster_resources.json")
	f.ok("/nodes/pve1/status", "@pve/node_status.json")
	f.ok("/nodes/pve1/storage", "@pve/storage.json")
	f.ok("/nodes/pve1/disks/zfs", "@pve/disks_zfs.json")
	f.ok("/nodes/pve1/disks/list", "@pve/disks_list.json")
	f.ok("/nodes/pve1/disks/smart?disk=/dev/nvme0n1", "@pve/smart_nvme.json")
	f.ok("/nodes/pve1/disks/smart?disk=/dev/sda", "@pve/smart_sda.json")
	f.ok("/nodes/pve1/disks/smart?disk=/dev/sdb", "@pve/smart_sdb.json")
	// /dev/sdc (USB-Stick): keine SMART-Antwort
	f.ok("/nodes/pve1/apt/update", "@pve/apt_update.json")
	f.ok("/nodes/pve1/qemu?full=1", "@pve/qemu_1.json")
	f.ok("/nodes/pve1/lxc", "@pve/lxc_1.json")
	for _, id := range []string{"101", "102", "103", "104"} {
		f.ok("/nodes/pve1/qemu/"+id+"/config", "@pve/qemu_"+id+"_config.json")
	}
	f.ok("/nodes/pve1/lxc/200/config", "@pve/lxc_200_config.json")
	f.ok("/cluster/ha/status/current", "@pve/ha_status.json")
	f.set("/cluster/ceph/status", http.StatusInternalServerError, "binary not installed: /usr/bin/ceph-mon")
	return f
}

func newTestPVE(t *testing.T, cfg PVEConfig, now *time.Time) *PVE {
	t.Helper()
	p, err := NewPVE(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return *now }
	return p
}

func TestPVECollect(t *testing.T) {
	f, cfg := pveFake(t)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now) // Node leer: aus cluster/status (local)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	cpu := svcByKey(t, svcs, "cpu")
	if m := mustMetric(t, cpu, "util"); !near(m.Value, 7.34) || m.Rule != model.RuleCPU {
		t.Errorf("cpu util = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "load"), "per_core"); !near(m.Value, 0.08) || m.Rule != model.RuleLoad {
		t.Errorf("load per_core = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "mem"), "used"); !near(m.Value, 42.1) || m.Max != 33544937472 {
		t.Errorf("mem = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "swap"), "used"); !near(m.Value, 1.22) {
		t.Errorf("swap = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "fs:/"), "used"); !near(m.Value, 30.62) || m.Rule != model.RuleFS {
		t.Errorf("fs:/ = %+v", m)
	}

	// Speicher
	if m := mustMetric(t, svcByKey(t, svcs, "store:local"), "used"); !near(m.Value, 29.06) || m.Rule != model.RuleStore || m.Max != 100861726720 {
		t.Errorf("store:local = %+v", m)
	}
	if s := svcByKey(t, svcs, "store:nas-backup"); !hasFact(s, "store_inactive") || len(s.Metrics) != 0 {
		t.Errorf("store:nas-backup = %+v", s)
	}
	if s := svcByKey(t, svcs, "store:old-lvm"); s.Default || len(s.Facts) != 0 {
		t.Errorf("abgeschalteter Speicher = %+v", s)
	}
	// ZFS
	if s := svcByKey(t, svcs, "zfs:rpool"); hasFact(s, "zfs_degraded") {
		t.Errorf("rpool = %+v", s)
	}
	if s := svcByKey(t, svcs, "zfs:tank"); !hasFact(s, "zfs_degraded") {
		t.Errorf("tank ohne zfs_degraded: %+v", s)
	}

	// Platten (Schluessel Seriennummer)
	nvme := svcByKey(t, svcs, "disk:S5GXNX0T512345A")
	if m := mustMetric(t, nvme, "temp"); m.Value != 41 || m.Rule != model.RuleNVMeTemp {
		t.Errorf("nvme temp = %+v", m)
	}
	if m := mustMetric(t, nvme, "wear"); m.Value != 3 || m.Rule != model.RuleWear {
		t.Errorf("nvme wear = %+v", m)
	}
	if m := mustMetric(t, nvme, "media_err"); m.Value != 0 {
		t.Errorf("nvme media = %+v", m)
	}
	if len(nvme.Facts) != 0 || !strings.Contains(nvme.Text, "SMART ok") {
		t.Errorf("nvme = %+v", nvme)
	}
	sda := svcByKey(t, svcs, "disk:WD-WCC7K1ABCDEF")
	if m := mustMetric(t, sda, "temp"); m.Value != 35 || m.Rule != model.RuleDiskTemp {
		t.Errorf("sda temp = %+v", m)
	}
	if _, ok := metric(sda, "wear"); ok {
		t.Errorf("HDD mit Verschleiss: %+v", sda)
	}
	if sda.Name != "sda (WDC_WD40EFRX-68N32N0)" || len(sda.Facts) != 0 {
		t.Errorf("sda = %+v", sda)
	}
	sdb := svcByKey(t, svcs, "disk:ZDH1XYZ9")
	if !hasFact(sdb, "smart_failed") || !hasFact(sdb, "smart_sectors") || hasFact(sdb, "smart_sectors_rising") {
		t.Errorf("sdb facts = %+v", sdb.Facts)
	}
	if m := mustMetric(t, sdb, "temp"); m.Value != 38 {
		t.Errorf("sdb temp = %+v", m)
	}
	if m := mustMetric(t, sdb, "pending"); m.Value != 8 {
		t.Errorf("sdb pending = %+v", m)
	}
	if s := svcByKey(t, svcs, "disk:4C530001230101115453"); !strings.Contains(s.Text, "SMART nicht lesbar") {
		t.Errorf("USB-Stick = %+v", s)
	}

	// Updates: Sicherheitsupdates nicht erkennbar -> keine Angabe
	upd := svcByKey(t, svcs, "updates")
	if m := mustMetric(t, upd, "pending"); m.Value != 2 {
		t.Errorf("updates = %+v", upd)
	}
	if _, ok := metric(upd, "security"); ok || hasFact(upd, "updates_security") {
		t.Errorf("Sicherheitsupdates geraten: %+v", upd)
	}

	// Cluster, HA, kein Ceph
	cl := svcByKey(t, svcs, "cluster")
	if cl.Name != "Cluster homelab" || hasFact(cl, "cluster_no_quorum") || !hasFact(cl, "cluster_node_down") || !strings.Contains(cl.Text, "pve3") {
		t.Errorf("cluster = %+v", cl)
	}
	if m := mustMetric(t, cl, "nodes_online"); m.Value != 2 {
		t.Errorf("nodes_online = %+v", m)
	}
	ha := svcByKey(t, svcs, "ha")
	if !hasFact(ha, "ha_error") || !strings.Contains(ha.Text, "ct:200") {
		t.Errorf("ha = %+v", ha)
	}
	if hasSvc(svcs, "ceph") {
		t.Error("Ceph-Dienst ohne Ceph")
	}

	// Gaeste
	vm101 := svcByKey(t, svcs, "vm:101")
	if vm101.Name != "web01 (VM 101)" || vm101.Kind != "vm" || len(vm101.Facts) != 0 {
		t.Errorf("vm:101 = %+v", vm101)
	}
	if m := mustMetric(t, vm101, "cpu"); !near(m.Value, 4.12) || m.Rule != model.RuleCPU {
		t.Errorf("vm:101 cpu = %+v", m)
	}
	if m := mustMetric(t, vm101, "mem"); m.Value != 50 {
		t.Errorf("vm:101 mem = %+v", m)
	}
	if _, ok := metric(vm101, "net_in"); ok {
		t.Error("Rate in der ersten Runde")
	}
	if _, ok := metric(vm101, "disk"); ok {
		t.Error("QEMU ohne Gast-Agent mit Platte")
	}
	if !strings.Contains(vm101.Text, "soll laufen") {
		t.Errorf("vm:101 Text = %q", vm101.Text)
	}
	vm102 := svcByKey(t, svcs, "vm:102")
	if !hasFact(vm102, "guest_down") || mustMetric(t, vm102, "running").Value != 0 {
		t.Errorf("vm:102 (onboot, gestoppt) = %+v", vm102)
	}
	vm103 := svcByKey(t, svcs, "vm:103")
	if vm103.Default || hasFact(vm103, "guest_down") || !strings.Contains(vm103.Text, "darf aus sein") {
		t.Errorf("vm:103 (nomonitor, ohne onboot) = %+v", vm103)
	}
	if vm104 := svcByKey(t, svcs, "vm:104"); hasFact(vm104, "guest_down") || !strings.Contains(vm104.Text, "Sperre backup") {
		t.Errorf("vm:104 (Backup im Stop-Modus) = %+v", vm104)
	}
	if hasSvc(svcs, "vm:9000") {
		t.Error("Vorlage als Dienst")
	}
	ct := svcByKey(t, svcs, "ct:200")
	if m := mustMetric(t, ct, "disk"); m.Value != 12.5 || m.Rule != model.RuleFS {
		t.Errorf("ct:200 disk = %+v", m)
	}
	if ct.Name != "pihole (CT 200)" || ct.Kind != "ct" {
		t.Errorf("ct:200 = %+v", ct)
	}

	// Reihenfolge: Node-Werte vor Gaesten
	if svcs[0].Key != "cpu" || svcs[len(svcs)-1].Key != "ct:200" {
		t.Errorf("Reihenfolge: erster %s, letzter %s", svcs[0].Key, svcs[len(svcs)-1].Key)
	}

	// Zweite Runde nach 60 s: Raten aus den Zaehlern, LXC neu gestartet (keine Raten), SMART und Config aus dem Speicher
	f.ok("/nodes/pve1/qemu?full=1", "@pve/qemu_2.json")
	f.ok("/nodes/pve1/lxc", "@pve/lxc_2.json")
	now = now.Add(60 * time.Second)
	svcs, err = p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 2: %v", err)
	}
	vm101 = svcByKey(t, svcs, "vm:101")
	for name, want := range map[string]float64{"net_in": 10, "net_out": 1, "read": 1e6, "write": 2e6} {
		if m := mustMetric(t, vm101, name); !near(m.Value, want) {
			t.Errorf("vm:101 %s = %v, erwartet %v", name, m.Value, want)
		}
	}
	if !strings.Contains(vm101.Text, "↓ 10 Mbit/s") {
		t.Errorf("vm:101 Text = %q", vm101.Text)
	}
	if _, ok := metric(svcByKey(t, svcs, "ct:200"), "net_in"); ok {
		t.Error("Rate nach Neustart des Gasts")
	}
	if n := f.count("/nodes/pve1/disks/smart?disk=/dev/sda"); n != 1 {
		t.Errorf("SMART %d-mal abgefragt, erwartet 1 (alle 30 min)", n)
	}
	if n := f.count("/nodes/pve1/qemu/101/config"); n != 1 {
		t.Errorf("Config %d-mal abgefragt, erwartet 1", n)
	}
	if n := f.count("/cluster/ceph/status"); n != 1 {
		t.Errorf("Ceph %d-mal abgefragt, erwartet 1 (fehlt: stuendlich)", n)
	}
	if !hasSvc(svcs, "disk:ZDH1XYZ9") || !hasSvc(svcs, "updates") {
		t.Error("Platten/Updates fehlen zwischen den Abfragen")
	}

	// Dritte Runde nach 31 min: SMART neu, ausstehende Sektoren gestiegen; Raten von vorn (Zaehler wieder da)
	f.ok("/nodes/pve1/disks/smart?disk=/dev/sdb", strings.Replace(fixture(t, "pve/smart_sdb.json"), `"raw":"8","normalized":100},
  {"id":"198"`, `"raw":"16","normalized":100},
  {"id":"198"`, 1))
	now = now.Add(31 * time.Minute)
	svcs, err = p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect 3: %v", err)
	}
	if sdb := svcByKey(t, svcs, "disk:ZDH1XYZ9"); !hasFact(sdb, "smart_sectors_rising") {
		t.Errorf("Sektoren gestiegen ohne smart_sectors_rising: %+v", sdb)
	}
	if n := f.count("/nodes/pve1/qemu/101/config"); n != 2 {
		t.Errorf("Config nach 31 min %d-mal abgefragt, erwartet 2", n)
	}
}

func TestPVEPartialAndErrors(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)

	// Teilfehler: Speicher ohne Rechte, LXC-Config fehlt -> uebrige Dienste, PartialError
	f.set("/nodes/pve1/storage", http.StatusForbidden, "Permission check failed (/storage/local, Datastore.Audit)")
	f.set("/nodes/pve1/lxc/200/config", http.StatusInternalServerError, "unable to read config")
	svcs, err := p.Collect(context.Background())
	if err == nil || !IsPartial(err) {
		t.Fatalf("erwartet PartialError, got %v", err)
	}
	if strings.Contains(deErr(err), testSecret) {
		t.Fatal("Secret im Fehlertext")
	}
	if !strings.Contains(deErr(err), "storage") || !strings.Contains(deErr(err), "Gast-Config (1)") {
		t.Errorf("Teilfehler = %v", err)
	}
	// F6-K2: betroffene Schluessel-Praefixe (Gast-Config laesst keinen Dienst fehlen)
	if pe := partialOf(t, err); !hasPrefix(pe, "store:") || hasPrefix(pe, "vm:") || !pe.Affects("store:local") || pe.Affects("vm:101") {
		t.Errorf("Prefixes = %v", pe.Prefixes)
	}
	if hasSvc(svcs, "store:local") || !hasSvc(svcs, "cpu") || !hasSvc(svcs, "vm:101") {
		t.Errorf("Dienste bei Teilfehler falsch")
	}
	if ct := svcByKey(t, svcs, "ct:200"); !strings.Contains(ct.Text, "Soll-Zustand unbekannt") || hasFact(ct, "guest_down") {
		t.Errorf("ct:200 ohne Config = %+v", ct)
	}

	// Liste der VMs fehlt: Zaehler bleiben fuer die naechste Runde
	f.set("/nodes/pve1/qemu?full=1", http.StatusInternalServerError, "got timeout")
	now = now.Add(time.Minute)
	svcs, err = p.Collect(context.Background())
	if !IsPartial(err) || hasSvc(svcs, "vm:101") {
		t.Fatalf("ohne qemu-Liste: err=%v", err)
	}
	if pe := partialOf(t, err); !pe.Affects("vm:101") || pe.Affects("ct:200") {
		t.Errorf("Prefixes ohne qemu-Liste = %v", pe.Prefixes)
	}
	f.ok("/nodes/pve1/qemu?full=1", "@pve/qemu_2.json")
	now = now.Add(time.Minute)
	svcs, _ = p.Collect(context.Background())
	if _, ok := metric(svcByKey(t, svcs, "vm:101"), "net_in"); !ok {
		t.Error("Zaehler nach fehlender Liste verloren")
	}

	// Token ungueltig: kein Dienst, Fehler ohne Secret
	f.set("/nodes/pve1/status", http.StatusUnauthorized, "invalid token value!")
	svcs, err = p.Collect(context.Background())
	if err == nil || IsPartial(err) || svcs != nil {
		t.Fatalf("401: svcs=%d err=%v", len(svcs), err)
	}
	if strings.Contains(deErr(err), testSecret) || !strings.Contains(deErr(err), "401") {
		t.Errorf("401-Fehler = %v", err)
	}
}

func TestPVECeph(t *testing.T) {
	f, cfg := pveFake(t)
	f.ok("/cluster/ceph/status", "@pve/ceph_status.json")
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	c := svcByKey(t, svcs, "ceph")
	if !hasFact(c, "ceph_warn") || hasFact(c, "ceph_err") || !strings.Contains(c.Text, "1 osds down") {
		t.Errorf("ceph = %+v", c)
	}
	if m := mustMetric(t, c, "osds_up"); m.Value != 5 {
		t.Errorf("osds_up = %+v", m)
	}
	if m := mustMetric(t, c, "used"); !near(m.Value, 2.43) || m.Rule != model.RuleStore {
		t.Errorf("ceph used = %+v", m)
	}
}

func TestPVETestAndNodes(t *testing.T) {
	f, cfg := pveFake(t)
	p, err := NewPVE(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := deRes(p.Test(context.Background()))
	if !res.OK || res.Error != "" || res.Version != "8.3.0" || res.Cluster != "homelab" || res.Node != "pve1" {
		t.Fatalf("Test = %+v", res)
	}
	if len(res.Nodes) != 3 || res.Nodes[1].Name != "pve2" || res.Nodes[1].IP != "192.168.10.12" || !res.Nodes[0].Local || res.Nodes[2].Online {
		t.Errorf("Nodes = %+v", res.Nodes)
	}
	if res.Summary != "3 Gäste im Cluster" || res.Fingerprint != cfg.Pin {
		t.Errorf("Test = %+v", res)
	}
	cl, nodes, err := p.Nodes(context.Background())
	if err != nil || cl != "homelab" || len(nodes) != 3 {
		t.Errorf("Nodes: %q %v %v", cl, nodes, err)
	}

	// Falscher Node-Name
	bad := cfg
	bad.Node = "pve9"
	pb, _ := NewPVE(bad)
	if r := deRes(pb.Test(context.Background())); r.OK || !strings.Contains(r.Error, "pve9") {
		t.Errorf("falscher Node: %+v", r)
	}

	// Ohne Pin und mit unbekanntem Zertifikat: Fingerabdruck zeigen, Token nicht senden
	before := f.auth
	np := cfg
	np.Pin = ""
	pn, err := NewPVE(np)
	if err != nil {
		t.Fatal(err)
	}
	r := deRes(pn.Test(context.Background()))
	if r.OK || !r.NeedConfirm || r.Fingerprint != cfg.Pin {
		t.Errorf("ohne Pin: %+v", r)
	}
	if f.auth != before {
		t.Error("Token an unbestaetigtes Zertifikat gesendet")
	}
	// Collect ohne Pin: Zertifikat nicht vertrauenswuerdig, kein Token
	if _, err := pn.Collect(context.Background()); err == nil || f.auth != before {
		t.Errorf("Collect ohne Pin: err=%v", err)
	}
}

func TestPVEConfigErrors(t *testing.T) {
	if _, err := NewPVE(PVEConfig{Addresses: []string{"https://pve:8006"}, TokenID: "kaputt", Secret: testSecret}); err == nil {
		t.Error("Token-ID ohne @ und ! angenommen")
	}
	if _, err := NewPVE(PVEConfig{TokenID: "a@pve!b", Secret: testSecret}); err == nil {
		t.Error("ohne Adresse angenommen")
	}
	_, err := NewPVE(PVEConfig{Addresses: []string{"https://pve:8006"}, TokenID: "a@pve!b", Secret: testSecret, Pin: "xyz"})
	if err == nil || strings.Contains(deErr(err), testSecret) {
		t.Errorf("falscher Pin: %v", err)
	}
}

func TestParseSmartTemps(t *testing.T) {
	// Rohwert mit Min/Max in den oberen Bytes (manche Seagate): 0x002D0012001E -> 30 °C
	d := parseSmart(smartResp{Health: "PASSED", Attributes: []smartAttr{{ID: []byte(`194`), Raw: []byte(`"193273528350"`)}}})
	if d.temp == nil || *d.temp != 30 {
		t.Errorf("temp = %v", d.temp)
	}
	if d.passed == nil || !*d.passed {
		t.Error("passed")
	}
	// NVMe mit kritischer Warnung
	d = parseSmart(smartResp{Health: "FAILED", Text: "Critical Warning:   0x04\nTemperature:  72 Celsius\nPercentage Used: 101%\n"})
	if d.critWarn == nil || *d.critWarn != 4 || *d.temp != 72 || *d.wearUsed != 101 {
		t.Errorf("nvme = %+v", d)
	}
	s := modeltest.Service("de", diskService("disk:X1", diskEntry{DevPath: "/dev/nvme1n1", Type: "nvme", Serial: "X1"}, &d, false, map[string]uint64{}))
	if !hasFact(s, "smart_failed") {
		t.Errorf("NVMe-Warnung ohne smart_failed: %+v", s)
	}
	// F6-K3: ueber 100 % verbraucht -> 100 (nicht verwerfen)
	if m := mustMetric(t, s, "wear"); m.Value != 100 {
		t.Errorf("Verschleiss ueber 100 %% = %v, erwartet 100", m.Value)
	}
}

func TestUpdatesSecurity(t *testing.T) {
	s := modeltest.Service("de", updatesService([]aptUpdate{{Package: "libssl3", Origin: "Debian", Label: "Debian-Security"}, {Package: "vim", Origin: "Debian"}}))
	if m := mustMetric(t, s, "security"); m.Value != 1 || !hasFact(s, "updates_security") {
		t.Errorf("updates = %+v", s)
	}
	if s := modeltest.Service("de", updatesService(nil)); s.Text != "keine ausstehend" || len(s.Facts) != 0 {
		t.Errorf("keine Updates = %+v", s)
	}
}

// F6-K1: Gesamtstatus aus den Texten von smartctl (Proxmox VE reicht sie durch) und den Werten von PBS.
func TestHealthOf(t *testing.T) {
	for in, want := range map[string]string{"PASSED": "ok", "passed": "ok", "OK": "ok", "FAILED!": "failed", "failed": "failed",
		"FAILURE PREDICTION THRESHOLD EXCEEDED: ascq=0x5d [asc=5d, ascq=0]": "failed", "UNKNOWN": "", "": ""} {
		got := ""
		if b := healthOf(in); b != nil {
			got = "failed"
			if *b {
				got = "ok"
			}
		}
		if got != want {
			t.Errorf("healthOf(%q) = %q, erwartet %q", in, got, want)
		}
	}
	// SAS-Platte mit Vorhersage: smart_failed
	s := diskService("disk:S1", diskEntry{DevPath: "/dev/sdd", Type: "hdd", Serial: "S1", Health: "FAILURE PREDICTION THRESHOLD EXCEEDED: ascq=0x5d"},
		nil, false, map[string]uint64{})
	if !hasFact(s, "smart_failed") {
		t.Errorf("SAS-Vorhersage ohne smart_failed: %+v", s)
	}
}

// F6-K1: Seriennummer "unknown"/leer nicht als Schluessel; gleiche Nummer mit verschiedener WWN kollidiert nicht.
func TestDiskKeys(t *testing.T) {
	list := []diskEntry{
		{DevPath: "/dev/sda", Serial: "unknown", WWN: "0x5000c500aaaa0001"},
		{DevPath: "/dev/sdb", Serial: "unknown", WWN: "0x5000c500aaaa0002"},
		{DevPath: "/dev/sdc", Serial: " "},
		{DevPath: "/dev/sdd", Serial: "ABC123", WWN: "0x1"},
		{DevPath: "/dev/sde", Serial: "ABC123", WWN: "0x1"}, // Multipath: ein Dienst
		{DevPath: "/dev/sdf", Serial: "DUP", WWN: "0x2"},
		{DevPath: "/dev/sdg", Serial: "DUP", WWN: "0x3"},
		{Name: "nvme0n1", Serial: "N/A"},
	}
	want := []string{"disk:0x5000c500aaaa0001", "disk:0x5000c500aaaa0002", "disk:sdc", "disk:ABC123", "disk:ABC123",
		"disk:0x2", "disk:0x3", "disk:nvme0n1"}
	got := diskKeys(list)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Schluessel %d = %q, erwartet %q", i, got[i], want[i])
		}
	}
	// in der Runde: beide Platten mit "unknown" erscheinen
	f, cfg := pveFake(t)
	f.ok("/nodes/pve1/disks/list", `[
  {"devpath":"/dev/sda","type":"ssd","model":"X","serial":"unknown","wwn":"0x5000c500aaaa0001","health":"PASSED","wearout":90},
  {"devpath":"/dev/sdb","type":"ssd","model":"X","serial":"unknown","wwn":"0x5000c500aaaa0002","health":"FAILED!","wearout":-5}
]`)
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	svcs, _ := newTestPVE(t, cfg, &now).Collect(context.Background())
	a, b := svcByKey(t, svcs, "disk:0x5000c500aaaa0001"), svcByKey(t, svcs, "disk:0x5000c500aaaa0002")
	if hasFact(a, "smart_failed") || !hasFact(b, "smart_failed") {
		t.Errorf("SMART je Platte falsch: %+v / %+v", a.Facts, b.Facts)
	}
	// F6-K3: wearout negativ (mehr als 100 % verbraucht) -> 100
	if m := mustMetric(t, b, "wear"); m.Value != 100 {
		t.Errorf("wear bei wearout -5 = %v, erwartet 100", m.Value)
	}
}

// F6-K1: NVMe bei PBS mit den Schluesseln aus dem JSON von smartctl.
func TestParseSmartPBSNVMeJSON(t *testing.T) {
	var r smartResp
	if err := json.Unmarshal([]byte(fixture(t, "pbs/smart_nvme_json.json")), &r); err != nil {
		t.Fatal(err)
	}
	d := parseSmart(r)
	if d.critWarn == nil || *d.critWarn != 4 || d.temp == nil || *d.temp != 45 || d.wearUsed == nil || *d.wearUsed != 120 ||
		d.mediaE == nil || *d.mediaE != 3 {
		t.Fatalf("parseSmart = %+v", d)
	}
	s := modeltest.Service("de", diskService("disk:N1", diskEntry{Name: "nvme0n1", DiskType: "nvme", Serial: "N1"}, &d, false, map[string]uint64{}))
	if !hasFact(s, "smart_failed") || !hasFact(s, "smart_sectors") || mustMetric(t, s, "wear").Value != 100 || mustMetric(t, s, "media_err").Value != 3 {
		t.Errorf("NVMe (JSON-Schluessel) = %+v", s)
	}
}

// F6-K4: qmpstatus (io-error, paused, guest-panicked) und Sperre nur begrenzt.
func TestPVEGuestState(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	f.ok("/nodes/pve1/qemu?full=1", `[
  {"vmid":101,"name":"web01","status":"running","qmpstatus":"io-error","cpu":0,"cpus":2,"mem":1073741824,"maxmem":4294967296,"uptime":100,"pid":1},
  {"vmid":102,"name":"win11","status":"running","qmpstatus":"paused","cpu":0,"cpus":4,"mem":1073741824,"maxmem":8589934592,"uptime":100,"pid":2},
  {"vmid":103,"name":"test","status":"running","qmpstatus":"guest-panicked","cpus":1,"maxmem":1073741824,"uptime":100,"pid":3,"tags":"nomonitor"},
  {"vmid":104,"name":"db01","status":"stopped","lock":"backup","cpus":2,"maxmem":4294967296,"uptime":0}
]`)
	clock := &testClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	p, err := NewPVE(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = clock.now
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	vm101 := svcByKey(t, svcs, "vm:101")
	if !hasFact(vm101, "guest_fault") || mustMetric(t, vm101, "running").Value != 0 || !strings.Contains(vm101.Text, "gestört (io-error)") {
		t.Errorf("vm:101 (io-error) = %+v", vm101)
	}
	vm102 := svcByKey(t, svcs, "vm:102")
	if !hasFact(vm102, "guest_down") || mustMetric(t, vm102, "running").Value != 0 || !strings.Contains(vm102.Text, "pausiert") {
		t.Errorf("vm:102 (pausiert, onboot) = %+v", vm102)
	}
	if vm103 := svcByKey(t, svcs, "vm:103"); !hasFact(vm103, "guest_fault") {
		t.Errorf("vm:103 (guest-panicked, ohne onboot) = %+v", vm103)
	}
	vm104 := svcByKey(t, svcs, "vm:104")
	if hasFact(vm104, "guest_down") || mustMetric(t, vm104, "locked").Value != 1 {
		t.Errorf("vm:104 (Backup im Stopp-Modus) = %+v", vm104)
	}
	if mustMetric(t, vm101, "locked").Value != 0 {
		t.Error("locked ohne Sperre")
	}
	// Sperre haengt seit ueber 4 h: wie gestoppt
	clock.add(5 * time.Hour)
	svcs, _ = p.Collect(context.Background())
	vm104 = svcByKey(t, svcs, "vm:104")
	if !hasFact(vm104, "guest_down") || mustMetric(t, vm104, "locked").Value != 0 || !strings.Contains(vm104.Text, "Sperre backup seit 5 Std.") {
		t.Errorf("vm:104 (Sperre seit 5 h) = %+v", vm104)
	}
	// andere Sperre: Frist von vorn
	f.ok("/nodes/pve1/qemu?full=1", `[{"vmid":104,"name":"db01","status":"stopped","lock":"migrate","cpus":2,"maxmem":4294967296,"uptime":0}]`)
	clock.add(time.Minute)
	svcs, _ = p.Collect(context.Background())
	if vm104 = svcByKey(t, svcs, "vm:104"); hasFact(vm104, "guest_down") || mustMetric(t, vm104, "locked").Value != 1 {
		t.Errorf("vm:104 (neue Sperre migrate) = %+v", vm104)
	}
}

// Raten mit dem Abrufzeitpunkt der Gaesteliste, nicht dem Rundenbeginn (vorher dauert z. B. apt/update).
func TestPVERatesFetchTime(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	clock := &testClock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)}
	f.mu.Lock()
	f.onHit = func(path string) {
		if path == "/nodes/pve1/apt/update" {
			clock.add(30 * time.Second) // langsame Abfrage nur in der ersten Runde (Updates alle 60 min)
		}
	}
	f.mu.Unlock()
	p, err := NewPVE(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = clock.now
	if _, err := p.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.ok("/nodes/pve1/qemu?full=1", "@pve/qemu_2.json")
	clock.add(60 * time.Second) // 60 s nach dem Abruf der ersten Liste, 90 s nach Rundenbeginn
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "vm:101"), "net_in"); !near(m.Value, 10) {
		t.Errorf("net_in = %v, erwartet 10 (Abrufzeitpunkt)", m.Value)
	}
}

// F6-K5: Ceph nur bei "nicht eingerichtet" stuendlich; Fehler eines eingerichteten Ceph = ceph_err.
func TestPVECephStates(t *testing.T) {
	f, cfg := pveFake(t)
	cfg.Node = "pve1"
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)
	f.set("/cluster/ceph/status", http.StatusInternalServerError, "got timeout")
	svcs, err := p.Collect(context.Background())
	if pe := partialOf(t, err); !hasPrefix(pe, "ceph") || hasSvc(svcs, "ceph") {
		t.Errorf("500 ohne bekanntes Ceph: %v", err)
	}
	now = now.Add(time.Minute)
	_, _ = p.Collect(context.Background())
	if n := f.count("/cluster/ceph/status"); n != 2 {
		t.Errorf("Ceph nach 500 %d-mal abgefragt, erwartet 2 (nicht 60 min sperren)", n)
	}
	f.ok("/cluster/ceph/status", "@pve/ceph_status.json")
	now = now.Add(time.Minute)
	if svcs, _ = p.Collect(context.Background()); !hasSvc(svcs, "ceph") {
		t.Fatal("Ceph fehlt")
	}
	f.set("/cluster/ceph/status", http.StatusInternalServerError, "got timeout")
	now = now.Add(time.Minute)
	svcs, err = p.Collect(context.Background())
	if err != nil {
		t.Errorf("Ceph-Fehler als Teilfehler statt Zustand: %v", err)
	}
	if c := svcByKey(t, svcs, "ceph"); !hasFact(c, "ceph_err") || !strings.Contains(c.Text, "nicht abrufbar") {
		t.Errorf("eingerichtetes Ceph antwortet nicht: %+v", c)
	}
	f.set("/cluster/ceph/status", http.StatusInternalServerError, "pveceph configuration not initialized")
	now = now.Add(time.Minute)
	if svcs, _ = p.Collect(context.Background()); hasSvc(svcs, "ceph") {
		t.Error("Ceph-Dienst nach dem Entfernen")
	}
	before := f.count("/cluster/ceph/status")
	now = now.Add(time.Minute)
	_, _ = p.Collect(context.Background())
	if f.count("/cluster/ceph/status") != before {
		t.Error("nicht eingerichtetes Ceph vor Ablauf der Stunde erneut abgefragt")
	}
}

// F6-K5: clusterweite Dienste bewertet nur die Node mit der kleinsten ID unter den Nodes online.
func TestPVEClusterWide(t *testing.T) {
	f, cfg := pveFake(t)
	status := func(pve2Online int) string {
		return fmt.Sprintf(`[{"type":"cluster","id":"cluster","name":"homelab","nodes":3,"quorate":1,"version":7},
  {"type":"node","id":"node/pve1","name":"pve1","nodeid":2,"ip":"192.168.10.11","online":1,"local":1},
  {"type":"node","id":"node/pve2","name":"pve2","nodeid":1,"ip":"192.168.10.12","online":%d,"local":0},
  {"type":"node","id":"node/pve3","name":"pve3","nodeid":3,"ip":"192.168.10.13","online":0,"local":0}]`, pve2Online)
	}
	f.ok("/cluster/status", status(1))
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"cluster", "ha"} {
		s := svcByKey(t, svcs, k)
		if len(s.Facts) != 0 || len(s.Metrics) != 0 || !strings.Contains(s.Text, "gemeldet von Node pve2") {
			t.Errorf("%s auf nicht zustaendiger Node = %+v", k, s)
		}
	}
	// pve2 offline: pve1 uebernimmt
	f.ok("/cluster/status", status(0))
	now = now.Add(time.Minute)
	svcs, _ = p.Collect(context.Background())
	if cl := svcByKey(t, svcs, "cluster"); !hasFact(cl, "cluster_node_down") || !strings.Contains(cl.Text, "pve2") {
		t.Errorf("cluster nach Uebernahme = %+v", cl)
	}
	if ha := svcByKey(t, svcs, "ha"); !hasFact(ha, "ha_error") {
		t.Errorf("ha nach Uebernahme = %+v", ha)
	}
}

// F6-K6: Node leer und mehrere Adressen: beim ersten Kontakt festgelegt, bleibt bei Failover.
func TestPVENodeFixed(t *testing.T) {
	fa := pveRoutes(t)
	sa := &switchable{h: fa}
	addrA, pin := tlsServer(t, sa)
	fb := pveRoutes(t) // andere Node: dort ist pve2 "local", pve1 wird weitergeleitet
	fb.ok("/cluster/status", strings.Replace(strings.Replace(fixture(t, "pve/cluster_status.json"),
		`"online":1,"local":1`, `"online":1,"local":0`, 1), `"nodeid":2,"ip":"192.168.10.12","online":1,"local":0`,
		`"nodeid":2,"ip":"192.168.10.12","online":1,"local":1`, 1))
	addrB, _ := tlsServer(t, fb)
	cfg := PVEConfig{Addresses: []string{addrA, addrB}, TokenID: "monitor64@pve!node64", Secret: testSecret, Pin: pin}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	p := newTestPVE(t, cfg, &now)
	if res := deRes(p.Test(context.Background())); !res.OK || res.Node != "pve1" || p.Node() != "pve1" {
		t.Fatalf("Test = %+v, Node() = %q", res, p.Node())
	}
	sa.setDown(true)
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect ueber Adresse B: %v", err)
	}
	if p.Node() != "pve1" || !hasSvc(svcs, "cpu") || fb.count("/nodes/pve1/status") != 1 || fb.count("/nodes/pve2/status") != 0 {
		t.Errorf("Node nach Failover: %q, pve1 %d, pve2 %d", p.Node(), fb.count("/nodes/pve1/status"), fb.count("/nodes/pve2/status"))
	}
}

// Cluster-Dienste bewertet die kleinste Node-ID unter den hier ueberwachten Nodes (nicht eine fehlende Node).
func TestClusterOwnerWatched(t *testing.T) {
	st := []pveStatus{{Type: "cluster", Name: "c1"}, {Type: "node", Name: "pve1", NodeID: 1, Online: 1}, {Type: "node", Name: "pve2", NodeID: 2, Online: 1}, {Type: "node", Name: "pve3", NodeID: 3, Online: 1}}
	seen := &ClusterSeen{}
	now := time.Now()
	fresh := func(n string) bool { return seen.fresh("c1", n, now) }
	if o := clusterOwner(st, "pve2", fresh); o != "pve2" {
		t.Fatalf("only pve2 watched: owner %q", o)
	}
	seen.mark("c1", "pve1", now.Add(-time.Minute))
	if o := clusterOwner(st, "pve2", fresh); o != "pve1" {
		t.Fatalf("pve1 watched: owner %q", o)
	}
	seen.mark("c1", "pve1", now.Add(-time.Hour))
	if o := clusterOwner(st, "pve3", fresh); o != "pve3" {
		t.Fatalf("pve1 stale: owner %q", o)
	}
	if o := clusterOwner(st, "pve3", nil); o != "pve1" {
		t.Fatalf("without seen: owner %q", o)
	}
}
