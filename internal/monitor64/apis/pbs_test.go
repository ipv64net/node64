package apis

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// pbsFake: PBS 3.3 mit einem Datastore (backup, zwei Namespaces), einem Wechseldatenträger und einem Datastore im
// Wartungsmodus; /admin/gc gibt es nicht (GC-Status je Datastore).
func pbsFake(t *testing.T, now time.Time) (*fakeAPI, PBSConfig) {
	f := newFakeAPI(t)
	ago := func(d time.Duration) int64 { return now.Add(-d).Unix() }
	f.ok("/version", "@pbs/version.json")
	f.ok("/nodes/localhost/status", "@pbs/node_status.json")
	f.ok("/status/datastore-usage", "@pbs/datastore_usage.json")
	f.ok("/nodes/localhost/apt/update", "@pbs/apt_update.json")
	f.ok("/nodes/localhost/disks/list", "@pbs/disks_list.json")
	f.ok("/nodes/localhost/disks/smart?disk=sda", "@pbs/smart_sda.json")
	f.ok("/nodes/localhost/disks/smart?disk=nvme0n1", "@pbs/smart_nvme.json")
	f.ok("/admin/datastore/backup/namespace", "@pbs/namespace_backup.json")
	f.ok("/admin/datastore/backup/groups", fmt.Sprintf(`[
  {"backup-type":"vm","backup-id":"101","last-backup":%d,"backup-count":14,"files":["qemu-server.conf.blob","drive-scsi0.img.fidx","index.json.blob"],"owner":"root@pam!backup","comment":"web01"},
  {"backup-type":"ct","backup-id":"200","last-backup":%d,"backup-count":7,"files":["pct.conf.blob","root.pxar.didx","catalog.pcat1.didx","index.json.blob"],"owner":"root@pam!backup","comment":"pihole"}
]`, ago(3*time.Hour), ago(40*time.Hour)))
	f.ok("/admin/datastore/backup/groups?ns=prod", fmt.Sprintf(`[
  {"backup-type":"host","backup-id":"nas01","last-backup":%d,"backup-count":3,"files":["root.pxar.didx","catalog.pcat1.didx","index.json.blob"],"owner":"root@pam"}
]`, ago(60*24*time.Hour)))
	f.ok("/admin/verify", fmt.Sprintf(`[
  {"id":"v-3f2a1b7c-90de","store":"backup","schedule":"daily","ignore-verified":true,"outdated-after":30,"next-run":%d,"last-run-state":"OK","last-run-upid":"UPID:pbs:0000A1B2:00C3D4E5:00000002:672F1A00:verificationjob:backup\\x3av\\x2d3f2a1b7c\\x2d90de:root@pam:","last-run-endtime":%d}
]`, now.Add(19*time.Hour).Unix(), ago(5*time.Hour)))
	f.ok("/admin/prune", fmt.Sprintf(`[
  {"id":"s-9c8d7e6f-a1b2","store":"backup","schedule":"daily","keep-daily":7,"keep-last":3,"keep-weekly":4,"next-run":%d,"last-run-state":"prune failed - unable to acquire lock on backup group","last-run-upid":"UPID:pbs:...","last-run-endtime":%d}
]`, now.Add(22*time.Hour).Unix(), ago(2*time.Hour)))
	f.ok("/admin/sync", `[]`)
	// /admin/gc fehlt (404), GC-Status je Datastore
	f.ok("/admin/datastore/backup/gc-job-status", fmt.Sprintf(`{"store":"backup","schedule":"daily","next-run":%d,"last-run-state":"OK","last-run-upid":"UPID:pbs:...","last-run-endtime":%d,"duration":3600,"removed-bytes":1048576000,"pending-bytes":0}`,
		now.Add(14*time.Hour).Unix(), ago(10*time.Hour)))
	addr, pin := tlsServer(t, f)
	return f, PBSConfig{Addresses: []string{addr}, TokenID: "monitor64@pbs!node64", Secret: testSecret, Pin: pin}
}

func TestPBSCollect(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, cfg := pbsFake(t, now)
	p, err := NewPBS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return now }
	svcs, err := p.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "cpu"), "util"); !near(m.Value, 2.15) {
		t.Errorf("cpu = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "load"), "per_core"); !near(m.Value, 0.05) {
		t.Errorf("load = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "mem"), "used"); m.Value != 25 {
		t.Errorf("mem = %+v", m)
	}
	if m := mustMetric(t, svcByKey(t, svcs, "fs:/"), "used"); !near(m.Value, 16.67) {
		t.Errorf("fs:/ = %+v", m)
	}
	// Updates mit erkennbarem Sicherheitsupdate (Label Debian-Security)
	if upd := svcByKey(t, svcs, "updates"); !hasFact(upd, "updates_security") || mustMetric(t, upd, "security").Value != 1 {
		t.Errorf("updates = %+v", upd)
	}

	// Datastores
	ds := svcByKey(t, svcs, "ds:backup")
	if m := mustMetric(t, ds, "used"); m.Value != 85 || m.Rule != model.RuleStore || m.Max != 8e12 {
		t.Errorf("ds:backup used = %+v", m)
	}
	if m := mustMetric(t, ds, "free"); m.Value != 1.2e12 {
		t.Errorf("ds:backup free = %+v", m)
	}
	if !strings.Contains(ds.Text, "3 Gruppen, 24 Snapshots") {
		t.Errorf("ds:backup Text = %q", ds.Text)
	}
	if usb := svcByKey(t, svcs, "ds:usb"); len(usb.Metrics) != 0 || len(usb.Facts) != 0 || !strings.Contains(usb.Text, "nicht eingehängt") {
		t.Errorf("ds:usb = %+v", usb)
	}
	if br := svcByKey(t, svcs, "ds:broken"); !hasFact(br, "store_inactive") || !strings.Contains(br.Text, "maintenance") {
		t.Errorf("ds:broken = %+v", br)
	}

	// Backups je Gruppe (Grenze 26 h)
	vm := svcByKey(t, svcs, "backup:backup/vm/101")
	if hasFact(vm, "backup_old") || !vm.Default || vm.Name != "Backup vm/101 web01 (backup)" {
		t.Errorf("vm/101 = %+v", vm)
	}
	if m := mustMetric(t, vm, "age"); m.Value != 3 || m.Unit != "h" {
		t.Errorf("vm/101 age = %+v", m)
	}
	ct := svcByKey(t, svcs, "backup:backup/ct/200")
	if !hasFact(ct, "backup_old") || !strings.Contains(ct.Facts[0].Text, "vor 40 Std.") {
		t.Errorf("ct/200 (40 h) = %+v", ct)
	}
	old := svcByKey(t, svcs, "backup:backup/prod/host/nas01")
	if !hasFact(old, "backup_old") || old.Default {
		t.Errorf("host/nas01 (60 Tage, Namespace prod) = %+v", old)
	}

	// Jobs
	if v := svcByKey(t, svcs, "job:verify:v-3f2a1b7c-90de"); hasFact(v, "job_failed") || !strings.Contains(v.Text, "vor 5 Std.: OK") {
		t.Errorf("verify = %+v", v)
	}
	pr := svcByKey(t, svcs, "job:prune:s-9c8d7e6f-a1b2")
	if !hasFact(pr, "job_failed") || !strings.Contains(pr.Text, "unable to acquire lock") || mustMetric(t, pr, "failed").Value != 1 {
		t.Errorf("prune = %+v", pr)
	}
	if gc := svcByKey(t, svcs, "job:gc:backup"); hasFact(gc, "job_failed") || gc.Name != "Garbage Collection backup" {
		t.Errorf("gc = %+v", gc)
	}
	if f.count("/admin/gc") != 1 || f.count("/admin/datastore/broken/gc-job-status") != 0 {
		t.Error("GC-Abfrage falsch")
	}

	// Platten (PBS: disk-type/status, NVMe-Werte als Attribute)
	sda := svcByKey(t, svcs, "disk:WSD1ABCD")
	if !hasFact(sda, "smart_sectors") || mustMetric(t, sda, "temp").Value != 38 || mustMetric(t, sda, "pending").Value != 2 {
		t.Errorf("sda = %+v", sda)
	}
	nv := svcByKey(t, svcs, "disk:50026B7686123456")
	if m := mustMetric(t, nv, "wear"); m.Value != 6 {
		t.Errorf("nvme wear = %+v", m)
	}
	if m := mustMetric(t, nv, "temp"); m.Value != 44 || m.Rule != model.RuleNVMeTemp {
		t.Errorf("nvme temp = %+v", m)
	}

	// Zweite Runde nach 5 min: Gruppen aus dem Speicher (alle 10 min), Alter laeuft weiter; /admin/gc nicht erneut
	now = now.Add(5 * time.Minute)
	svcs, err = p.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.count("/admin/datastore/backup/groups") != 1 || f.count("/admin/gc") != 1 {
		t.Errorf("Gruppen %d-mal, /admin/gc %d-mal abgefragt", f.count("/admin/datastore/backup/groups"), f.count("/admin/gc"))
	}
	if m := mustMetric(t, svcByKey(t, svcs, "backup:backup/vm/101"), "age"); !near(m.Value, 3.08) {
		t.Errorf("Alter nach 5 min = %v", m.Value)
	}
}

func TestPBSPartialAndThreshold(t *testing.T) {
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	f, cfg := pbsFake(t, now)
	cfg.BackupMaxAge = 48 * time.Hour
	f.set("/admin/datastore/backup/groups?ns=prod", http.StatusForbidden, "permission check failed")
	f.set("/admin/verify", http.StatusInternalServerError, "unable to read verification.cfg")
	p, err := NewPBS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return now }
	svcs, err := p.Collect(context.Background())
	if !IsPartial(err) || strings.Contains(err.Error(), testSecret) {
		t.Fatalf("erwartet PartialError: %v", err)
	}
	if !strings.Contains(err.Error(), "groups backup") || !strings.Contains(err.Error(), "admin/verify") {
		t.Errorf("Teilfehler = %v", err)
	}
	if !hasSvc(svcs, "ds:backup") || hasSvc(svcs, "backup:backup/vm/101") || hasSvc(svcs, "job:verify:v-3f2a1b7c-90de") {
		t.Error("Dienste bei Teilfehler falsch")
	}
	// Gruppen wieder lesbar (nach 10 min): Grenze 48 h -> ct/200 (40 h) ok
	f.ok("/admin/datastore/backup/groups?ns=prod", `[]`)
	now = now.Add(11 * time.Minute)
	svcs, _ = p.Collect(context.Background())
	if ct := svcByKey(t, svcs, "backup:backup/ct/200"); hasFact(ct, "backup_old") {
		t.Errorf("ct/200 bei Grenze 48 h = %+v", ct)
	}
	// Status nicht lesbar: ganzer Zugang fehlerhaft
	f.set("/nodes/localhost/status", http.StatusForbidden, "permission check failed")
	if svcs, err := p.Collect(context.Background()); err == nil || IsPartial(err) || svcs != nil {
		t.Errorf("403 auf status: %v", err)
	}
}

func TestPBSTest(t *testing.T) {
	now := time.Now()
	_, cfg := pbsFake(t, now)
	p, err := NewPBS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	res := p.Test(context.Background())
	if !res.OK || res.Version != "3.3.3" || res.Summary != "3 Datastores" || res.Node != "localhost" {
		t.Errorf("Test = %+v", res)
	}
}
