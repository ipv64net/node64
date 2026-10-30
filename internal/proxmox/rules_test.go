package proxmox

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// pveRun haelt Engine, Einstellungen und Uhr fuer eine Folge von Snapshots (alle 30 s).
type pveRun struct {
	t   *testing.T
	e   *Engine
	set *SystemSettings
	now time.Time
}

func newPveRun(t *testing.T) *pveRun {
	return &pveRun{t: t, e: NewEngine(), set: &SystemSettings{SystemID: 1, Name: "Lab", Items: map[string]*Settings{}},
		now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
}

func (p *pveRun) item(key string) *Settings {
	it := p.set.Items[key]
	if it == nil {
		it = &Settings{SystemID: 1, Key: key}
		p.set.Items[key] = it
	}
	return it
}

func (p *pveRun) snap(ok bool, res ...Resource) []Event {
	p.now = p.now.Add(30 * time.Second)
	return p.e.Evaluate(&Snapshot{SystemID: 1, Time: p.now, OK: ok, Error: "timeout", Resources: res}, p.set)
}

func pveEvStr(evs []Event) string {
	var b []string
	for _, e := range evs {
		b = append(b, e.Kind+":"+e.What+":"+e.Key)
	}
	return strings.Join(b, ",")
}

func (p *pveRun) expect(evs []Event, want string) {
	p.t.Helper()
	if got := pveEvStr(evs); got != want {
		p.t.Fatalf("Ereignisse: %q, erwartet %q", got, want)
	}
}

func pveNode(name string, online bool) Resource {
	r := Resource{Type: TypeNode, Node: name, Name: name, State: StateOnline, Status: "online", CPU: 0.05, Mem: 100, MaxMem: 1000,
		Disk: 100, MaxDisk: 1000}
	if !online {
		r.State, r.Status = StateOffline, "offline"
	}
	return r
}

func pveVM(vmid int, st State) Resource {
	r := Resource{Type: TypeQEMU, Node: "pve1", VMID: vmid, Name: fmt.Sprint("vm", vmid), State: st, Status: "running",
		CPU: 0.1, Mem: 100, MaxMem: 1000}
	switch st {
	case StateStopped:
		r.Status, r.CPU, r.Mem = "stopped", 0, 0
	case StatePaused:
		r.QMP = "paused"
	case StateError:
		r.QMP = "guest-panicked"
	case StateUnknown:
		r.Status = "unknown"
	}
	return r
}

func TestRulesUnreachable(t *testing.T) {
	p := newPveRun(t)
	p.expect(p.snap(true, pveNode("pve1", true)), "")
	p.expect(p.snap(false), "")
	evs := p.snap(false)
	p.expect(evs, "down:unreachable:")
	if evs[0].Name != "Lab" || !strings.Contains(evs[0].Text, "nicht erreichbar: timeout") || evs[0].SystemID != 1 {
		t.Fatalf("Ereignis: %+v", evs[0])
	}
	p.expect(p.snap(false), "")
	p.expect(p.snap(true, pveNode("pve1", true)), "up:unreachable:")
	// kurzer Aussetzer unter der Verzoegerung: nichts
	p.expect(p.snap(false), "")
	p.expect(p.snap(true, pveNode("pve1", true)), "")
	// abgeschaltet: keine Meldung, auch keine Entwarnung
	p.item("").Rules.Unreachable = pveBool(false)
	p.snap(false)
	p.expect(p.snap(false), "")
	p.expect(p.snap(true), "")
}

func TestRulesStoppedDelayAndUp(t *testing.T) {
	p := newPveRun(t)
	p.expect(p.snap(true, pveVM(100, StateRunning)), "")
	p.expect(p.snap(true, pveVM(100, StateStopped)), "") // Verzoegerung 2
	evs := p.snap(true, pveVM(100, StateStopped))
	p.expect(evs, "down:stopped:qemu/100")
	if evs[0].Text != "VM 100 „vm100“ ist gestoppt" || !evs[0].Since.Equal(p.now.Add(-30*time.Second)) {
		t.Fatalf("Ereignis: %+v", evs[0])
	}
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	evs = p.snap(true, pveVM(100, StateRunning))
	p.expect(evs, "up:stopped:qemu/100")
	if evs[0].Text != "VM 100 „vm100“ läuft wieder" {
		t.Fatalf("Entwarnung: %q", evs[0].Text)
	}
	// Verzoegerung 1 auf Gastebene
	one := 1
	p.item("qemu/100").Rules.Delay = &one
	p.expect(p.snap(true, pveVM(100, StateStopped)), "down:stopped:qemu/100")
	// Regel aus: kein Ausfall
	p.snap(true, pveVM(100, StateRunning))
	p.item("qemu/100").Rules.Stopped = pveBool(false)
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
}

func TestRulesExpectRunning(t *testing.T) {
	p := newPveRun(t)
	// nie gelaufen: nichts
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	}
	// fest erwartet
	p.item("qemu/100").ExpectRunning = pveBool(true)
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateStopped)), "down:stopped:qemu/100")
	// gespeichert „lief schon“ (nach Neustart von Node64)
	q := newPveRun(t)
	q.item("qemu/101").SeenRunning = true
	q.snap(true, pveVM(101, StateStopped))
	q.expect(q.snap(true, pveVM(101, StateStopped)), "down:stopped:qemu/101")
	// fest nicht erwartet, obwohl gelaufen
	r := newPveRun(t)
	r.item("qemu/102").ExpectRunning = pveBool(false)
	r.snap(true, pveVM(102, StateRunning))
	r.snap(true, pveVM(102, StateStopped))
	r.expect(r.snap(true, pveVM(102, StateStopped)), "")
}

func TestRulesCrashedPausedSuspended(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(100, StateRunning), pveVM(101, StateRunning), pveVM(102, StateRunning))
	evs := p.snap(true, pveVM(100, StateError), pveVM(101, StatePaused), pveVM(102, StateSuspended))
	p.expect(evs, "down:crashed:qemu/100") // Absturz ohne Verzoegerung
	if !strings.Contains(evs[0].Text, "abgestürzt (guest-panicked)") {
		t.Fatalf("Text: %q", evs[0].Text)
	}
	p.expect(p.snap(true, pveVM(100, StateStopped), pveVM(101, StatePaused), pveVM(102, StateSuspended)),
		"down:paused:qemu/101,down:suspended:qemu/102")
	p.expect(p.snap(true, pveVM(100, StateRunning), pveVM(101, StateRunning), pveVM(102, StateRunning)),
		"up:crashed:qemu/100,up:paused:qemu/101,up:suspended:qemu/102")
	// Absturz abgeschaltet
	p.item("").Rules.Crashed = pveBool(false)
	p.expect(p.snap(true, pveVM(100, StateError), pveVM(101, StateRunning), pveVM(102, StateRunning)), "")
}

func TestRulesLock(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(100, StateRunning))
	bk := pveVM(100, StateBackup)
	bk.Lock = "backup"
	for i := 0; i < 3; i++ {
		p.expect(p.snap(true, bk), "") // laeuft mit Backup: ok
	}
	// Backup im Stopp-Modus: gestoppt mit Lock ist kein Ausfall
	bk.Status = "stopped"
	for i := 0; i < 3; i++ {
		p.expect(p.snap(true, bk), "")
	}
	// direkt nach dem Lock zaehlt die erste Abfrage nicht
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateStopped)), "down:stopped:qemu/100")
	mig := pveVM(100, StateLocked)
	mig.Lock = "migrate"
	p.expect(p.snap(true, mig), "up:stopped:qemu/100") // laeuft (mit Lock) wieder
}

// Backup eines gestoppten Gasts: Proxmox startet ihn kurz (lock=backup) – danach ist „gestoppt“ keine Stoerung.
func TestRulesBackupOfStoppedGuest(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(103, StateStopped))
	bk := pveVM(103, StateBackup)
	bk.Lock = "backup"
	p.expect(p.snap(true, bk), "")
	p.expect(p.snap(true, bk), "")
	after := pveVM(103, StateRunning) // Lock schon weg, VM noch nicht beendet
	after.AfterLock = true
	p.expect(p.snap(true, after), "")
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, pveVM(103, StateStopped)), "")
	}
	// laeuft spaeter von sich aus: dann gilt er als „lief schon einmal“
	p.snap(true, pveVM(103, StateRunning))
	p.snap(true, pveVM(103, StateStopped))
	p.expect(p.snap(true, pveVM(103, StateStopped)), "down:stopped:qemu/103")
}

// „Gestoppt ist richtig“: ExpectRunning aus erledigt eine offene Stoerung still, auch spaeter keine Entwarnung.
func TestRulesAckStopped(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(103, StateRunning))
	p.snap(true, pveVM(103, StateStopped))
	p.expect(p.snap(true, pveVM(103, StateStopped)), "down:stopped:qemu/103")
	if _, ok := p.e.Outage(1, "qemu/103"); !ok {
		t.Fatal("Stoerung nicht gemerkt")
	}
	p.item("qemu/103").ExpectRunning = pveBool(false)
	p.expect(p.snap(true, pveVM(103, StateStopped)), "")
	if _, ok := p.e.Outage(1, "qemu/103"); ok {
		t.Fatal("Stoerung nach „gestoppt ist richtig“ noch offen")
	}
	if es := p.e.Export(1); es != nil && es.Res["qemu/103"].What != "" {
		t.Fatalf("Export: %+v", es)
	}
	p.expect(p.snap(true, pveVM(103, StateRunning)), "") // laeuft wieder: keine Entwarnung (war keine Stoerung)
	p.expect(p.snap(true, pveVM(103, StateStopped)), "")
	// Docker: beendet mit Fehler, soll nicht laufen
	d := newPveRun(t)
	run := Resource{Type: TypeDocker, Name: "web", State: StateRunning, Status: "running"}
	ex := Resource{Type: TypeDocker, Name: "web", State: StateError, Status: "exited", Detail: DockerExited, ExitCode: 1}
	d.snap(true, run)
	d.expect(d.snap(true, ex), "down:exited:docker/web")
	d.item("docker/web").ExpectRunning = pveBool(false)
	d.expect(d.snap(true, ex), "")
	d.expect(d.snap(true, run), "")
}

func TestRulesNodeOffline(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveNode("pve1", true), pveVM(100, StateRunning))
	unk := pveVM(100, StateUnknown)
	p.expect(p.snap(true, pveNode("pve1", false), unk), "")
	evs := p.snap(true, pveNode("pve1", false), unk)
	p.expect(evs, "down:offline:node/pve1")
	if evs[0].Text != "Node „pve1“ ist offline" {
		t.Fatalf("Text: %q", evs[0].Text)
	}
	for i := 0; i < 3; i++ {
		p.expect(p.snap(true, pveNode("pve1", false), unk), "") // kein Alarm je Gast
	}
	// Node wieder da, Gast nicht gestartet → nach Verzoegerung gemeldet
	p.expect(p.snap(true, pveNode("pve1", true), pveVM(100, StateStopped)), "up:offline:node/pve1")
	p.expect(p.snap(true, pveNode("pve1", true), pveVM(100, StateStopped)), "down:stopped:qemu/100")
}

// Node absichtlich offline (Wartung, ExpectRunning aus): keine Stoerung; eine offene erledigt sich still, ohne Entwarnung.
func TestRulesNodeMaintenance(t *testing.T) {
	p := newPveRun(t)
	off := false
	p.snap(true, pveNode("pve1", true), pveNode("pve2", true))
	p.item("node/pve2").ExpectRunning = &off
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, pveNode("pve1", true), pveNode("pve2", false)), "")
	}
	p.expect(p.snap(true, pveNode("pve1", true), pveNode("pve2", true)), "") // wieder da: keine Entwarnung
	// gemeldete Stoerung, danach „offline ist richtig“: still erledigt
	p.set.Items["node/pve2"].ExpectRunning = nil
	p.snap(true, pveNode("pve1", true), pveNode("pve2", false))
	p.expect(p.snap(true, pveNode("pve1", true), pveNode("pve2", false)), "down:offline:node/pve2")
	p.set.Items["node/pve2"].ExpectRunning = &off
	p.expect(p.snap(true, pveNode("pve1", true), pveNode("pve2", false)), "")
	p.expect(p.snap(true, pveNode("pve1", true), pveNode("pve2", true)), "")
}

func TestRulesRestartedAsCheckMuted(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(100, StateRunning), pveVM(101, StateRunning))
	rs := pveVM(100, StateRunning)
	rs.Restarted, rs.Uptime = true, 20
	evs := p.snap(true, rs, pveVM(101, StateRunning))
	p.expect(evs, "restarted::qemu/100")
	if !evs[0].Since.Equal(p.now.Add(-20*time.Second)) || evs[0].Text != "VM 100 „vm100“ wurde neu gestartet" {
		t.Fatalf("Neustart: %+v", evs[0])
	}

	// als Check: keine Zustandsereignisse, Neustart und Schwellen weiter
	p.item("qemu/100").AsCheck = true
	p.expect(p.snap(true, rs, pveVM(101, StateRunning)), "restarted::qemu/100")
	p.snap(true, pveVM(100, StateStopped))
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateRunning)), "") // keine Entwarnung
	hot := pveVM(100, StateRunning)
	hot.Disk, hot.MaxDisk = 0, 1000
	hot.Mem = 990
	p.snap(true, hot)
	for i := 0; i < 25; i++ {
		if evs := p.snap(true, hot); len(evs) > 0 {
			p.expect(evs, "threshold:mem:qemu/100")
			return
		}
	}
	t.Fatal("Schwelle trotz AsCheck nicht gemeldet")
}

func TestRulesIgnored(t *testing.T) {
	p := newPveRun(t)
	tpl := pveVM(100, StateStopped)
	tpl.Template = true
	tag := pveVM(101, StateRunning)
	tag.Tags = []string{"prod", "NoMonitor"}
	p.item("qemu/102").Muted = true
	run := []Resource{tpl, tag, pveVM(102, StateRunning)}
	p.snap(true, run...)
	tag2 := tag
	tag2.State, tag2.Status = StateStopped, "stopped"
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, tpl, tag2, pveVM(102, StateError)), "")
	}
	// stumm aufgehoben: neue Basis, keine alte Meldung
	p.item("qemu/102").Muted = false
	p.expect(p.snap(true, pveVM(102, StateRunning)), "")
	p.expect(p.snap(true, pveVM(102, StateError)), "down:crashed:qemu/102")
	// ganzes System stumm
	p.item("").Muted = true
	p.expect(p.snap(false), "")
	p.expect(p.snap(false), "")
	p.expect(p.snap(true, pveVM(102, StateError)), "")
}

func TestRulesThresholds(t *testing.T) {
	p := newPveRun(t)
	ct := Resource{Type: TypeLXC, Node: "pve1", VMID: 200, Name: "ct", State: StateRunning, Status: "running", CPU: 0.95,
		Mem: 100, MaxMem: 1000, Disk: 950, MaxDisk: 1000}
	// Disk 90 %/0 min: nach Verzoegerung (2 Abfragen); CPU 90 %/10 min: erst nach 10 min
	p.expect(p.snap(true, ct), "")
	evs := p.snap(true, ct)
	p.expect(evs, "threshold:disk:lxc/200")
	if evs[0].Value != 95 || evs[0].Limit != 90 || !strings.Contains(evs[0].Text, "Disk 95 % (Grenze 90 %)") {
		t.Fatalf("Disk: %+v", evs[0])
	}
	var cpuAt int
	for i := 3; i <= 30; i++ {
		evs := p.snap(true, ct)
		if len(evs) > 0 {
			p.expect(evs, "threshold:cpu:lxc/200")
			cpuAt = i
			break
		}
	}
	if cpuAt != 21 { // 1. Abfrage + 10 min = 21. Abfrage bei 30 s
		t.Fatalf("CPU-Schwelle bei Abfrage %d", cpuAt)
	}
	// ein Ausreisser nach unten setzt nichts zurueck, zwei Abfragen darunter = Entwarnung
	low := ct
	low.CPU, low.Disk = 0.2, 100
	p.expect(p.snap(true, low), "")
	p.expect(p.snap(true, ct), "")
	p.expect(p.snap(true, low), "")
	evs = p.snap(true, low)
	p.expect(evs, "threshold_ok:cpu:lxc/200,threshold_ok:disk:lxc/200")
	if !strings.Contains(evs[0].Text, "CPU wieder unter 90 % (20 %)") {
		t.Fatalf("Entwarnung: %q", evs[0].Text)
	}
	// Dauer unterbrochen: CPU 9 min hoch, kurz runter, wieder hoch → zaehlt neu
	for i := 0; i < 18; i++ {
		p.expect(p.snap(true, pveWithDisk(ct, 100)), "")
	}
	p.snap(true, low)
	for i := 0; i < 18; i++ {
		p.expect(p.snap(true, pveWithDisk(ct, 100)), "")
	}
	// QEMU ohne Gast-Agent (Disk 0): keine Disk-Schwelle
	vm := pveVM(100, StateRunning)
	vm.MaxDisk = 1000
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, vm), "")
	}
	// eigene Regel aus (0 %): keine RAM-Schwelle
	p.item("lxc/200").Rules.Mem = &Threshold{0, 0}
	full := pveWithDisk(ct, 100)
	full.CPU, full.Mem = 0, 1000
	for i := 0; i < 4; i++ {
		p.expect(p.snap(true, full), "")
	}
}

func pveWithDisk(r Resource, d int64) Resource { r.Disk = d; return r }

// Gemeldete Stoerungen ueberstehen einen Neustart: Export → Import, danach keine zweite Meldung, nur die Entwarnung.
func TestEngineExportImport(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	snap := func(st State, qmp string, cpu float64, ok bool) *Snapshot {
		s := &Snapshot{SystemID: 1, Time: now, OK: ok}
		if ok {
			s.Resources = []Resource{{Type: TypeNode, Node: "n", Name: "n", State: StateOnline, Status: "online", CPU: cpu, MaxMem: 1},
				{Type: TypeQEMU, VMID: 100, Node: "n", Name: "web", State: st, Status: "running", QMP: qmp, CPU: 0.1, MaxMem: 1}}
		}
		now = now.Add(time.Minute)
		return s
	}
	e := NewEngine()
	if e.Export(1) != nil {
		t.Fatal("export of unknown system")
	}
	e.Evaluate(snap(StateRunning, "running", 0.1, true), nil)
	evs := e.Evaluate(snap(StateError, "io-error", 0.1, true), nil)
	if len(evs) != 1 || evs[0].What != WhatCrashed || evs[0].Detail != "io-error" {
		t.Fatalf("crash event: %+v", evs)
	}
	for i := 0; i < 12; i++ { // CPU des Nodes ueber 90 % fuer mehr als 10 min
		e.Evaluate(snap(StateError, "io-error", 0.99, true), nil)
	}
	st := e.Export(1)
	if st == nil || st.Res["qemu/100"].What != WhatCrashed || st.Res["node/n"].Thr["cpu"].Limit != 90 {
		t.Fatalf("export: %+v", st)
	}
	e2 := NewEngine()
	e2.Import(1, st)
	if evs := e2.Evaluate(snap(StateError, "io-error", 0.99, true), nil); len(evs) != 0 {
		t.Fatalf("after import: reported again: %+v", evs)
	}
	evs = e2.Evaluate(snap(StateRunning, "running", 0.1, true), nil)
	if len(evs) != 1 || evs[0].Kind != KindUp {
		t.Fatalf("up after import: %+v", evs)
	}
	evs = e2.Evaluate(snap(StateRunning, "running", 0.1, true), nil)
	if len(evs) != 1 || evs[0].Kind != KindThresholdOK {
		t.Fatalf("threshold ok after import: %+v", evs)
	}
	if e2.Export(1) != nil {
		t.Fatal("nothing open any more")
	}
	// System nicht erreichbar
	e3 := NewEngine()
	e3.Evaluate(snap(StateRunning, "", 0, false), nil)
	e3.Evaluate(snap(StateRunning, "", 0, false), nil)
	st = e3.Export(1)
	if st == nil || !st.Down {
		t.Fatalf("unreachable export: %+v", st)
	}
	e4 := NewEngine()
	e4.Import(1, st)
	if evs := e4.Evaluate(snap(StateRunning, "", 0, false), nil); len(evs) != 0 {
		t.Fatalf("unreachable again: %+v", evs)
	}
	if evs := e4.Evaluate(snap(StateRunning, "running", 0, true), nil); len(evs) != 1 || evs[0].Kind != KindUp || evs[0].What != WhatUnreachable {
		t.Fatalf("reachable again: %+v", evs)
	}
	e4.Import(1, nil) // nil aendert nichts
}

// Waehrend AsCheck bzw. abgeschalteter Regel erkannte Stoerung wird nachgeholt, sobald AsCheck aus bzw. die Regel an
// ist (sonst kaeme nie eine Meldung); eine vom Check gemeldete Stoerung (Adopt) nicht noch einmal.
func TestRulesPendingOutage(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(100, StateRunning))
	p.item("qemu/100").AsCheck = true
	p.snap(true, pveVM(100, StateStopped))
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.item("qemu/100").AsCheck = false
	evs := p.snap(true, pveVM(100, StateStopped))
	p.expect(evs, "down:stopped:qemu/100")
	if !evs[0].Since.Equal(p.now.Add(-60 * time.Second)) {
		t.Fatalf("Since: %v", evs[0].Since)
	}
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateRunning)), "up:stopped:qemu/100")

	// Check hatte gemeldet: Engine uebernimmt (Adopt), meldet nur die Entwarnung
	p.item("qemu/100").AsCheck = true
	p.snap(true, pveVM(100, StateStopped))
	p.snap(true, pveVM(100, StateStopped))
	p.e.Adopt(1, "qemu/100")
	p.item("qemu/100").AsCheck = false
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateRunning)), "up:stopped:qemu/100")
	p.e.Adopt(1, "qemu/100") // laeuft: nichts zu uebernehmen
	p.expect(p.snap(true, pveVM(100, StateRunning)), "")

	// „nicht erreichbar“ abgeschaltet, waehrend es passiert, dann wieder an: Meldung nachgeholt
	q := newPveRun(t)
	q.item("").Rules.Unreachable = pveBool(false)
	q.snap(false)
	q.expect(q.snap(false), "")
	q.item("").Rules.Unreachable = nil
	q.expect(q.snap(false), "down:unreachable:")
	q.expect(q.snap(true), "up:unreachable:")
}

// Als Check meldet die Engine keine Entwarnung (der Check meldet sie); eine schon gemeldete Stoerung gibt Outage
// heraus, damit der neue Check sie uebernimmt statt sie noch einmal zu melden.
func TestRulesAsCheckNoDuplicateUp(t *testing.T) {
	p := newPveRun(t)
	p.snap(true, pveVM(100, StateRunning))
	p.snap(true, pveVM(100, StateStopped))
	p.expect(p.snap(true, pveVM(100, StateStopped)), "down:stopped:qemu/100")
	since, ok := p.e.Outage(1, "qemu/100")
	if !ok || !since.Equal(p.now.Add(-30*time.Second)) {
		t.Fatalf("Outage: %v %v", since, ok)
	}
	if _, ok := p.e.Outage(1, "qemu/101"); ok {
		t.Fatal("Outage ohne Stoerung")
	}
	p.item("qemu/100").AsCheck = true
	p.expect(p.snap(true, pveVM(100, StateStopped)), "")
	p.expect(p.snap(true, pveVM(100, StateRunning)), "") // Entwarnung kommt ueber den Check
	if _, ok := p.e.Outage(1, "qemu/100"); ok {
		t.Fatal("Stoerung nach Entwarnung offen")
	}
	p.item("qemu/100").AsCheck = false
	p.expect(p.snap(true, pveVM(100, StateRunning)), "")
}

// Die Verzoegerung „nicht erreichbar“ zaehlt auch zeitlich: schnelle Wiederholungen nach Fehlern (5 s, 10 s …)
// melden nicht schon nach Sekunden.
func TestRulesUnreachableDelayByTime(t *testing.T) {
	e := NewEngine()
	set := &SystemSettings{SystemID: 1, Name: "Lab"}
	t0 := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	at := func(sec int, ok bool) string {
		return pveEvStr(e.Evaluate(&Snapshot{SystemID: 1, Time: t0.Add(time.Duration(sec) * time.Second), OK: ok, Interval: 30 * time.Second}, set))
	}
	at(0, true)
	for _, sec := range []int{1, 6, 16} { // Backoff 5 s, 10 s
		if got := at(sec, false); got != "" {
			t.Fatalf("%d s: %q zu frueh", sec, got)
		}
	}
	if got := at(31, false); got != "down:unreachable:" { // 30 s nach dem ersten Fehler (Delay 2 × 30 s Intervall)
		t.Fatalf("31 s: %q", got)
	}
}
