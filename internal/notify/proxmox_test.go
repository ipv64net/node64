package notify

import (
	"strings"
	"testing"
	"time"
)

// Proxmox VE: eigene Arten (Modul-Meldungen), Text ueber pve.ev.<Art>.<Ursache>, Absturz mit hoher Prioritaet.
func TestProxmoxAlerts(t *testing.T) {
	for _, k := range []Kind{KindProxmoxDown, KindProxmoxUp, KindProxmoxThreshold, KindProxmoxThresholdOK, KindProxmoxRestarted} {
		if !IsProxmox(k) || !IsModule(k) {
			t.Fatalf("%s must be a proxmox module kind", k)
		}
	}
	if !isDownKind(KindProxmoxDown) || !isDownKind(KindProxmoxThreshold) || isDownKind(KindProxmoxUp) || isDownKind(KindProxmoxThresholdOK) || isDownKind(KindProxmoxRestarted) {
		t.Fatal("down kinds")
	}
	d, st, rec := testDispatcher(t, map[string]string{SetBaseURL: "https://node.example"})
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "lab – app", Type: "proxmox", Target: "qemu/102", NotifyDown: true, NotifyUp: true, Local: true, Critical: true}
	d.Dispatch(Alert{EventID: "p1", Kind: KindProxmoxDown, Check: info, Time: time.Now(), Reason: "crashed",
		Data: map[string]string{"what": "crashed", "type": "qemu", "name": "app", "system": "lab", "detail": "guest-panicked", "path": "/healthchecks/proxmox/system/3/res/qemu/102"}})
	msgs := waitMsgs(t, rec, 1)
	m := msgs[0]
	if m.Kind != KindProxmoxDown || m.Priority != 5 || m.URL != "https://node.example/healthchecks/proxmox/system/3/res/qemu/102" ||
		!strings.Contains(m.Text, "pve.ev.down.crashed") && !strings.Contains(m.Text, "app") {
		t.Fatalf("crash message: %+v", m)
	}
	if !strings.Contains(m.Title, "lab – app") && m.Title != "notify.subject.proxmox_down" { // Texte kommen aus docs/tmp-pve-i18n.json in die Locales
		t.Fatalf("title: %q", m.Title)
	}
	if px, _ := m.Payload["proxmox"].(map[string]string); px["detail"] != "guest-panicked" {
		t.Fatalf("payload: %+v", m.Payload)
	}
	// Schwelle (Prioritaet 4), Entwarnung (2), Neustart (3); fremder Pfad faellt auf die Uebersicht zurueck
	info.Critical = false
	d.Dispatch(Alert{EventID: "p2", Kind: KindProxmoxThreshold, Check: info, Time: time.Now(), Data: map[string]string{"what": "cpu", "type": "qemu", "value": "97.5", "limit": "90", "path": "https://evil/"}})
	d.Dispatch(Alert{EventID: "p3", Kind: KindProxmoxThresholdOK, Check: info, Time: time.Now(), Data: map[string]string{"what": "cpu", "type": "qemu"}})
	d.Dispatch(Alert{EventID: "p4", Kind: KindProxmoxRestarted, Check: info, Time: time.Now(), Data: map[string]string{"type": "lxc"}})
	msgs = waitMsgs(t, rec, 4)
	prio := map[Kind]int{}
	for _, x := range msgs {
		prio[x.Kind] = x.Priority
		if x.Kind == KindProxmoxThreshold && x.URL != "https://node.example/healthchecks/proxmox" {
			t.Fatalf("path not limited: %q", x.URL)
		}
	}
	if prio[KindProxmoxThreshold] != 4 || prio[KindProxmoxThresholdOK] != 2 || prio[KindProxmoxRestarted] != 3 {
		t.Fatalf("priorities: %v", prio)
	}
}

// Ruhezeit: Proxmox-Meldungen werden wie Check-Meldungen gemerkt und danach als Sammelmeldung verschickt (je Gast der
// letzte Stand getrennt nach Zustand, Schwelle und Neustart; eigene Kanalwahl; Link auf die Proxmox-Seite). Andere
// Modul-Meldungen (DynDNS) entfallen weiter.
func TestProxmoxQuietHours(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC)}
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7",
		SetQuietTZ: "UTC", SetBaseURL: "https://node.example"})
	d.now = clk.now
	addChannel(t, st, "default", true)
	ops := addChannel(t, st, "ops", false)
	app := CheckInfo{Name: "lab – app", Type: "proxmox", Target: "qemu/102", NotifyDown: true, NotifyUp: true, Local: true}
	db := CheckInfo{Name: "lab – db", Type: "proxmox", Target: "lxc/200", NotifyDown: true, NotifyUp: true, Local: true}
	pve1 := CheckInfo{Name: "lab – pve1", Type: "proxmox", Target: "node/pve1", NotifyDown: true, NotifyUp: true, Local: true}
	web := CheckInfo{Name: "lab – web", Type: "proxmox", Target: "qemu/105", NotifyDown: true, NotifyUp: true, Local: true, Channels: []int64{ops.ID}}
	pa := func(k string) string { return "/healthchecks/proxmox/system/3/res/" + k }
	now := clk.now()
	d.Dispatch(Alert{EventID: "q1", Kind: KindProxmoxDown, Check: app, Time: now, Data: map[string]string{"what": "crashed", "type": "qemu", "name": "app", "detail": "guest-panicked", "path": pa("qemu/102")}})
	d.Dispatch(Alert{EventID: "q2", Kind: KindProxmoxThreshold, Check: app, Time: now, Data: map[string]string{"what": "cpu", "type": "qemu", "name": "app", "value": "97.5", "limit": "90", "path": pa("qemu/102")}})
	d.Dispatch(Alert{EventID: "q3", Kind: KindProxmoxDown, Check: db, Time: now, Data: map[string]string{"what": "stopped", "type": "lxc", "name": "db", "path": pa("lxc/200")}})
	d.Dispatch(Alert{EventID: "q4", Kind: KindProxmoxUp, Check: db, Time: now.Add(time.Hour), Data: map[string]string{"what": "stopped", "type": "lxc", "name": "db", "path": pa("lxc/200")}})
	d.Dispatch(Alert{EventID: "q5", Kind: KindProxmoxRestarted, Check: pve1, Time: now, Data: map[string]string{"type": "node", "name": "pve1", "path": pa("node/pve1")}})
	d.Dispatch(Alert{EventID: "q6", Kind: KindProxmoxDown, Check: web, Time: now, Data: map[string]string{"what": "paused", "type": "qemu", "name": "web", "path": pa("qemu/105")}})
	d.Dispatch(Alert{EventID: "q7", Kind: KindDynFail, Check: CheckInfo{Name: "IPv4", NotifyDown: true, NotifyUp: true, Local: true}, Time: now, Reason: "badauth"})
	time.Sleep(300 * time.Millisecond)
	if n := len(rec.list()); n != 0 {
		t.Fatalf("nothing may be sent during quiet hours, got %d: %+v", n, rec.list())
	}
	clk.set(time.Date(2026, 1, 8, 7, 1, 0, 0, time.UTC))
	msgs := waitMsgs(t, rec, 2)
	time.Sleep(200 * time.Millisecond)
	if msgs = rec.list(); len(msgs) != 2 { // je Kanal eine Sammelmeldung, DynDNS verworfen
		t.Fatalf("expected two digests, got %d: %+v", len(msgs), msgs)
	}
	by := map[string]Message{}
	for _, m := range msgs {
		by[m.Check.Target] = m // recorder: Target = Kanalname
	}
	m := by["default"]
	title := "notify.subject.quiet_digest_events" // Text kommt aus docs/tmp-pve-ch-i18n.json in die Locales
	if m.Kind != KindSummary || (m.Title != title && !strings.Contains(m.Title, "4 Meldungen")) || m.URL != "https://node.example/healthchecks/proxmox" ||
		!strings.Contains(m.Text, "lab – app: gestört seit") || !strings.Contains(m.Text, "abgestürzt (guest-panicked)") ||
		!strings.Contains(m.Text, "CPU 97.5 %") || !strings.Contains(m.Text, "lab – db: war gestört, wieder OK") ||
		!strings.Contains(m.Text, "lab – pve1: Node „pve1“ wurde neu gestartet") || strings.Contains(m.Text, "lab – web") {
		t.Fatalf("digest default channel: %+v", m)
	}
	if strings.Count(m.Text, "lab – app") != 2 { // Zustand und Schwelle getrennt
		t.Fatalf("app lines: %q", m.Text)
	}
	if p, _ := m.Payload["down"].(int); p != 2 {
		t.Fatalf("still down: %+v", m.Payload)
	}
	w := by["ops"]
	if w.Kind != KindSummary || w.URL != "https://node.example"+pa("qemu/105") || !strings.Contains(w.Text, "lab – web: gestört seit") ||
		!strings.Contains(w.Text, "angehalten") || strings.Contains(w.Text, "lab – app") {
		t.Fatalf("digest ops channel: %+v", w)
	}
}

// Ruhezeit nur mit Entwarnungen: Sammelmeldung der Entwarnungen (summary_up), Link auf den Gast.
func TestProxmoxQuietHoursRecovered(t *testing.T) {
	clk := &testClock{t: time.Date(2026, 1, 7, 23, 30, 0, 0, time.UTC)}
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "22:00", SetQuietTo: "07:00", SetQuietDays: "1,2,3,4,5,6,7",
		SetQuietTZ: "UTC", SetBaseURL: "https://node.example"})
	d.now = clk.now
	addChannel(t, st, "default", true)
	app := CheckInfo{Name: "lab – app", Type: "proxmox", Target: "qemu/102", NotifyDown: true, NotifyUp: true, Local: true}
	path := "/healthchecks/proxmox/system/3/res/qemu/102"
	d.Dispatch(Alert{EventID: "r1", Kind: KindProxmoxThreshold, Check: app, Time: clk.now(), Data: map[string]string{"what": "mem", "type": "qemu", "name": "app", "value": "99", "limit": "95", "path": path}})
	d.Dispatch(Alert{EventID: "r2", Kind: KindProxmoxThresholdOK, Check: app, Time: clk.now().Add(time.Minute), Data: map[string]string{"what": "mem", "type": "qemu", "name": "app", "value": "60", "limit": "95", "path": path}})
	time.Sleep(200 * time.Millisecond)
	clk.set(time.Date(2026, 1, 8, 7, 1, 0, 0, time.UTC))
	m := waitMsgs(t, rec, 1)[0]
	if m.Kind != KindSummaryUp || m.URL != "https://node.example"+path || !strings.Contains(m.Text, "lab – app: war gestört, wieder OK") {
		t.Fatalf("recovered digest: %+v", m)
	}
}
