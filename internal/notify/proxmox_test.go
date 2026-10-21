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

// Ruhezeit: Proxmox-Meldungen entfallen wie andere Modul-Meldungen, ein Absturz (kritisch) kommt trotzdem.
func TestProxmoxQuietHours(t *testing.T) {
	d, st, rec := testDispatcher(t, map[string]string{SetQuietEnabled: "1", SetQuietFrom: "00:00", SetQuietTo: "23:59"})
	addChannel(t, st, "default", true)
	info := CheckInfo{Name: "lab – db", Type: "proxmox", NotifyDown: true, NotifyUp: true, Local: true}
	d.Dispatch(Alert{EventID: "q1", Kind: KindProxmoxDown, Check: info, Time: time.Now(), Data: map[string]string{"what": "stopped", "type": "qemu"}})
	info.Critical = true
	d.Dispatch(Alert{EventID: "q2", Kind: KindProxmoxDown, Check: info, Time: time.Now(), Data: map[string]string{"what": "crashed", "type": "qemu"}})
	msgs := waitMsgs(t, rec, 1)
	time.Sleep(100 * time.Millisecond)
	if msgs = rec.list(); len(msgs) != 1 || msgs[0].Priority != 5 {
		t.Fatalf("quiet hours: %+v", msgs)
	}
}
