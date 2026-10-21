package checks

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func pveDef(id int64, key string) Definition {
	p, _ := json.Marshal(ProxmoxParams{SystemID: id, Key: key})
	return Definition{Token: "t", Type: TypeProxmox, Target: key, Params: p}
}

// Check-Typ proxmox: liest den Stand aus Runner.Proxmox, fragt Proxmox nicht selbst.
func TestProxmoxCheck(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	state := ProxmoxState{System: "lab", Polling: true, Reachable: true, Time: now, Interval: 30 * time.Second, Found: true, Node: "pve1", Name: "web"}
	r := NewRunner()
	r.Now = func() time.Time { return now.Add(10 * time.Second) }
	var asked []string
	r.Proxmox = func(id int64, key string) ProxmoxState {
		asked = append(asked, key)
		if id != 3 {
			return ProxmoxState{Error: "proxmox system not found"}
		}
		return state
	}
	cases := []struct {
		state, qmp string
		status     Status
		reason     Reason
	}{
		{"running", "running", Up, ReasonOK},
		{"backup", "", Up, ReasonOK},
		{"locked", "", Up, ReasonOK},
		{"stopped", "", Down, ReasonPVEStopped},
		{"paused", "paused", Down, ReasonPVEPaused},
		{"suspended", "", Down, ReasonPVESuspended},
		{"error", "guest-panicked", Down, ReasonPVECrashed},
		{"unknown", "", Down, ReasonPVEUnknown},
	}
	for _, c := range cases {
		state.State, state.QMP = c.state, c.qmp
		res := r.Run(context.Background(), pveDef(3, "qemu/100"))
		if len(res) != 1 || res[0].Status != c.status || res[0].Reason != c.reason {
			t.Fatalf("%s: %+v", c.state, res)
		}
		if c.state == "error" && !strings.Contains(res[0].Message, "guest-panicked") {
			t.Fatalf("crash message: %q", res[0].Message)
		}
	}
	// Node
	state.State = "online"
	if res := r.Run(context.Background(), pveDef(3, "node/pve1")); res[0].Status != Up {
		t.Fatalf("node online: %+v", res)
	}
	state.State = "offline"
	if res := r.Run(context.Background(), pveDef(3, "node/pve1")); res[0].Reason != ReasonPVEOffline {
		t.Fatalf("node offline: %+v", res)
	}
	// System nicht erreichbar, Stand zu alt, nicht abgefragt, Gast fehlt
	state.State, state.Reachable, state.Error = "running", false, "connection refused"
	if res := r.Run(context.Background(), pveDef(3, "qemu/100")); res[0].Reason != ReasonPVEUnreachable || !strings.Contains(res[0].Message, "connection refused") {
		t.Fatalf("unreachable: %+v", res)
	}
	state.Reachable, state.Error = true, ""
	r.Now = func() time.Time { return now.Add(10 * time.Minute) }
	if res := r.Run(context.Background(), pveDef(3, "qemu/100")); res[0].Reason != ReasonPVEUnreachable {
		t.Fatalf("stale: %+v", res)
	}
	r.Now = func() time.Time { return now }
	if res := r.Run(context.Background(), pveDef(4, "qemu/100")); res[0].Status != Down || res[0].Reason != ReasonPVEUnreachable || !strings.Contains(res[0].Message, "not found") {
		t.Fatalf("unknown system: %+v", res)
	}
	state.Found = false
	if res := r.Run(context.Background(), pveDef(3, "qemu/100")); res[0].Reason != ReasonPVEMissing {
		t.Fatalf("missing: %+v", res)
	}
	state.Found, state.Time = true, time.Time{}
	if res := r.Run(context.Background(), pveDef(3, "qemu/100")); res[0].Reason != ReasonPVEUnreachable {
		t.Fatalf("no data yet: %+v", res)
	}
	// ohne Proxmox-Ueberwachung (z. B. auf den ipv64-Servern)
	r.Proxmox = nil
	if res := r.Run(context.Background(), pveDef(3, "qemu/100")); res[0].Status != Down || res[0].Reason != ReasonPVEUnreachable {
		t.Fatalf("no source: %+v", res)
	}
	if len(asked) == 0 || asked[0] != "qemu/100" {
		t.Fatal("lookup not used")
	}
}

func TestProxmoxValidateAndPrivate(t *testing.T) {
	if err := Validate(pveDef(3, "lxc/200")); err != nil {
		t.Fatal(err)
	}
	for _, d := range []Definition{pveDef(0, "lxc/200"), pveDef(3, "storage/x"), pveDef(3, ""),
		{Type: TypeProxmox, Params: json.RawMessage(`{"system_id":1,"key":"qemu/1","x":1}`)}} {
		if err := Validate(d); err == nil {
			t.Fatalf("invalid accepted: %s", d.Params)
		}
	}
	if !IsPrivateTarget(string(TypeProxmox), "qemu/100") {
		t.Fatal("proxmox checks must stay local")
	}
}
