package healthchecks

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

// setSelfID setzt die eigene Kennung (zwei Module in einem Prozess teilen sie).
func setSelfID(t *testing.T, id string) {
	t.Helper()
	self.Lock()
	old := self.id
	self.id = id
	self.Unlock()
	t.Cleanup(func() {
		self.Lock()
		self.id = old
		self.Unlock()
	})
}

// Proxmox VE ueber den Cluster: System samt Token von A nach B (dort mit B's Schluessel), Kennung gleich, Heim-Node A
// meldet; Proxmox-Check findet das System ueber die Kennung; Loeschen kommt an; lokaler Docker-Socket bleibt.
func TestPVEClusterSync(t *testing.T) {
	ctx := context.Background()
	fake := newPVEFake()
	fsrv := startPVEFake(t, fake)
	coreA, coreB := pveCore(t), pveCore(t)
	mA, srvA, _ := newPVEModule(t, coreA, pveBox(t, 1))
	mB, _, _ := newPVEModule(t, coreB, pveBox(t, 2))
	const nodeA, nodeB, nodeC = "nodeA_0123456789abcdef", "nodeB_0123456789abcdef", "nodeC_0123456789abcdef"
	var changes []string
	homeOnline := true
	mA.SetCluster(ClusterHooks{
		Change: func(_ context.Context, item, id string, deleted bool) {
			changes = append(changes, item+"/"+id+map[bool]string{true: " del", false: ""}[deleted])
		},
		Members: func(context.Context, string) []Peer { return []Peer{{ID: nodeB, Online: true}} },
	})
	mB.SetCluster(ClusterHooks{
		Change:  func(context.Context, string, string, bool) {},
		Members: func(context.Context, string) []Peer { return []Peer{{ID: nodeA, Online: homeOnline}} },
	})

	setSelfID(t, nodeA)
	id := pveCreate(t, srvA, fsrv)
	sysA, err := mA.pve.st.System(ctx, id)
	if err != nil || !proxmox.ValidUID(sysA.UID) || sysA.Home != "" {
		t.Fatalf("system on A: %+v %v", sysA, err)
	}
	uid := sysA.UID
	if len(changes) != 1 || changes[0] != "proxmox/"+uid {
		t.Fatalf("change hook: %v", changes)
	}
	// lokaler Docker-Socket geht nicht in den Cluster, ein Docker-Host ueber das Netz schon
	local := &proxmox.System{Kind: proxmox.KindDocker, Name: "local", Addresses: []string{checks.DefaultDockerHost()}, Interval: 30, Enabled: true}
	remote := &proxmox.System{Kind: proxmox.KindDocker, Name: "nas", Addresses: []string{"tcp://192.0.2.7:2375"}, Interval: 30, Enabled: true}
	for _, s := range []*proxmox.System{local, remote} {
		if err := mA.pveSaveSystemBy(ctx, s, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if ids, _ := mA.ClusterIDs(ctx, ClusterItemDocker); len(ids) != 1 || ids[0] != remote.UID {
		t.Fatalf("docker ids: %v (local %s)", ids, local.UID)
	}
	if _, found, _ := mA.ClusterGet(ctx, ClusterItemDocker, local.UID); found {
		t.Fatal("local socket must not be shared")
	}
	if ids, _ := mA.ClusterIDs(ctx, ClusterItemProxmox); len(ids) != 1 || ids[0] != uid {
		t.Fatalf("proxmox ids: %v", ids)
	}
	data, found, err := mA.ClusterGet(ctx, ClusterItemProxmox, uid)
	if err != nil || !found || !strings.Contains(string(data), pveTestSecret) || !strings.Contains(string(data), `"home":"`+nodeA+`"`) {
		t.Fatalf("cluster data: %s %v", data, err)
	}

	// B uebernimmt: gleiche Kennung, Token mit B's Schluessel verschluesselt, Heim-Node A, Abfrage laeuft
	setSelfID(t, nodeB)
	if err := mB.ClusterApply(ctx, ClusterItemDocker, uid, data, false); err == nil {
		t.Fatal("wrong area must be refused")
	}
	if err := mB.ClusterApply(ctx, ClusterItemProxmox, uid, data, false); err != nil {
		t.Fatal(err)
	}
	sysB, err := mB.pve.st.SystemByUID(ctx, uid)
	if err != nil || sysB.Secret != pveTestSecret || sysB.Home != nodeA || sysB.TokenID != pveTestToken {
		t.Fatalf("system on B: %+v %v", sysB, err)
	}
	var raw string
	_ = coreB.Reader().QueryRowContext(ctx, `SELECT secret FROM pve_systems WHERE uid = ?`, uid).Scan(&raw)
	if raw == "" || strings.Contains(raw, pveTestSecret) {
		t.Fatal("secret must be stored encrypted on B")
	}
	if pp, _ := mB.pvePollOf(sysB.ID); pp == nil {
		t.Fatal("B must poll the system")
	}
	if got, ok := mB.pveUIDOf(uid); !ok || got != sysB.ID {
		t.Fatalf("uid lookup: %d %v", got, ok)
	}
	// Meldungen: Heim-Node A, solange erreichbar; sonst die Node mit der kleinsten Kennung (hier B)
	if mB.pveNotifiesHere(ctx, sysB) {
		t.Fatal("home node A notifies")
	}
	homeOnline = false
	if !mB.pveNotifiesHere(ctx, sysB) {
		t.Fatal("home offline: B notifies")
	}
	setSelfID(t, nodeA)
	if !mA.pveNotifiesHere(ctx, sysA) {
		t.Fatal("A is home")
	}

	// Proxmox-Check mit Kennung: lokale ID ist egal; auf B ohne das System klar gestoert
	params, _ := json.Marshal(checks.ProxmoxParams{SystemID: 999, Key: "qemu/100", SystemUID: uid})
	r := checks.NewRunner()
	r.Proxmox, r.ProxmoxUID = mB.pveLookup, mB.pveUIDOf
	res := r.Run(ctx, checks.Definition{Type: checks.TypeProxmox, Target: "qemu/100", Params: params})[0]
	if res.Details["system_id"] != sysB.ID {
		t.Fatalf("check must use B's system: %+v", res)
	}
	other, _ := json.Marshal(checks.ProxmoxParams{SystemID: sysB.ID, Key: "qemu/100", SystemUID: strings.Repeat("0", 32)})
	if res := r.Run(ctx, checks.Definition{Type: checks.TypeProxmox, Target: "qemu/100", Params: other})[0]; res.Status != checks.Down ||
		!strings.Contains(res.Message, "not set up on this node") {
		t.Fatalf("unknown uid: %+v", res)
	}

	// Loeschen kommt an
	setSelfID(t, nodeB)
	if err := mB.ClusterApply(ctx, ClusterItemProxmox, uid, nil, true); err != nil {
		t.Fatal(err)
	}
	if _, err := mB.pve.st.SystemByUID(ctx, uid); err == nil {
		t.Fatal("system must be deleted on B")
	}

	// Messende Nodes eines Proxmox-Checks: Besitzerin vorn, nur Nodes mit dem Bereich
	setSelfID(t, nodeA)
	c := &Check{Type: checks.TypeProxmox, Nodes: []string{nodeC, nodeB}}
	if got := mA.clusterNodesOf(c, nil); !slices.Equal(got, []string{nodeA, nodeB}) {
		t.Fatalf("nodes: %v", got)
	}
	c.Nodes = []string{nodeB}
	if got := mA.clusterNodesOf(c, []string{nodeC}); !slices.Equal(got, []string{nodeC, nodeB}) {
		t.Fatalf("owner stays first: %v", got)
	}
	d := &Check{Type: checks.TypeDocker, Params: json.RawMessage(`{}`), Nodes: []string{nodeA, nodeB}}
	if got := mA.clusterNodesOf(d, nil); got != nil {
		t.Fatalf("local docker stays single: %v", got)
	}
	d.Params = json.RawMessage(`{"host":"tcp://192.0.2.7:2375"}`)
	if got := mA.clusterNodesOf(d, nil); !slices.Equal(got, []string{nodeA, nodeB}) {
		t.Fatalf("network docker: %v", got)
	}
	mA.SetCluster(ClusterHooks{})
	if got := mA.clusterNodesOf(d, nil); got != nil {
		t.Fatalf("without cluster: %v", got)
	}
}

// Ein Proxmox-Check von aussen ohne Kennung (hub, aeltere Node) behaelt die hier bekannte.
func TestKeepSystemUID(t *testing.T) {
	uid := strings.Repeat("a", 32)
	cur := &Check{Type: checks.TypeProxmox, Params: json.RawMessage(`{"system_id":3,"key":"qemu/1","system_uid":"` + uid + `"}`)}
	got := keepSystemUID(cur, json.RawMessage(`{"system_id":3,"key":"qemu/1","system":"lab"}`))
	var p checks.ProxmoxParams
	if json.Unmarshal(got, &p) != nil || p.SystemUID != uid || p.System != "lab" {
		t.Fatalf("kept: %s", got)
	}
	if got := keepSystemUID(nil, json.RawMessage(`{"system_id":3}`)); string(got) != `{"system_id":3}` {
		t.Fatalf("new check: %s", got)
	}
}
