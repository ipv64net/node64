package proxmox

import (
	"strings"
	"testing"
	"time"
)

// storeSnap: Proxmox-VE-Snapshot mit einem Node und Speichern (alle 30 s wie pveRun.snap).
func (p *pveRun) storeSnap(st ...PVEStorage) []Event {
	p.now = p.now.Add(30 * time.Second)
	p.set.Kind = KindPVE
	node := Resource{Type: TypeNode, Node: "pve1", Name: "pve1", State: StateOnline, Status: "online", CPU: 0.01, Mem: 1, MaxMem: 10,
		Disk: 1, MaxDisk: 10}
	return p.e.Evaluate(&Snapshot{SystemID: 1, Time: p.now, OK: true, Resources: []Resource{node}, Storages: st}, p.set)
}

func pveStore(node, name string, pct float64) PVEStorage {
	return PVEStorage{Storage: name, Node: node, Status: "available", Total: 1000, Used: int64(pct * 10)}
}

// Speicher eines Proxmox VE: Regel „Speicher belegt ab“ (datastore) wie beim PBS, je Speicher (lokal Node/Name,
// gemeinsam nur der Name); „voll in N Tagen“ gibt es nicht; nicht verfuegbar = ohne Werte.
func TestPVEStorageFill(t *testing.T) {
	p := newPveRun(t)
	days := 14
	p.item("").Rules.DatastoreDays = &days // gilt bei Proxmox VE nicht
	nfs := pveStore("", "nfs", 50)
	nfs.Shared = true
	p.expectDS(p.storeSnap(pveStore("pve1", "local-lvm", 91), pveStore("pve2", "local-lvm", 50), nfs), "")
	evs := p.storeSnap(pveStore("pve1", "local-lvm", 92), pveStore("pve2", "local-lvm", 50), nfs)
	p.expectDS(evs, "threshold:storage:pve1/local-lvm")
	if !strings.Contains(evs[0].Text, "Speicher „pve1/local-lvm“ 92 % belegt") || evs[0].Limit != 90 {
		t.Fatalf("Ereignis: %+v", evs[0])
	}
	nfs.Used = 960
	p.expectDS(p.storeSnap(pveStore("pve1", "local-lvm", 92), pveStore("pve2", "local-lvm", 50), nfs), "")
	p.expectDS(p.storeSnap(pveStore("pve1", "local-lvm", 92), pveStore("pve2", "local-lvm", 50), nfs), "threshold:storage:nfs")
	if a := p.e.DatastoreAlarm(1); !a["pve1/local-lvm"][0] || !a["nfs"][0] || a["pve2/local-lvm"][0] {
		t.Fatalf("DatastoreAlarm: %v", a)
	}
	// nicht verfuegbar: Stand bleibt, keine Entwarnung
	gone := pveStore("pve1", "local-lvm", 0)
	gone.Status = "unknown"
	p.expectDS(p.storeSnap(gone, nfs), "")
	p.expectDS(p.storeSnap(gone, nfs), "")
	if !p.e.DatastoreAlarm(1)["pve1/local-lvm"][0] {
		t.Fatal("Schwelle von pve1/local-lvm verloren")
	}
	// wieder da und unter 88 %: Entwarnung nach Delay
	p.expectDS(p.storeSnap(pveStore("pve1", "local-lvm", 80), nfs), "")
	p.expectDS(p.storeSnap(pveStore("pve1", "local-lvm", 80), nfs), "threshold_ok:storage:pve1/local-lvm")
	// System nicht erreichbar: nichts verworfen
	p.now = p.now.Add(30 * time.Second)
	p.e.Evaluate(&Snapshot{SystemID: 1, Time: p.now, OK: false}, p.set)
	if !p.e.DatastoreAlarm(1)["nfs"][0] {
		t.Fatal("Schwelle von nfs nach Ausfall verloren")
	}
}
