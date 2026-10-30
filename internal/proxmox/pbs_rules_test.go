package proxmox

import (
	"strings"
	"testing"
	"time"
)

// pbsSnap: PBS-Snapshot mit Host und Datastores (alle 30 s wie pveRun.snap).
func (p *pveRun) pbsSnap(ds ...PBSDatastore) []Event {
	p.now = p.now.Add(30 * time.Second)
	p.set.Kind = KindPBS
	host := Resource{Type: TypeNode, Node: pbsNode, Name: "Backup", State: StateOnline, Status: "online", CPU: 0.01, Mem: 1, MaxMem: 10,
		Disk: 1, MaxDisk: 10}
	return p.e.Evaluate(&Snapshot{SystemID: 1, Time: p.now, OK: true, Resources: []Resource{host}, PBS: &PBSInfo{Datastores: ds}}, p.set)
}

func pbsDS(store string, pct float64) PBSDatastore {
	return PBSDatastore{Store: store, Total: 1000, Used: int64(pct * 10), Avail: 1000 - int64(pct*10)}
}

func pbsEvStr(evs []Event) string {
	var b []string
	for _, e := range evs {
		b = append(b, e.Kind+":"+e.What+":"+e.Detail)
	}
	return strings.Join(b, ",")
}

func (p *pveRun) expectDS(evs []Event, want string) {
	p.t.Helper()
	if got := pbsEvStr(evs); got != want {
		p.t.Fatalf("Ereignisse: %q, erwartet %q", got, want)
	}
}

// Standard: belegt ab 90 %, Delay 2; Entwarnung erst unter 88 %; mehrere Datastores getrennt.
func TestPBSDatastoreFill(t *testing.T) {
	p := newPveRun(t)
	p.expectDS(p.pbsSnap(pbsDS("a", 91), pbsDS("b", 50)), "")
	evs := p.pbsSnap(pbsDS("a", 92), pbsDS("b", 95))
	p.expectDS(evs, "threshold:datastore:a")
	if evs[0].Key != "" || evs[0].Limit != 90 || evs[0].Value != 92 || !strings.Contains(evs[0].Text, "Datastore „a“ 92 % belegt") {
		t.Fatalf("Ereignis: %+v", evs[0])
	}
	p.expectDS(p.pbsSnap(pbsDS("a", 93), pbsDS("b", 96)), "threshold:datastore:b")
	if got := p.e.DatastoreAlarm(1); !got["a"][0] || !got["b"][0] || got["a"][1] {
		t.Fatalf("DatastoreAlarm: %v", got)
	}
	// zwischen 88 und 90 %: keine Entwarnung (Hysterese)
	p.expectDS(p.pbsSnap(pbsDS("a", 89), pbsDS("b", 96)), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 89), pbsDS("b", 96)), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 87), pbsDS("b", 96)), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 87), pbsDS("b", 96)), "threshold_ok:datastore:a")
	// Datastore mit Fehler bzw. nicht eingehaengt: Stand bleibt, keine Entwarnung
	bad := pbsDS("b", 0)
	bad.Error = "datastore not available"
	p.expectDS(p.pbsSnap(pbsDS("a", 50), bad), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 50), bad), "")
	if !p.e.DatastoreAlarm(1)["b"][0] {
		t.Fatal("Schwelle von b verloren")
	}
	// Datastore entfernt: Stand verworfen, ohne Meldung
	p.expectDS(p.pbsSnap(pbsDS("a", 50)), "")
	if p.e.DatastoreAlarm(1)["b"][0] {
		t.Fatal("entfernter Datastore noch gemeldet")
	}
	// Grenze aus: nichts
	off := Threshold{}
	p.item("").Rules.Datastore = &off
	p.expectDS(p.pbsSnap(pbsDS("a", 99)), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 99)), "")
}

// Voll in weniger als N Tagen: nur mit Schaetzung in der Zukunft, ohne Schaetzung bzw. in der Vergangenheit Entwarnung.
func TestPBSDatastoreFullDays(t *testing.T) {
	p := newPveRun(t)
	days := 14
	off := Threshold{}
	p.item("").Rules.DatastoreDays, p.item("").Rules.Datastore = &days, &off
	full := func(d float64) PBSDatastore {
		x := pbsDS("a", 50)
		x.Full = p.now.Add(30*time.Second + time.Duration(d*24)*time.Hour).Unix()
		return x
	}
	p.expectDS(p.pbsSnap(full(30)), "")
	p.expectDS(p.pbsSnap(full(9.5)), "")
	evs := p.pbsSnap(full(9.5))
	p.expectDS(evs, "threshold:datastore_full:a")
	if evs[0].Value != 9 || evs[0].Limit != 14 || !strings.Contains(evs[0].Text, "in 9 Tagen voll") {
		t.Fatalf("Ereignis: %+v", evs[0])
	}
	// 15 Tage: zwischen Grenze und Entwarnung (16): nichts
	p.expectDS(p.pbsSnap(full(15)), "")
	p.expectDS(p.pbsSnap(full(15)), "")
	// Schaetzung in der Vergangenheit (Belegung sinkt): Entwarnung nach Delay
	past := pbsDS("a", 50)
	past.Full = p.now.Add(-time.Hour).Unix()
	p.expectDS(p.pbsSnap(past), "")
	evs = p.pbsSnap(past)
	p.expectDS(evs, "threshold_ok:datastore_full:a")
	if evs[0].Value != 0 {
		t.Fatalf("Entwarnung: %+v", evs[0])
	}
	// keine Schaetzung: nie Meldung
	p.expectDS(p.pbsSnap(pbsDS("a", 50)), "")
	p.expectDS(p.pbsSnap(pbsDS("a", 50)), "")
}

// Gemeldete Datastore-Schwellen ueberstehen Export/Import (keine doppelte Meldung, Entwarnung kommt).
func TestPBSDatastoreExportImport(t *testing.T) {
	p := newPveRun(t)
	p.pbsSnap(pbsDS("a", 95))
	p.expectDS(p.pbsSnap(pbsDS("a", 95)), "threshold:datastore:a")
	es := p.e.Export(1)
	if es == nil || es.DS["a"]["datastore"].Limit != 90 {
		t.Fatalf("Export: %+v", es)
	}
	e2 := NewEngine()
	e2.Import(1, es)
	p.e = e2
	p.expectDS(p.pbsSnap(pbsDS("a", 95)), "")
	p.pbsSnap(pbsDS("a", 50))
	p.expectDS(p.pbsSnap(pbsDS("a", 50)), "threshold_ok:datastore:a")
}

func TestRuleSetDatastoreValidate(t *testing.T) {
	bad := -1
	if err := (&RuleSet{DatastoreDays: &bad}).Validate(); err == nil {
		t.Fatal("negative Tage angenommen")
	}
	if err := (&RuleSet{Datastore: &Threshold{Percent: 120}}).Validate(); err == nil {
		t.Fatal("120 % angenommen")
	}
	ok := 30
	r := DefaultRule().Apply(RuleSet{DatastoreDays: &ok})
	if r.Datastore.Percent != 90 || r.DatastoreDays != 30 {
		t.Fatalf("Regel: %+v", r)
	}
}
