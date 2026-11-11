package web

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

// Gespeicherte Reihenfolge, Groesse und Sichtbarkeit gelten; Weggefallenes faellt raus, Neues kommt hinten dazu.
func TestDashMerge(t *testing.T) {
	avail := dashAvailable([]module.DashboardInfo{{Module: "healthchecks"}}, []namedCard{{Module: "dns64"}}, true, false)
	saved := []dashItem{{ID: "storage", Size: "xl"}, {ID: "card:gone", Size: "s"}, {ID: "node", Size: "s", Hidden: true}, {ID: "chart:dns64", Size: "zz"}}
	got := dashMerge(avail, saved)
	if got[0].ID != "storage" || got[0].Size != "xl" || got[1].ID != "node" || !got[1].Hidden {
		t.Fatalf("saved order/size/hidden not applied: %+v", got[:2])
	}
	if got[2].ID != "chart:dns64" || got[2].Size != "l" || got[2].Hidden {
		t.Fatalf("invalid size must keep default, saved visibility applies: %+v", got[2])
	}
	ids := map[string]bool{}
	for _, it := range got {
		ids[it.ID] = true
	}
	if ids["card:gone"] || !ids["board:healthchecks"] || !ids["card:dns64"] || len(got) != len(avail) {
		t.Fatalf("merge: %v", ids)
	}
	for _, it := range dashMerge(avail, nil) {
		if it.Hidden != (it.ID == "chart:dns64") {
			t.Fatalf("by default only charts are hidden: %+v", it)
		}
	}
}

// Letzte Stoerungen: Monitor64 laeuft in der Liste der Healthchecks mit (neueste zuerst, hoechstens 10); ohne
// Healthchecks bekommt die Liste eine eigene Kachel vorne.
func TestDashIncidents(t *testing.T) {
	now := time.Now()
	hc := []module.IncidentInfo{{Name: "web", StartedAt: now.Add(-2 * time.Hour)}}
	var m64 []module.IncidentInfo
	for i := range 12 {
		m64 = append(m64, module.IncidentInfo{Name: "m64", Source: "nav.monitor64", StartedAt: now.Add(-time.Duration(i) * time.Hour)})
	}
	boards := []module.DashboardInfo{{Module: "healthchecks", Incidents: hc}}
	avail := dashAvailable(boards, nil, false, false)
	avail = dashIncidents(avail, boards, m64)
	var list []module.IncidentInfo
	for _, it := range avail {
		if it.Kind == "incidents" {
			if it.ID != "incidents:healthchecks" || list != nil {
				t.Fatalf("one shared list expected: %+v", it)
			}
			list = it.Board.Incidents
		}
	}
	if len(list) != dashIncidentsMax || list[0].StartedAt != m64[0].StartedAt || list[2].Name != "web" || list[3].Name != "m64" {
		t.Fatalf("merged: %+v", list)
	}
	only := dashIncidents(dashAvailable(nil, nil, false, false), nil, m64[:2])
	if only[0].ID != "incidents:monitor64" || len(only[0].Board.Incidents) != 2 {
		t.Fatalf("without healthchecks: %+v", only[0])
	}
	if got := dashIncidents(dashAvailable(nil, nil, false, false), nil, nil); got[0].Kind == "incidents" {
		t.Fatal("no incidents, no tile")
	}
}
