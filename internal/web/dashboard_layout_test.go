package web

import (
	"testing"

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
