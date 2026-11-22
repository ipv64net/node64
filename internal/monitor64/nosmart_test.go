package monitor64

import (
	"context"
	"slices"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// #215: "SMART-Werte abfragen" aus - der Agent bekommt alle Abschnitte ausser smart, im Push-Betrieb wird SMART
// verworfen; den Schalter gibt es nur bei Zugaengen, die SMART lesen (SSH hat seinen eigenen, standardmaessig aus).
func TestNoSmart(t *testing.T) {
	if slices.Contains(noSmartSections, m64proto.SecSmart) || len(noSmartSections) != len(m64proto.AllSections)-1 {
		t.Fatalf("Abschnitte ohne SMART: %v", noSmartSections)
	}
	rep := &m64proto.Report{SMART: []m64proto.SMART{{Device: "/dev/sda"}},
		Errors: []m64proto.SectionErr{{Section: m64proto.SecSmart, Error: "x"}, {Section: m64proto.SecFS, Error: "y"}},
		Notes:  []m64proto.SectionNote{{Section: m64proto.SecSmart, Note: "smartctl fehlt"}}}
	dropSmart(rep)
	if rep.SMART != nil || len(rep.Errors) != 1 || rep.Errors[0].Section != m64proto.SecFS || len(rep.Notes) != 0 {
		t.Fatalf("dropSmart: %+v", rep)
	}
	for _, c := range []struct {
		typ, cfg string
		ok       bool
	}{
		{"pve", `{"no_smart":true}`, true},
		{"pbs", `{"no_smart":true}`, true},
		{"truenas", `{"no_smart":true}`, true},
		{"agent", `{"no_smart":true}`, true},
		{"snmp", `{"no_smart":true}`, false},
		{"docker", `{"no_smart":true}`, false},
		{"ssh", `{"smart":true}`, true},
		{"pve", `{"smart":true}`, false},
	} {
		if _, err := cleanAccessConfig(c.typ, []byte(c.cfg)); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.typ, c.cfg, err)
		}
	}
}

type refreshSrc struct{ n int }

func (r *refreshSrc) Collect(context.Context) ([]model.Service, error) { return nil, nil }
func (r *refreshSrc) RefreshDisks()                                    { r.n++ }

// #215 (Nachtrag): "Dienste erkennen" laesst Proxmox VE/PBS ohne SMART die Plattenliste neu lesen.
func TestRefreshDisks(t *testing.T) {
	var _ diskRefresher = (*apis.PVE)(nil)
	var _ diskRefresher = (*apis.PBS)(nil)
	src := &refreshSrc{}
	rt := &hostRT{accs: []*accRT{{col: &apiAdapter{apiCollector: apiCollector{src: src}}}, {col: nil}, {col: &agentCollector{}}}}
	refreshDisks(rt)
	if src.n != 1 {
		t.Fatalf("RefreshDisks: %d", src.n)
	}
}
