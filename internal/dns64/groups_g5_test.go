package dns64

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/metrics"
)

// G5: Kennzahlen je Gruppe fuer Prometheus.
func TestGroupMetrics(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	g, _ := m.AddGroup(ctx, "Kinder")
	if _, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if err := m.SetHold(ctx, g.ID, groups.HoldBlock, 30, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if st := m.groupStates()[g.ID]; !st.Off || !st.Hold || st.Schedule != "" {
		t.Fatalf("state: %+v", st)
	}
	if _, err := query(net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), "nas"); err != nil {
		t.Fatal(err)
	}
	w := metrics.New()
	m.Metrics(ctx, w)
	var sb strings.Builder
	_, _ = w.WriteTo(&sb)
	for _, want := range []string{
		`node64_dns64_group_queries_total{group="Kinder",status="local"} 1`,
		`node64_dns64_group_internet_off{group="Kinder"} 1`,
		`node64_dns64_group_free{group="Kinder"} 0`,
		`node64_dns64_group_members{group="Kinder"} 1`,
	} {
		if !strings.Contains(sb.String(), want) {
			t.Errorf("missing %q in\n%s", want, sb.String())
		}
	}
}

// G5: Gruppen ziehen mit Export/Import um (ohne Knopf-Zustand); vorhandene Gruppen gleichen Namens bleiben.
func TestGroupExportImport(t *testing.T) {
	a, _ := testModule(t)
	ctx := context.Background()
	g, _ := a.AddGroup(ctx, "Kinder")
	_, _ = a.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindMAC, Value: "02:11:22:33:44:55", Label: "Tablet"})
	_ = a.SetGroupRules(ctx, g.ID, groups.Rules{Cats: []string{"social"}, SafeSearch: true, YouTube: "moderate", Bypass: true})
	_, _ = a.AddGroupDomain(ctx, groups.Domain{GroupID: g.ID, Domain: "schule.example", Action: groups.ActionAllow})
	sc, _ := a.AddSchedule(ctx, groups.Schedule{GroupID: g.ID, Label: "Nacht", Days: []int{1, 2}, Start: "21:00", End: "07:00", Action: groups.ScheduleOff})
	_ = a.SetScheduleEnabled(ctx, sc.ID, false)
	_ = a.SetHold(ctx, g.ID, groups.HoldBlock, 0, time.Time{})
	out, err := a.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)

	b, _ := testModule(t)
	if _, err := b.Import(ctx, raw); err != nil {
		t.Fatal(err)
	}
	list, err := b.Groups(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("groups %v %v", list, err)
	}
	x := list[0]
	if x.Name != "Kinder" || len(x.Members) != 1 || x.Members[0].Label != "Tablet" || !x.SafeSearch || x.YouTube != "moderate" || !x.Bypass ||
		len(x.Cats) != 1 || len(x.Domains) != 1 || len(x.Schedules) != 1 || x.Schedules[0].Enabled || x.Hold != "" {
		t.Fatalf("imported: %+v", x)
	}
	if _, err := b.Import(ctx, raw); err != nil { // zweimal: keine doppelte Gruppe
		t.Fatal(err)
	}
	if list, _ := b.Groups(ctx); len(list) != 1 || len(list[0].Members) != 1 {
		t.Fatalf("second import: %+v", list)
	}
}
