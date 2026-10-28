package dns64

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/groups"
)

type clCall struct {
	item, id string
	deleted  bool
}

type clLog struct {
	mu    sync.Mutex
	calls []clCall
}

func (l *clLog) hook(_ context.Context, item, id string, deleted bool) {
	l.mu.Lock()
	l.calls = append(l.calls, clCall{item, id, deleted})
	l.mu.Unlock()
}

// take liefert die Meldungen seit dem letzten Aufruf.
func (l *clLog) take() []clCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.calls
	l.calls = nil
	return out
}

// sync uebertraegt alle gemeldeten Eintraege von a nach b (wie der Cluster: Stand holen, uebernehmen).
func clSync(t *testing.T, a, b *Module, calls []clCall) {
	t.Helper()
	ctx := context.Background()
	for _, c := range calls {
		data, found, err := a.ClusterGet(ctx, c.item, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if err := b.ClusterApply(ctx, c.item, c.id, data, c.deleted || !found); err != nil {
			t.Fatalf("apply %+v: %v", c, err)
		}
	}
}

func TestClusterSync(t *testing.T) {
	a, _ := testModule(t)
	b, _ := testModule(t)
	ctx := context.Background()
	gb, err := b.AddGroup(ctx, "Kinder") // gab es auf B schon vor dem Cluster
	if err != nil {
		t.Fatal(err)
	}
	var la, lb clLog
	a.SetCluster(la.hook)
	b.SetCluster(lb.hook)

	// eigene Eintraege, nur-hier-Eintrag, Zone
	if _, err := a.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10", Comment: "NAS"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddRecord(ctx, Record{Name: "pc.home.lan", Type: "A", Value: "192.168.1.11", LocalOnly: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddZone(ctx, Zone{Name: "home.lan", Authoritative: true}); err != nil {
		t.Fatal(err)
	}
	// Weiterleitung, Umschreiben, Freigabe, Einstellung
	if _, err := a.AddForward(ctx, Forward{Domain: "firma.local", Servers: []string{"10.8.0.1"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddRewrite(ctx, Rewrite{Name: "nas.example.com", Target: "nas.home.lan"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.importAllow([]string{"example.org"}); err != nil {
		t.Fatal(err)
	}
	c := a.loadConfig(ctx)
	c.BlockMode = blockNX
	if err := a.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	// Gruppe mit Regeln, Domain, Zeitplan und Mitglied
	ga, err := a.AddGroup(ctx, "Kinder")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.SetGroupRules(ctx, ga.ID, groups.Rules{ListsMode: groups.ListsGlobal, Cats: []string{"social"}, SafeSearch: true, YouTube: "strict"}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddGroupDomain(ctx, groups.Domain{GroupID: ga.ID, Domain: "schule.de", Action: groups.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddSchedule(ctx, groups.Schedule{GroupID: ga.ID, Days: []int{1, 2}, Start: "21:00", End: "07:00", Action: groups.ScheduleOff}); err != nil {
		t.Fatal(err)
	}
	if _, err := a.AddMember(ctx, groups.Member{GroupID: ga.ID, Kind: groups.KindIP, Value: "192.168.1.50", Label: "Tablet"}); err != nil {
		t.Fatal(err)
	}

	calls := la.take()
	for _, c := range calls {
		if strings.Contains(c.id, recordKey("pc.home.lan", "A", "192.168.1.11")) {
			t.Fatal("local-only record reported")
		}
	}
	clSync(t, a, b, calls)

	recs, _ := b.Records(ctx)
	if len(recs) != 1 || recs[0].Name != "nas.home.lan" || recs[0].Comment != "NAS" {
		t.Fatalf("records on b = %+v", recs)
	}
	if z, _ := b.Zones(ctx); len(z) != 1 || !z[0].Authoritative {
		t.Fatalf("zones on b = %+v", z)
	}
	if f, _ := b.Forwards(ctx); len(f) != 1 || f[0].Servers[0] != "dns://10.8.0.1:53" {
		t.Fatalf("forwards on b = %+v", f)
	}
	if r, _ := b.Rewrites(ctx); len(r) != 1 {
		t.Fatalf("rewrites on b = %+v", r)
	}
	if al, _ := b.allowlist(); !al.Contains("example.org") {
		t.Fatal("allowlist not synced")
	}
	if b.loadConfig(ctx).BlockMode != blockNX {
		t.Fatal("block mode not synced")
	}
	gl, _ := b.Groups(ctx)
	if len(gl) != 1 || gl[0].ID != gb.ID || gl[0].UID != ga.UID {
		t.Fatalf("groups on b = %+v (want local group %d with uid %s)", gl, gb.ID, ga.UID)
	}
	g := gl[0]
	if !g.SafeSearch || len(g.Cats) != 1 || len(g.Domains) != 1 || len(g.Schedules) != 1 || len(g.Members) != 1 || g.Members[0].Label != "Tablet" {
		t.Fatalf("group on b = %+v", g)
	}

	// Loeschen und Aendern kommen ebenso an
	lb.take()
	if err := a.DeleteForward(ctx, mustForwardID(t, a, "firma.local")); err != nil {
		t.Fatal(err)
	}
	if err := a.SetHold(ctx, ga.ID, groups.HoldBlock, 30, time.Time{}); err != nil {
		t.Fatal(err)
	}
	clSync(t, a, b, la.take())
	if f, _ := b.Forwards(ctx); len(f) != 0 {
		t.Fatalf("forward not deleted on b: %+v", f)
	}
	if gl, _ := b.Groups(ctx); gl[0].Hold != groups.HoldBlock {
		t.Fatalf("hold not synced: %+v", gl[0])
	}
	if err := a.DeleteGroup(ctx, ga.ID); err != nil {
		t.Fatal(err)
	}
	clSync(t, a, b, la.take())
	if gl, _ := b.Groups(ctx); len(gl) != 0 {
		t.Fatalf("group not deleted on b: %+v", gl)
	}
}

func mustForwardID(t *testing.T, m *Module, domain string) int64 {
	t.Helper()
	fl, _ := m.Forwards(context.Background())
	for _, f := range fl {
		if f.Domain == domain {
			return f.ID
		}
	}
	t.Fatalf("no forward %s", domain)
	return 0
}

// Gleichzeitige Aenderungen: ein aelterer Stand darf den neueren nicht ueberschreiben (sonst Meldungen geloeschter
// Eintraege, die es noch gibt), und der gemeldete Stand entspricht am Ende der Datenbank.
func TestClusterConcurrentChanges(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	var l clLog
	m.SetCluster(l.hook)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.AddRecord(ctx, Record{Name: "h" + strconv.Itoa(i) + ".home.lan", Type: "A", Value: "192.168.1." + strconv.Itoa(i+1)}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	for _, c := range l.take() {
		if c.deleted {
			t.Fatalf("bogus deletion reported: %+v", c)
		}
	}
	cur, err := m.clCurrent(ctx, ItemRecords)
	if err != nil {
		t.Fatal(err)
	}
	m.clMu.Lock()
	snap := m.clSnap[ItemRecords]
	m.clMu.Unlock()
	if len(snap) != len(cur) || len(cur) != 20 {
		t.Fatalf("snapshot %d entries, database %d, want 20", len(snap), len(cur))
	}
}
