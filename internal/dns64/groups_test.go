package dns64

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// Gruppen anlegen, Geraet zuordnen: die Anfrage steht mit Gruppe im Log, laesst sich danach filtern und das
// Geraet erscheint in der Liste der letzten 24 Stunden; ein Geraet gehoert immer nur einer Gruppe.
func TestGroupsG1(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	kids, err := m.AddGroup(ctx, " Kinder ")
	if err != nil || kids.Name != "Kinder" {
		t.Fatalf("add: %+v %v", kids, err)
	}
	guests, _ := m.AddGroup(ctx, "Gäste")
	var ce *cfgError
	if _, err := m.AddGroup(ctx, "Kinder"); !errors.As(err, &ce) || ce.Key != "err_group_dup" {
		t.Fatalf("duplicate: %v", err)
	}
	if _, err := m.AddMember(ctx, groups.Member{GroupID: kids.ID, Kind: groups.KindIP, Value: "127.0.0.1", Label: "Test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddMember(ctx, groups.Member{GroupID: kids.ID, Kind: groups.KindMAC, Value: "kaputt"}); !errors.As(err, &ce) || ce.Key != "err_member" {
		t.Fatalf("bad member: %v", err)
	}
	q := new(dns.Msg)
	q.SetQuestion("nas.home.lan.", dns.TypeA)
	if _, _, err := (&dns.Client{Timeout: 3 * time.Second}).Exchange(q, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // Log wird jede Sekunde geschrieben
	e := m.running()
	g := "Kinder"
	rows, total, err := e.store.Recent(ctx, querylog.LogFilter{Group: &g, Limit: 10})
	if err != nil || total != 1 || rows[0].Group != "Kinder" {
		t.Fatalf("log by group: %v %d %v", rows, total, err)
	}
	none := ""
	if _, total, _ := e.store.Recent(ctx, querylog.LogFilter{Group: &none, Limit: 10}); total != 0 {
		t.Fatalf("without group: %d", total)
	}
	devs, err := m.devices(ctx, e)
	if err != nil || len(devs) != 1 || devs[0].IP != "127.0.0.1" || devs[0].GroupID != kids.ID || devs[0].Queries != 1 {
		t.Fatalf("devices: %+v %v", devs, err)
	}
	// dasselbe Geraet in eine andere Gruppe: wechselt
	if _, err := m.AddMember(ctx, groups.Member{GroupID: guests.ID, Kind: groups.KindIP, Value: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	list, _ := m.Groups(ctx)
	if len(list) != 2 || len(list[0].Members) != 0 || len(list[1].Members) != 1 {
		t.Fatalf("groups after move: %+v", list)
	}
	if err := m.MoveGroup(ctx, guests.ID, true); err != nil {
		t.Fatal(err)
	}
	if list, _ = m.Groups(ctx); list[0].ID != guests.ID {
		t.Fatalf("order: %+v", list)
	}
	if err := m.RenameGroup(ctx, guests.ID, "Besuch"); err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteGroup(ctx, guests.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = m.core.Reader().QueryRow(`SELECT COUNT(*) FROM dns64_group_members`).Scan(&n)
	if n != 0 || m.grp.For(mustAddr("127.0.0.1")).ID != 0 {
		t.Fatalf("members left %d", n)
	}
	if err := m.DeleteGroup(ctx, guests.ID); !errors.Is(err, errNotFound) {
		t.Fatalf("delete twice: %v", err)
	}
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
