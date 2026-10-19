package dns64

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/edge"
)

// G4: Sperren/Frei per Knopf und Zeitplaene; bei "Internet aus" antwortet DNS64 mit der Adresse der Node, der
// Eingang zeigt gesperrten Geraeten auf Port 80 die Hinweisseite.
func TestGroupSchedules(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	hp, hs := freePort(t), freePort(t)
	e, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPPort: hp, HTTPSPort: hs, Default: edge.DefaultNotFound}, noCerts{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	m.SetEdge(e)
	c := m.loadConfig(ctx)
	for i := range c.Upstreams {
		c.Upstreams[i].Enabled = false
	}
	for i := range c.Lists {
		c.Lists[i].Enabled = false
	}
	c.Upstreams = append(c.Upstreams, upstreamSetting{Server: upstream.Server{Name: "Nirgends", URL: "https://127.0.0.1:1/dns-query"}, Enabled: true, Custom: true})
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	g, _ := m.AddGroup(ctx, "Kinder")
	for _, ip := range []string{"192.168.1.50", "127.0.0.1"} {
		if _, err := m.AddMember(ctx, groups.Member{GroupID: g.ID, Kind: groups.KindIP, Value: ip}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.AddGroupDomain(ctx, groups.Domain{GroupID: g.ID, Domain: "schule.example", Action: groups.ActionAllow}); err != nil {
		t.Fatal(err)
	}
	m.running().srv.HintV4 = net.ParseIP("192.0.2.10").To4()
	ask := func(client, name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(name), dns.TypeA)
		return m.running().srv.Answer(q, netip.MustParseAddr(client), "udp")
	}
	hinted := func(r *dns.Msg) bool {
		return len(r.Answer) == 1 && r.Answer[0].(*dns.A).A.Equal(net.ParseIP("192.0.2.10")) && r.Answer[0].Header().Ttl == 10
	}
	kid, other := "192.168.1.50", "192.168.1.60"
	if hinted(ask(kid, "heise.example")) {
		t.Fatal("off without hold")
	}
	if err := m.SetHold(ctx, g.ID, groups.HoldBlock, 30, time.Time{}); err != nil {
		t.Fatal(err)
	}
	m.running().srv.HintV4 = net.ParseIP("192.0.2.10").To4()
	if !hinted(ask(kid, "heise.example")) || hinted(ask(other, "heise.example")) || hinted(ask(kid, "schule.example")) {
		t.Fatal("hold block")
	}
	if r := ask(kid, "nas.home.lan"); len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatal("own record during internet off")
	}
	// Hinweisseite ueber den Eingang (Port 80, unbekannter Host, gesperrtes Geraet 127.0.0.1)
	var resp *http.Response
	for i := 0; i < 100; i++ {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(hp)+"/", nil)
		req.Host = "heise.example"
		if resp, err = http.DefaultClient.Do(req); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "Kinder") {
		t.Fatalf("hint page: %d %s", resp.StatusCode, body)
	}
	// aufheben, Zeitplan den ganzen Tag, Frei setzt ihn aus
	if err := m.SetHold(ctx, g.ID, "", 0, time.Time{}); err != nil {
		t.Fatal(err)
	}
	m.running().srv.HintV4 = net.ParseIP("192.0.2.10").To4()
	if hinted(ask(kid, "heise.example")) {
		t.Fatal("released")
	}
	sc, err := m.AddSchedule(ctx, groups.Schedule{GroupID: g.ID, Label: "Test", Days: []int{1, 2, 3, 4, 5, 6, 7}, Start: "00:00", End: "00:00", Action: groups.ScheduleOff})
	if err != nil {
		t.Fatal(err)
	}
	if !hinted(ask(kid, "heise.example")) {
		t.Fatal("schedule off")
	}
	if err := m.SetHold(ctx, g.ID, groups.HoldFree, 30, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if hinted(ask(kid, "heise.example")) {
		t.Fatal("free does not suspend the schedule")
	}
	if err := m.SetScheduleEnabled(ctx, sc.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddSchedule(ctx, groups.Schedule{GroupID: g.ID, Days: []int{1}, Start: "25:00", End: "07:00"}); err == nil {
		t.Fatal("invalid schedule accepted")
	}
	if _, err := m.RemoveSchedule(ctx, sc.ID); err != nil {
		t.Fatal(err)
	}
}
