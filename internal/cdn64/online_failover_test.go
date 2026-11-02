package cdn64

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Failover sichtbar: ipv64 meldet srv08 als ausgefallen (standby), dann springt srv09 ein (replaced_by/stands_in), dann
// ist srv08 zurueck. Je Schritt ein Eintrag im Log, die Dashboard-Karte zeigt den Failover gelb, die Spalte CDN64 das
// Abzeichen "srv08 -> srv09", GET /api/cdn64/online die Zuordnung.
func TestOnlineFailover(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	edge := func(n string, port int) ipv64api.CDN64Edge {
		return ipv64api.CDN64Edge{Name: n, Host: "127.0.0.1", Port: port, IPs: []string{"127.0.0.1"}}
	}
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{edge("srv08", 1), edge("srv10", 2)}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"fo.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.onlineEnable(ctx, h, 1); err != nil {
		t.Fatal(err)
	}
	logs := &syncBuf{}
	e.m.log = slog.New(slog.NewTextHandler(logs, nil))
	set := func(edges ...ipv64api.CDN64Edge) {
		f.mu.Lock()
		f.tunEdges = edges
		f.mu.Unlock()
		e.m.onlineSync(ctx)
	}
	card := func() string {
		c, err := e.m.Card(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range c.Stats {
			if s.LabelKey == "cdn64.card.failover" || s.LabelKey == "cdn64.card.edge_down" {
				out = append(out, s.LabelKey+"="+s.Text+"/"+s.Class)
			}
		}
		return strings.Join(out, ",")
	}
	badge := func(name string) onlineBadge {
		for _, r := range e.m.onlineIndex(ctx, []*Host{h}) {
			for _, b := range r.Edges {
				if b.Name == name {
					return b
				}
			}
		}
		return onlineBadge{}
	}

	// 1) srv08 faellt aus, noch kein Ersatz (die ersten 3 Minuten tragen die anderen Server)
	down := edge("srv08", 1)
	down.Standby = true
	set(down, edge("srv10", 2))
	if !strings.Contains(logs.String(), "server not reachable") || !strings.Contains(logs.String(), "edge=srv08") {
		t.Fatalf("log on failure: %s", logs.String())
	}
	if got := card(); got != "cdn64.card.edge_down=srv08/text-warning-emphasis" {
		t.Fatalf("card on failure: %q", got)
	}

	// 2) srv09 springt ein
	down.ReplacedBy = "srv09"
	in := edge("srv09", 3)
	in.StandsIn = "srv08"
	set(down, in, edge("srv10", 2))
	if !strings.Contains(logs.String(), "failover, stand-in") || !strings.Contains(logs.String(), "stand_in=srv09") {
		t.Fatalf("log on stand-in: %s", logs.String())
	}
	if got := card(); got != "cdn64.card.failover=srv08 → srv09/text-warning-emphasis" {
		t.Fatalf("card on stand-in: %q", got)
	}
	if v := e.m.onlineStatus(ctx); v.Failover["srv08"] != "srv09" {
		t.Fatalf("status failover: %+v", v.Failover)
	}
	if b := badge("srv08"); b.ReplacedBy != "srv09" {
		t.Fatalf("badge srv08: %+v", b)
	}
	if b := badge("srv09"); b.StandsIn != "srv08" {
		t.Fatalf("badge srv09: %+v", b)
	}
	row := hostRow{Host: h, Online: &onlineRow{Mode: 1, Names: h.Names, Status: "active",
		Edges: []onlineBadge{{Name: "srv08", State: "down", ReplacedBy: "srv09"}, {Name: "srv09", State: "direct", StandsIn: "srv08"}}}}
	body := renderHosts(t, listData{Kind: KindProxy, OnlineOn: true, Rows: []hostRow{row}})
	for _, want := range []string{"text-bg-warning", "cdn64.online.replaced", "bi-arrow-right", "cdn64.online.stands_in", "bi-arrow-repeat"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}

	// 3) srv08 zurueck: Ersatz entfaellt, Eintrag im Log, Karte ohne Hinweis
	set(edge("srv08", 1), edge("srv10", 2))
	if !strings.Contains(logs.String(), "server back, failover ended") {
		t.Fatalf("log on return: %s", logs.String())
	}
	if got := card(); got != "" {
		t.Fatalf("card after return: %q", got)
	}
	if v := e.m.onlineStatus(ctx); len(v.Failover) != 0 {
		t.Fatalf("status after return: %+v", v.Failover)
	}
}
