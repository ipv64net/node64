package cdn64

import (
	"context"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/ipv64api"
)

// Parallele Tunnel-Verbindungen: ipv64 meldet die Zahl der Klasse, die Node baut so viele je Server auf und zeigt sie.
func TestOnlineSessions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		edges: []ipv64api.CDN64Edge{{Name: "srv07", Host: "127.0.0.1", Port: 1, IPs: []string{"127.0.0.1"}}}}
	e.m.SetOnlineAPI(f)
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"app.test"}, "93.184.216.34", 8080
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.onlineEnable(ctx, h, 1); err != nil {
		t.Fatal(err)
	}
	wanted := func() int {
		e.m.online.mu.Lock()
		cl := e.m.online.client
		e.m.online.mu.Unlock()
		if cl == nil {
			return -1
		}
		return cl.Status()[0].Wanted
	}
	if w := wanted(); w != 1 {
		t.Fatalf("default sessions: %d", w)
	}
	f.mu.Lock()
	f.sessions = 4
	f.mu.Unlock()
	e.m.onlineSync(ctx)
	if v := e.m.core.SettingOr(ctx, setOnlineSessions, ""); v != "4" || wanted() != 4 {
		t.Fatalf("after class change: setting %q, wanted %d", v, wanted())
	}
	e.m.onlineSync(ctx) // unveraendert: kein Neustart noetig, bleibt 4
	if wanted() != 4 {
		t.Fatal("sessions lost")
	}
	body := renderHosts(t, listData{Kind: KindProxy, OnlineOn: true, Rows: []hostRow{{Host: h,
		Online: &onlineRow{Mode: 1, Names: h.Names, Status: "active", Edges: []onlineBadge{{Name: "srv07", State: "direct", Sessions: 4}}}}}})
	if !strings.Contains(body, "×4") || !strings.Contains(body, "cdn64.online.sessions_title") {
		t.Fatal("badge without session count")
	}
}
