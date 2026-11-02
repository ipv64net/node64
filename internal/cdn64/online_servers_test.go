package cdn64

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
)

func TestServersView(t *testing.T) {
	if newServersView(nil) != nil {
		t.Fatal("nil portal: view")
	}
	// Supporter: fest 2, keine Auswahl
	v := newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Assigned: []string{"srv07", "srv08"}})
	if v.Options != nil || v.Names != "srv07, srv08" {
		t.Fatalf("fixed: %+v", v)
	}
	// Business: 1 bis 2
	v = newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}})
	if !slices.Equal(v.Options, []int{1, 2}) || v.Current != 2 {
		t.Fatalf("business: %+v", v)
	}
	// Company: 1 bis alle, dazu "alle (auch kuenftige)"; alle zugeteilt = Option 0
	v = newServersView(&ipv64api.CDN64Servers{Count: 4, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08", "srv09", "srv10"}})
	if !slices.Equal(v.Options, []int{1, 2, 3, 4, 0}) || v.Current != 0 {
		t.Fatalf("company: %+v", v)
	}
}

func TestOnlineServersPage(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	f := &fakeOnline{ready: true, tunnels: map[string]bool{}, hosts: map[int64]string{}, modes: map[int64]int{},
		servers: &ipv64api.CDN64Servers{Count: 2, Max: 4, All: true, Total: 4, Selectable: true, Assigned: []string{"srv07", "srv08"}}}
	e.m.SetOnlineAPI(f)
	ov, _ := f.Overview(ctx)
	e.m.onlineSetRemote(ov, nil)
	var flash string
	e.m.g.Flash = func(_ http.ResponseWriter, _ *http.Request, kind, text string) { flash = kind + ": " + text }
	e.m.g.T = func(_ *http.Request, key string, _ ...any) string { return key }
	e.m.g.Audit = func(*http.Request, string, string, string) {}
	post := func(count string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/cdn64/online/servers", strings.NewReader("count="+count))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.m.pageOnlineServers(rec, req)
		return rec
	}
	if rec := post("3"); rec.Code != http.StatusSeeOther || !strings.HasPrefix(flash, "success") || !slices.Equal(f.setCount, []int{3}) {
		t.Fatalf("set 3: %d %q %v", rec.Code, flash, f.setCount)
	}
	if s := e.m.online.remote.Load().Data.Servers; s == nil || s.Count != 3 {
		t.Fatalf("remote not updated: %+v", s)
	}
	if post("x"); !strings.HasPrefix(flash, "danger") || len(f.setCount) != 1 {
		t.Fatalf("invalid: %q %v", flash, f.setCount)
	}
	f.servers.Selectable = false // Klasse fest: ipv64 lehnt ab
	if post("1"); !strings.HasPrefix(flash, "danger") {
		t.Fatalf("fixed plan: %q", flash)
	}
	// Kachel unter den Proxy-Hosts: Auswahl mit "alle", aktuelle Anzahl gewaehlt
	f.servers.Selectable = true
	d := listData{Kind: KindProxy, Quota: newOnlineQuota(ipv64api.CDN64Quota{}, time.Now()), Servers: newServersView(f.servers)}
	body := renderHosts(t, d)
	for _, want := range []string{`id="cdn-servers"`, `action="/cdn64/online/servers"`, `<option value="3" selected>`, `<option value="0">`, "srv07, srv08, srv09"} {
		if !strings.Contains(body, want) {
			t.Fatalf("page misses %q", want)
		}
	}
	d.Servers = newServersView(&ipv64api.CDN64Servers{Count: 2, Max: 2, Total: 4, Assigned: []string{"srv07", "srv08"}})
	if body = renderHosts(t, d); !strings.Contains(body, `id="cdn-servers"`) || strings.Contains(body, `name="count"`) {
		t.Fatal("fixed plan: no selection expected")
	}
}
