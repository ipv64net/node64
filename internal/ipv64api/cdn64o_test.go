package ipv64api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Schutz-Statistik (GET /cdn64o/protection) und Schalter WAF/JA4 (PATCH /cdn64o/hosts/{id}): Felder wie im Plan.
func TestCDN64Protection(t *testing.T) {
	var patch map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && r.URL.Path == "/cdn64o/protection" && r.URL.Query().Get("days") == "7":
			_, _ = io.WriteString(w, `{"data":{"days":7,"ja4_global":"count","totals":{"blocked_list":10,"blocked_acl":1,"blocked_flood":2,"blocked_limit":3,"blocked_waf":4,"blocked_ja4":5,"ja4_hits":6,"blocked_ips":7,"conns":100,"conns_v4":40},
				"daily":[{"day":"2026-10-27","blocked_list":10,"conns":100}],"hosts":[{"id":5,"fqdn":"app.example.de","mode":2,"blocked_waf":4}],"ja4_top":[{"ja4":"t13d1516h2_8daaf6152771_e5627efa2ab1","hits":6}]}}`)
		case r.Method == "PATCH" && r.URL.Path == "/cdn64o/hosts/5":
			patch = map[string]any{}
			_ = json.NewDecoder(r.Body).Decode(&patch)
			_, _ = io.WriteString(w, `{"data":{"id":5,"fqdn":"app.example.de","mode":2,"waf":false,"ja4":"count","protection":{"blocked_list":1,"conns":2}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	ctx := context.Background()
	p, err := c.CDN64Protection(ctx, testKey, 7)
	if err != nil || p.Days != 7 || p.JA4Global != "count" || p.Totals.Blocked() != 25 || p.Totals.Overload() != 5 || p.Totals.ConnsV4 != 40 || p.Totals.JA4Hits != 6 {
		t.Fatalf("protection: %+v %v", p, err)
	}
	if len(p.Daily) != 1 || p.Daily[0].Day != "2026-10-27" || p.Daily[0].BlockedList != 10 || len(p.Hosts) != 1 || p.Hosts[0].BlockedWAF != 4 ||
		p.Hosts[0].Mode != 2 || len(p.JA4Top) != 1 || p.JA4Top[0].Hits != 6 {
		t.Fatalf("protection lists: %+v", p)
	}
	off := false
	h, err := c.CDN64SetProtection(ctx, testKey, 5, &off, "count")
	if err != nil || h.WAF || h.JA4 != "count" || h.Protection.BlockedList != 1 || h.Protection.Conns != 2 {
		t.Fatalf("set: %+v %v", h, err)
	}
	if len(patch) != 2 || patch["waf"] != false || patch["ja4"] != "count" {
		t.Fatalf("patch body: %v", patch)
	}
	if _, err := c.CDN64SetProtection(ctx, testKey, 5, nil, "block"); err != nil || len(patch) != 1 || patch["ja4"] != "block" {
		t.Fatalf("only ja4: %v %v", patch, err)
	}
}
