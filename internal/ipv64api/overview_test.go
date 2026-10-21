package ipv64api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Account-Uebersicht: CDN-Domains und -Traffic aus /cdn64o (altes und neues CDN, Monat), ohne die Route aus /me.
func TestOverviewCDNQuota(t *testing.T) {
	withCDN := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/me":
			_, _ = io.WriteString(w, `{"data":{"email":"t@example.com","plan":{"name":"Supporter"},"usage":{"cdn_domains":{"used":1,"limit":10},"cdn_traffic_gb":{"used":0.2,"limit":100}}}}`)
		case r.URL.Path == "/cdn64o" && withCDN:
			_, _ = io.WriteString(w, `{"data":{"quota":{"domains":{"used":3,"old_cdn":1,"limit":10},"traffic_mb":{"used":409.6,"old_cdn":204.8,"limit":102400},"bandwidth_mbit":0},"hosts":[]}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"status":404,"code":"not_found","detail":"no such route"}`)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "test")
	get := func() map[string]Limit {
		ov, err := c.overview(context.Background(), testKey)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]Limit{}
		for _, l := range ov.Limits {
			out[l.Key] = l
		}
		return out
	}
	l := get()
	if d := l["cdn_domains"]; d.Used != 3 || d.Max != 10 {
		t.Fatalf("domains: %+v", d)
	}
	if tr := l["cdn_traffic_gb"]; tr.Used != 0.4 || tr.Max != 100 || tr.Pct() != 0 || tr.BarPct() != 1 || !tr.GB() {
		t.Fatalf("traffic: %+v pct %d bar %v", tr, tr.Pct(), tr.BarPct())
	}
	withCDN = false
	l = get()
	if d, tr := l["cdn_domains"], l["cdn_traffic_gb"]; d.Used != 1 || tr.Used != 0.2 {
		t.Fatalf("fallback /me: %+v %+v", d, tr)
	}
}

// Balkenbreite: Kommazahl, bei Verbrauch mindestens 1 %, hoechstens 100 %, unbegrenzt 0; Limit 0 und belegt = voll.
func TestLimitBarPct(t *testing.T) {
	for _, c := range []struct {
		l    Limit
		want float64
	}{
		{Limit{Used: 0, Max: 100}, 0}, {Limit{Used: 0.4, Max: 100}, 1}, {Limit{Used: 37.25, Max: 100}, 37.3}, {Limit{Used: 1, Max: 3}, 33.3},
		{Limit{Used: 150, Max: 100}, 100}, {Limit{Used: 5, Unlimited: true}, 0}, {Limit{Used: 5}, 100}, {Limit{}, 0},
	} {
		if got := c.l.BarPct(); got != c.want {
			t.Errorf("%+v: %v, want %v", c.l, got, c.want)
		}
	}
}

// Farbe und Zustand wie bei PROXY64: Limit 0, aber belegt (z. B. CDN-Domains nicht im Tarif) ist voll und rot.
func TestLimitFullClass(t *testing.T) {
	for _, c := range []struct {
		l          Limit
		pct        int
		full, warn bool
		class      string
	}{
		{Limit{Used: 2}, 100, true, true, "bg-danger"},
		{Limit{}, 0, false, false, "bg-success"},
		{Limit{Used: 80, Max: 100}, 80, false, true, "bg-warning"},
		{Limit{Used: 100, Max: 100}, 100, true, true, "bg-danger"},
		{Limit{Used: 10, Max: 100}, 10, false, false, "bg-success"},
		{Limit{Used: 5, Unlimited: true}, 0, false, false, "bg-success"},
	} {
		if c.l.Pct() != c.pct || c.l.Full() != c.full || c.l.Warn() != c.warn || c.l.BarClass() != c.class {
			t.Errorf("%+v: pct %d full %v warn %v class %s", c.l, c.l.Pct(), c.l.Full(), c.l.Warn(), c.l.BarClass())
		}
	}
}
