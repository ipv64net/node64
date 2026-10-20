package ipv64api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestThreatWatchClient(t *testing.T) {
	var gotAuth, gotBody, gotSince, gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotMethod, gotPath = r.Header.Get("Authorization"), r.Method, r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v2/threat/watch":
			_, _ = io.WriteString(w, `{"data":{"limits":{"max":3,"min_prefix_v4":16,"min_prefix_v6":32},
				"networks":[{"id":1,"cidr":"203.0.113.0/24","label":"Buero","verified":false,"created_at":"2026-10-20T12:00:00Z"}],
				"dyndns":[{"ip":"198.51.100.7","domain":"x.ipv64.net"}]}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v2/threat/watch":
			var in map[string]string
			_ = json.Unmarshal(b, &in)
			switch in["cidr"] {
			case "10.0.0.0/8":
				w.WriteHeader(http.StatusUnprocessableEntity)
				_, _ = io.WriteString(w, `{"error":{"code":"not_public","message":"Netz ist nicht oeffentlich"}}`)
			case "203.0.113.0/24":
				w.WriteHeader(http.StatusConflict)
				_, _ = io.WriteString(w, `{"error":{"code":"duplicate","message":"schon eingetragen"}}`)
			case "192.0.2.0/24":
				w.WriteHeader(http.StatusForbidden)
				_, _ = io.WriteString(w, `{"error":{"code":"limit_reached","message":"Limit erreicht"}}`)
			default:
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, `{"data":{"id":7,"cidr":"`+in["cidr"]+`","label":"`+in["label"]+`","verified":false,"created_at":"2026-10-20T13:00:00Z"}}`)
			}
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v2/threat/watch/7":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
			_, _ = io.WriteString(w, `{"error":{"code":"not_found","message":"unbekannt"}}`)
		case r.URL.Path == "/api/v2/threat/watch/alerts":
			gotSince = r.URL.Query().Get("since")
			if gotSince == "slow" {
				w.Header().Set("Retry-After", "90")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = io.WriteString(w, `{"error":{"code":"rate_limited","message":"zu oft"}}`)
				return
			}
			_, _ = io.WriteString(w, `{"data":{"alerts":[{"id":123,"ip":"203.0.113.9","cidr":"203.0.113.0/24","network_id":1,"source":"network",
				"listed":true,"score":72,"kinds":["ssh:bruteforce"],"first_seen":"2026-10-19","last_seen":"2026-10-20","created_at":"2026-10-20T12:30:00Z"},
				{"id":124,"ip":"198.51.100.7","cidr":"198.51.100.7/32","network_id":null,"source":"dyndns","listed":false,"score":20,"kinds":[],"created_at":"2026-10-20T12:30:00Z"}],
				"next":"2026-10-20T12:30:00Z"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL+"/api/v2", "node64/test")
	ctx := context.Background()
	const key = "KEY0123456789abcdef"

	l, err := c.ThreatWatchList(ctx, key)
	if err != nil || l.Limits.Max != 3 || l.Limits.MinPrefixV4 != 16 || l.Limits.MinPrefixV6 != 32 || len(l.Networks) != 1 || l.Networks[0].Label != "Buero" ||
		l.Networks[0].Verified || len(l.DynDNS) != 1 || l.DynDNS[0].Domain != "x.ipv64.net" {
		t.Fatalf("list: %+v %v", l, err)
	}
	if gotAuth != "Bearer "+key {
		t.Fatalf("auth header: %q", gotAuth)
	}

	n, err := c.ThreatWatchAdd(ctx, key, "198.51.100.0/24", "Lager")
	if err != nil || n.ID != 7 || n.CIDR != "198.51.100.0/24" || n.Label != "Lager" || gotMethod != http.MethodPost {
		t.Fatalf("add: %+v %v", n, err)
	}
	if gotBody != `{"cidr":"198.51.100.0/24","label":"Lager"}` {
		t.Fatalf("add body: %s", gotBody)
	}
	for cidr, want := range map[string]struct {
		status int
		code   string
	}{"10.0.0.0/8": {422, "not_public"}, "203.0.113.0/24": {409, "duplicate"}, "192.0.2.0/24": {403, "limit_reached"}} {
		_, err := c.ThreatWatchAdd(ctx, key, cidr, "")
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != want.status || ae.Code != want.code || ae.Detail == "" || ErrorCode(err) != want.code {
			t.Fatalf("add %s: %v (%+v)", cidr, err, ae)
		}
	}

	if err := c.ThreatWatchDelete(ctx, key, 7); err != nil || gotMethod != http.MethodDelete || gotPath != "/api/v2/threat/watch/7" {
		t.Fatalf("delete: %v", err)
	}
	var ae *APIError
	if err := c.ThreatWatchDelete(ctx, key, 8); !errors.As(err, &ae) || ae.Status != 404 || ae.Code != "not_found" {
		t.Fatalf("delete 404: %v", err)
	}

	a, err := c.ThreatWatchAlerts(ctx, key, "")
	if err != nil || len(a.Alerts) != 2 || a.Next != "2026-10-20T12:30:00Z" || gotSince != "" {
		t.Fatalf("alerts: %+v %v", a, err)
	}
	if x := a.Alerts[0]; x.ID != 123 || x.NetworkID == nil || *x.NetworkID != 1 || !x.Listed || x.Score != 72 || len(x.Kinds) != 1 || x.FirstSeen != "2026-10-19" {
		t.Fatalf("alert 0: %+v", x)
	}
	if x := a.Alerts[1]; x.NetworkID != nil || x.Source != "dyndns" {
		t.Fatalf("alert 1: %+v", x)
	}
	if _, err := c.ThreatWatchAlerts(ctx, key, "2026-10-20T12:30:00+02:00"); err != nil || gotSince != "2026-10-20T12:30:00+02:00" {
		t.Fatalf("since not passed verbatim: %q %v", gotSince, err)
	}
	_, err = c.ThreatWatchAlerts(ctx, key, "slow")
	if !errors.As(err, &ae) || ae.Status != 429 || ae.RetryAfter != 90*time.Second || ae.Code != "rate_limited" {
		t.Fatalf("429: %v %+v", err, ae)
	}
}

// 401 kommt als *APIError (Status lesbar) und gilt trotzdem als ErrUnauthorized; kaputte Antworten sind Fehler.
func TestThreatWatchErrors(t *testing.T) {
	var status int
	var answer string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	defer srv.Close()
	c := NewClient(srv.URL+"/api/v2", "node64/test")
	ctx := context.Background()

	status, answer = http.StatusUnauthorized, `{"error":{"code":"unauthorized","message":"bad key"}}`
	_, err := c.ThreatWatchList(ctx, "k")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || !errors.Is(err, ErrUnauthorized) || ae.Code != "unauthorized" {
		t.Fatalf("401: %v", err)
	}
	status, answer = http.StatusForbidden, `{"error":"forbidden"}`
	if _, err := c.ThreatWatchList(ctx, "k"); !errors.As(err, &ae) || ae.Status != 403 || ae.Detail != "forbidden" || errors.Is(err, ErrUnauthorized) {
		t.Fatalf("403: %v", err)
	}
	status, answer = http.StatusBadGateway, `<html>bad gateway</html>`
	if _, err := c.ThreatWatchAlerts(ctx, "k", ""); !errors.As(err, &ae) || ae.Status != 502 {
		t.Fatalf("502: %v", err)
	}
	status, answer = http.StatusOK, `{"nodata":true}`
	if _, err := c.ThreatWatchList(ctx, "k"); err == nil {
		t.Fatal("answer without data accepted")
	}
	status, answer = http.StatusOK, `{"data":{"alerts":null,"next":""}}`
	if a, err := c.ThreatWatchAlerts(ctx, "k", ""); err != nil || a.Alerts == nil || len(a.Alerts) != 0 {
		t.Fatalf("empty alerts: %+v %v", a, err)
	}
	srv.Close()
	if _, err := c.ThreatWatchList(ctx, "k"); err == nil || errors.As(err, &ae) {
		t.Fatalf("network error must not be APIError: %v", err)
	}
}
