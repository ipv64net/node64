package healthchecks

import (
	"encoding/json"
	"net/url"
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

// WHOIS: Formular -> Parameter -> Formular; Intervall mindestens 1 h, Wiederholung mindestens 10 min.
func TestWhoisFormAndInterval(t *testing.T) {
	in, err := checkFromForm(formRequest(url.Values{"name": {"Domain"}, "type": {"whois"}, "target": {"example.de"},
		"whois_source": {"whois"}, "whois_min_days": {"30"}, "whois_contains": {"nameserver: ns1.ipv64.net\n\ncountry: DE "}}))
	if err != nil {
		t.Fatal(err)
	}
	var p checks.WhoisParams
	if err := json.Unmarshal(in.Params, &p); err != nil || p.Source != "whois" || p.MinDays == nil || *p.MinDays != 30 || len(p.Contains) != 2 || p.Contains[1] != "country: DE" {
		t.Fatalf("params: %s %v", in.Params, err)
	}
	f := formFromCheck(&Check{Type: checks.TypeWhois, Target: in.Target, Params: in.Params})
	if f["whois_source"] != "whois" || f["whois_min_days"] != "30" || f["whois_contains"] != "nameserver: ns1.ipv64.net\ncountry: DE" {
		t.Fatalf("form back: %v", f)
	}

	_, srv := newTestModule(t)
	if code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "w", "type": "whois", "target": "example.de", "interval_seconds": 60}); code != 422 && code != 400 {
		t.Fatalf("60 s accepted: %d %s", code, b)
	}
	code, b := call(t, srv, "POST", "/api/checks", map[string]any{"name": "w", "type": "whois", "target": "example.de", "interval_seconds": 3600, "retry_interval_seconds": 20})
	if code != 201 && code != 200 {
		t.Fatalf("create: %d %s", code, b)
	}
	var c struct {
		RetryIntervalSeconds int `json:"retry_interval_seconds"`
	}
	_ = json.Unmarshal(b, &c)
	if c.RetryIntervalSeconds < 600 {
		t.Fatalf("retry: %d", c.RetryIntervalSeconds)
	}
}
