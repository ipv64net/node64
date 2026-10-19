package healthchecks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

func formRequest(vals url.Values) *http.Request {
	r := httptest.NewRequest("POST", "/healthchecks/new", strings.NewReader(vals.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// Formular -> Parameter -> Pruefung -> Formular fuer JSON- und DNS-Checks.
func TestFormJSONAndDNS(t *testing.T) {
	r := formRequest(url.Values{"name": {"API"}, "type": {"json"}, "target": {"https://example.org/health"},
		"json_rules": {"status == ok\nqueue < 100"}, "json_any": {"on"}, "follow_redirects": {"on"}})
	in, err := checkFromForm(r)
	if err != nil {
		t.Fatal(err)
	}
	var hp checks.HTTPParams
	if err := json.Unmarshal(in.Params, &hp); err != nil || len(hp.JSONRules) != 2 || !hp.JSONAny || hp.JSONRules[1].Op != "lt" {
		t.Fatalf("json params: %s %v", in.Params, err)
	}
	if err := checks.Validate(checks.Definition{Type: checks.TypeJSON, Target: in.Target, Params: in.Params}); err != nil {
		t.Fatal(err)
	}
	f := formFromCheck(&Check{Type: checks.TypeJSON, Target: in.Target, Params: in.Params})
	if f["json_rules"] != "status == ok\nqueue < 100" || f["json_any"] != "on" {
		t.Fatalf("json form back: %q %q", f["json_rules"], f["json_any"])
	}
	if _, err := checkFromForm(formRequest(url.Values{"type": {"json"}, "json_rules": {"status ?? ok"}})); err == nil {
		t.Fatal("bad rule accepted")
	}

	r = formRequest(url.Values{"name": {"Home"}, "type": {"dns"}, "target": {"home.example.org"}, "dns_record_type": {"AAAA"},
		"dns_resolver": {"server"}, "dns_server": {"192.168.10.30"}, "dns_expect": {"contains"}, "dns_values": {"2001:db8::1\n\n2001:db8::2"},
		"dns_dnssec": {"on"}, "dns_min_ttl": {"60"}})
	in, err = checkFromForm(r)
	if err != nil {
		t.Fatal(err)
	}
	var dp checks.DNSParams
	if err := json.Unmarshal(in.Params, &dp); err != nil || dp.RecordType != "AAAA" || dp.Server != "192.168.10.30" || len(dp.Values) != 2 || !dp.DNSSEC || dp.MinTTL != 60 {
		t.Fatalf("dns params: %s %v", in.Params, err)
	}
	if err := checks.Validate(checks.Definition{Type: checks.TypeDNS, Target: in.Target, Params: in.Params}); err != nil {
		t.Fatal(err)
	}
	if !checks.DNSNeedsNode(in.Params) {
		t.Fatal("home network server must be local only")
	}
	c := &Check{Type: checks.TypeDNS, Target: in.Target, Params: in.Params}
	f = formFromCheck(c)
	if f["dns_values"] != "2001:db8::1\n2001:db8::2" || f["dns_resolver"] != "server" || f["dns_min_ttl"] != "60" {
		t.Fatalf("dns form back: %+v", f)
	}
	if b := c.TargetBadge(); b.Text != "AAAA home.example.org" {
		t.Fatalf("badge: %+v", b)
	}
}
