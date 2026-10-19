package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestJSONPath(t *testing.T) {
	doc := map[string]any{"a": map[string]any{"b": []any{map[string]any{"c": "x"}}}}
	steps, err := parseJSONPath("$.a.b[0].c")
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := lookupJSON(doc, steps); !ok || v != "x" {
		t.Fatalf("lookup: %v %v", v, ok)
	}
	for _, bad := range []string{"a..b", "a[x]", "a[0", "a[-1]"} {
		if _, err := parseJSONPath(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestJSONCheck(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/status":
			w.Write([]byte(`{"status":"ok","queue":42,"healthy":true,"tags":["a","b"],"items":[{"name":"db","up":false}]}`))
		case "/html":
			w.Write([]byte("<html>"))
		}
	}))
	defer srv.Close()
	r := testRunner()
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	rules := func(anyOf bool, rr ...JSONRule) map[string]any {
		return map[string]any{"json_rules": rr, "json_any": anyOf}
	}

	res := one(t, r, def(TypeJSON, base+"/status", rules(false,
		JSONRule{Path: "status", Op: "eq", Value: "ok"},
		JSONRule{Path: "queue", Op: "lt", Value: "100"},
		JSONRule{Path: "healthy", Op: "eq", Value: "true"},
		JSONRule{Path: "tags", Op: "contains", Value: "b"},
		JSONRule{Path: "version", Op: "not_exists"})))
	if res.Status != Up || res.Details["value"] != nil && res.Details["json_value"] != "ok" {
		t.Fatalf("all rules: %+v", res)
	}
	if !strings.Contains(res.Message, "status = ok") {
		t.Fatalf("message: %q", res.Message)
	}
	// Zahl der ersten Bedingung landet als value in den Details
	res = one(t, r, def(TypeJSON, base+"/status", rules(false, JSONRule{Path: "queue", Op: "ge", Value: "42"})))
	if res.Status != Up || res.Details["value"] != 42.0 {
		t.Fatalf("value: %+v", res.Details)
	}
	res = one(t, r, def(TypeJSON, base+"/status", rules(false, JSONRule{Path: "items[0].up", Op: "eq", Value: "true"})))
	if res.Status != Down || res.Reason != ReasonJSONMismatch || !strings.Contains(res.Message, "is false") {
		t.Fatalf("mismatch: %+v", res)
	}
	// eine von zwei genuegt
	res = one(t, r, def(TypeJSON, base+"/status", rules(true, JSONRule{Path: "items[0].up", Op: "eq", Value: "true"}, JSONRule{Path: "queue", Op: "gt", Value: "1"})))
	if res.Status != Up {
		t.Fatalf("any: %+v", res)
	}
	res = one(t, r, def(TypeJSON, base+"/html", rules(false, JSONRule{Path: "status", Op: "exists"})))
	if res.Status != Down || res.Reason != ReasonJSONInvalid {
		t.Fatalf("not json: %+v", res)
	}
	if err := Validate(def(TypeJSON, base+"/status", rules(false))); err == nil {
		t.Fatal("json without rules accepted")
	}
	if err := Validate(def(TypeJSON, base+"/status", rules(false, JSONRule{Path: "q", Op: "lt", Value: "abc"}))); err == nil {
		t.Fatal("lt with text accepted")
	}
}

// testDNS startet einen kleinen Nameserver auf 127.0.0.1 fuer example.test.
func testDNS(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc("example.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		switch {
		case q.Name == "www.example.test." && q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR("www.example.test. 300 IN A 192.0.2.10")
			rr2, _ := dns.NewRR("www.example.test. 300 IN A 192.0.2.11")
			m.Answer = append(m.Answer, rr, rr2)
		case q.Name == "example.test." && q.Qtype == dns.TypeTXT:
			rr, _ := dns.NewRR(`example.test. 60 IN TXT "v=spf1 include:_spf.example.net -all"`)
			m.Answer = append(m.Answer, rr)
		case q.Name == "example.test." && q.Qtype == dns.TypeMX:
			rr, _ := dns.NewRR("example.test. 300 IN MX 10 Mail.Example.Test.")
			m.Answer = append(m.Answer, rr)
		case q.Name == "home.example.test." && q.Qtype == dns.TypeA:
			rr, _ := dns.NewRR("home.example.test. 60 IN A 203.0.113.5")
			m.Answer = append(m.Answer, rr)
		default:
			m.Rcode = dns.RcodeNameError
		}
		w.WriteMsg(m)
	})
	srv := &dns.Server{PacketConn: pc, Handler: mux}
	go srv.ActivateAndServe()
	t.Cleanup(func() { srv.Shutdown() })
	return pc.LocalAddr().String()
}

func TestDNSCheck(t *testing.T) {
	addr := testDNS(t)
	r := testRunner()
	p := func(m map[string]any) map[string]any { m["resolver"] = "server"; m["server"] = addr; return m }
	run := func(target string, params map[string]any) Result { return one(t, r, def(TypeDNS, target, p(params))) }

	if res := run("www.example.test", map[string]any{}); res.Status != Up || !strings.Contains(res.Message, "192.0.2.10, 192.0.2.11") {
		t.Fatalf("any: %+v", res)
	}
	if res := run("www.example.test", map[string]any{"expect": "contains", "values": []string{"192.0.2.11"}}); res.Status != Up {
		t.Fatalf("contains: %+v", res)
	}
	if res := run("www.example.test", map[string]any{"expect": "equals", "values": []string{"192.0.2.10"}}); res.Status != Down || res.Reason != ReasonDNSMismatch {
		t.Fatalf("equals with extra record: %+v", res)
	}
	if res := run("example.test", map[string]any{"record_type": "MX", "expect": "equals", "values": []string{"10 mail.example.test"}}); res.Status != Up {
		t.Fatalf("mx case-insensitive: %+v", res)
	}
	if res := run("example.test", map[string]any{"record_type": "TXT", "expect": "regex", "values": []string{"^v=spf1 .*-all$"}}); res.Status != Up {
		t.Fatalf("txt regex: %+v", res)
	}
	if res := run("example.test", map[string]any{"record_type": "TXT", "min_ttl": 300}); res.Status != Down {
		t.Fatalf("min ttl: %+v", res)
	}
	if res := run("gone.example.test", map[string]any{}); res.Status != Down || res.Reason != ReasonDNSNXDomain {
		t.Fatalf("nxdomain down: %+v", res)
	}
	if res := run("gone.example.test", map[string]any{"expect": "nxdomain"}); res.Status != Up {
		t.Fatalf("nxdomain expected: %+v", res)
	}
	// oeffentliche IP: nur mit PublicIP (Node), sonst ungueltig
	if res := run("home.example.test", map[string]any{"expect": "public_ip"}); res.Status != Down || res.Reason != ReasonInvalid {
		t.Fatalf("public_ip without node: %+v", res)
	}
	r.PublicIP = func(context.Context, string) (string, error) { return "203.0.113.5", nil }
	if res := run("home.example.test", map[string]any{"expect": "public_ip"}); res.Status != Up {
		t.Fatalf("public_ip: %+v", res)
	}
	r.PublicIP = func(context.Context, string) (string, error) { return "203.0.113.9", nil }
	if res := run("home.example.test", map[string]any{"expect": "public_ip"}); res.Status != Down || !strings.Contains(res.Message, "203.0.113.9") {
		t.Fatalf("public_ip mismatch: %+v", res)
	}
}

func TestDNSValidateAndNeedsNode(t *testing.T) {
	ok := []map[string]any{{}, {"record_type": "aaaa"}, {"resolver": "server", "server": "1.1.1.1"}, {"resolver": "server", "server": "[2606:4700::1111]:53"},
		{"expect": "contains", "values": []string{"1.2.3.4"}}, {"resolver": "authoritative"}}
	for _, p := range ok {
		if err := Validate(def(TypeDNS, "example.org", p)); err != nil {
			t.Fatalf("%v: %v", p, err)
		}
	}
	bad := []map[string]any{{"record_type": "XYZ"}, {"resolver": "server", "server": "dns.google"}, {"expect": "contains"},
		{"expect": "regex", "values": []string{"("}}, {"expect": "public_ip", "record_type": "MX"}, {"min_ttl": -1}}
	for _, p := range bad {
		if err := Validate(def(TypeDNS, "example.org", p)); err == nil {
			t.Fatalf("%v accepted", p)
		}
	}
	if err := Validate(def(TypeDNS, "not a name", nil)); err == nil {
		t.Fatal("bad name accepted")
	}
	if !DNSNeedsNode([]byte(`{"resolver":"server","server":"192.168.10.30"}`)) || !DNSNeedsNode([]byte(`{"expect":"public_ip"}`)) || DNSNeedsNode([]byte(`{"resolver":"server","server":"1.1.1.1"}`)) {
		t.Fatal("DNSNeedsNode")
	}
	if !IsPrivateTarget("dns", "nas.local") || IsPrivateTarget("dns", "example.org") || !IsPrivateTarget("json", "http://192.168.1.2/api") {
		t.Fatal("IsPrivateTarget")
	}
}

func TestJSONRulesText(t *testing.T) {
	rules, err := ParseJSONRules("status == ok\n\n# Kommentar\nqueue < 100\nmsg == \"two words\"\nversion !exists\nname ~ ^web-[0-9]+$")
	if err != nil || len(rules) != 5 || rules[2].Value != "two words" || rules[3].Op != "not_exists" || rules[4].Op != "regex" {
		t.Fatalf("parse: %+v %v", rules, err)
	}
	back, _ := ParseJSONRules(FormatJSONRules(rules))
	if len(back) != 5 || back[1].Op != "lt" || back[1].Value != "100" {
		t.Fatalf("round trip: %+v", back)
	}
	for _, bad := range []string{"status", "a ?? b", "x exists y"} {
		if _, err := ParseJSONRules(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
