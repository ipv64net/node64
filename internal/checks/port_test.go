package checks

import (
	"encoding/json"
	"testing"
)

func TestSplitTargetPort(t *testing.T) {
	cases := []struct {
		typ          Type
		target, in   string
		wantT, wantP string
		err          bool
	}{
		{TypeTCP, "server.de:8080", `{}`, "server.de", `{"port":8080}`, false},
		{TypePort, "server.de:8080", `{"port":8080,"expect":"closed"}`, "server.de", `{"expect":"closed","port":8080}`, false},
		{TypeTCP, "server.de:8080", `{"port":8443}`, "", "", true},
		{TypeCert, "[2001:db8::1]:8443", `{"min_days":7}`, "2001:db8::1", `{"min_days":7,"port":8443}`, false},
		{TypeTCP, "server.de", `{"port":22}`, "server.de", `{"port":22}`, false},
		{TypeHTTP, "example.com:8080", `{}`, "example.com:8080", `{}`, false},
		{TypeTCP, "server.de:0", `{}`, "", "", true},
	}
	for _, c := range cases {
		gotT, gotP, err := SplitTargetPort(c.typ, c.target, json.RawMessage(c.in))
		if (err != nil) != c.err {
			t.Fatalf("%s %s: err = %v", c.typ, c.target, err)
		}
		if c.err {
			continue
		}
		if gotT != c.wantT || string(gotP) != c.wantP {
			t.Errorf("%s %s: got %q %s, want %q %s", c.typ, c.target, gotT, gotP, c.wantT, c.wantP)
		}
	}
}

func TestDisplayTargetUsesMeasuredPort(t *testing.T) {
	cases := []struct {
		def  Definition
		want string
	}{
		{Definition{Type: TypeTCP, Target: "server.de:8080", Params: json.RawMessage(`{"port":8443}`)}, "server.de:8443"},
		{Definition{Type: TypeTCP, Target: "server.de:8080", Params: json.RawMessage(`{}`)}, "server.de:8080"},
		{Definition{Type: TypePort, Target: "server.de", Params: json.RawMessage(`{"port":22}`)}, "server.de:22"},
		{Definition{Type: TypeCert, Target: "server.de", Params: json.RawMessage(`{"port":443}`)}, "server.de"},
		{Definition{Type: TypeCert, Target: "2001:db8::1", Params: json.RawMessage(`{"port":8443}`)}, "[2001:db8::1]:8443"},
		{Definition{Type: TypeICMP, Target: "server.de"}, "server.de"},
	}
	for _, c := range cases {
		if got := DisplayTarget(c.def); got != c.want {
			t.Errorf("%s %s %s: got %q, want %q", c.def.Type, c.def.Target, c.def.Params, got, c.want)
		}
	}
}
