package ports

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestCheckAndOverview(t *testing.T) {
	ctx := context.Background()
	r := New()
	r.Provide("web", func(context.Context) []Claim {
		return []Claim{{Purpose: "HTTP", Proto: TCP, Port: 8080, Active: true}}
	})
	dohOn := true
	r.Provide("dns64", func(context.Context) []Claim {
		return []Claim{{Purpose: "DNS", Proto: UDP, Port: 53, Active: true}, {Purpose: "DoH", Proto: TCP, Port: 443, Active: dohOn}}
	})
	r.Provide("edge", func(context.Context) []Claim {
		return []Claim{{Purpose: "HTTPS", Proto: TCP, Port: 443}, {Purpose: "HTTP/3", Proto: UDP, Port: 443}}
	})

	err := r.Check(ctx, "edge", []Claim{{Proto: TCP, Port: 443}})
	var ce *ConflictError
	if !errors.As(err, &ce) || ce.With.Owner != "dns64" || ce.With.Purpose != "DoH" {
		t.Fatalf("443/tcp must conflict with DoH: %v", err)
	}
	if err := r.Check(ctx, "edge", []Claim{{Proto: UDP, Port: 443}, {Proto: TCP, Port: 80}}); err != nil {
		t.Fatalf("443/udp and 80/tcp are free: %v", err)
	}
	if err := r.Check(ctx, "dns64", []Claim{{Proto: TCP, Port: 443}}); err != nil {
		t.Fatalf("own claim must not conflict: %v", err)
	}
	if err := r.Check(ctx, "edge", []Claim{{Proto: TCP, Port: 8080, Bind: "192.0.2.1"}}); err == nil {
		t.Fatal("a specific address overlaps with all addresses")
	}

	var doh Entry
	for _, e := range r.Overview(ctx) {
		if e.Owner == "dns64" && e.Port == 443 {
			doh = e
		}
	}
	if len(doh.Conflicts) != 1 || doh.Conflicts[0] != "edge (HTTPS)" {
		t.Fatalf("overview conflicts: %+v", doh)
	}
	dohOn = false // DoH aus, Edge nur eingestellt: kein Konflikt mehr
	for _, e := range r.Overview(ctx) {
		if len(e.Conflicts) > 0 {
			t.Fatalf("no conflict expected: %+v", e)
		}
	}
	if err := r.Check(ctx, "edge", []Claim{{Proto: TCP, Port: 443}}); err != nil {
		t.Fatalf("443 is free now: %v", err)
	}
}

func TestOverlap(t *testing.T) {
	cases := []struct {
		a, b Claim
		want bool
	}{
		{Claim{Proto: TCP, Port: 1}, Claim{Proto: UDP, Port: 1}, false},
		{Claim{Proto: TCP, Port: 1, Bind: "10.0.0.1"}, Claim{Proto: TCP, Port: 1, Bind: "10.0.0.2"}, false},
		{Claim{Proto: TCP, Port: 1, Bind: "10.0.0.1"}, Claim{Proto: TCP, Port: 1, Bind: "::"}, true},
		{Claim{Proto: TCP, Port: 1, Bind: "10.0.0.1"}, Claim{Proto: TCP, Port: 1, Bind: "10.0.0.1"}, true},
	}
	for _, c := range cases {
		if got := Overlap(c.a, c.b); got != c.want {
			t.Errorf("%v vs %v: %v", c.a, c.b, got)
		}
	}
}

func TestProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	if err := Probe(TCP, "127.0.0.1", port); err == nil {
		t.Fatal("busy port must fail the probe")
	}
	ln.Close()
	if err := Probe(TCP, "127.0.0.1", port); err != nil {
		t.Fatalf("free port: %v", err)
	}
}
