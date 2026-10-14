package dns64

import (
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
	"github.com/ipv64net/node64/internal/notify"
)

func TestMonitor(t *testing.T) {
	var sent []string
	x := newMonitor(func(kind notify.Kind, name, reason, msg string) { sent = append(sent, string(kind)+":"+name) })
	t0 := time.Now()
	bad := []upstream.Stats{{Name: "Quad9", URL: "tls://dns.quad9.net", Proto: "dot", Requests: 10, Healthy: false, LastError: "timeout"}}
	good := []upstream.Stats{{Name: "Quad9", URL: "tls://dns.quad9.net", Proto: "dot", Requests: 11, Healthy: true}}
	list := func(f int) []filter.ListStatus {
		return []filter.ListStatus{{List: filter.List{Name: "OISD Small", URL: "https://small.oisd.nl/"}, Failures: f, Error: "HTTP 503"}}
	}

	x.check(t0, bad, list(1), true, true)
	x.check(t0.Add(2*time.Minute), bad, list(2), true, true)
	if len(sent) != 0 {
		t.Fatalf("too early: %v", sent)
	}
	x.check(t0.Add(3*time.Minute), bad, list(3), true, true)
	x.check(t0.Add(4*time.Minute), bad, list(4), true, true) // nur einmal
	if len(sent) != 2 || sent[0] != "dns64_upstream:Quad9 (DoT)" || sent[1] != "dns64_lists:OISD Small" {
		t.Fatalf("sent = %v", sent)
	}
	x.check(t0.Add(5*time.Minute), good, list(0), true, true)
	if len(sent) != 3 || sent[2] != "dns64_upstream_ok:Quad9 (DoT)" {
		t.Fatalf("recovery: %v", sent)
	}
	// kurz gestoert: keine Meldung; abgeschaltet: keine Meldung
	x.check(t0.Add(6*time.Minute), bad, list(0), true, true)
	x.check(t0.Add(7*time.Minute), good, list(0), true, true)
	x.check(t0.Add(8*time.Minute), bad, list(3), false, false)
	x.check(t0.Add(12*time.Minute), bad, list(4), false, false)
	if len(sent) != 3 {
		t.Fatalf("unexpected: %v", sent)
	}
}
