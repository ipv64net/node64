package checker

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
)

func chk(target string) scheduler.Check {
	return scheduler.Check{Def: checks.Definition{Type: checks.TypeHTTP, Target: target}}
}

// Je Zielhost (ueber alle Accounts) und fuer den Server begrenzt; andere Ziele laufen weiter, der Eimer fuellt sich
// mit der Zeit wieder.
func TestThrottle(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	th := newThrottle(60, 1000, slog.New(slog.NewTextHandler(io.Discard, nil))) // 1 Lauf/s je Ziel, 60 auf Vorrat
	th.now = func() time.Time { return now }
	ok := 0
	for i := 0; i < 100; i++ {
		if th.allow(chk("https://opfer.example/pfad")) {
			ok++
		}
	}
	if ok != 60 || th.skipped != 40 {
		t.Fatalf("per target: %d allowed, %d skipped", ok, th.skipped)
	}
	if !th.allow(chk("https://anderes.example/")) {
		t.Fatal("other target throttled")
	}
	if th.allow(chk("http://OPFER.example:8080/x")) { // gleicher Host, andere Schreibweise/Port
		t.Fatal("same host not counted")
	}
	// IPv6/v4-gemappt: gleiche Adresse in anderer Schreibweise teilt den Eimer
	for _, v := range []string{"http://[2001:db8::1]/", "http://[2001:0db8:0:0::1]/", "https://[::ffff:192.0.2.1]/", "https://192.0.2.1/"} {
		th.allow(chk(v))
	}
	if n := len(th.targets); n != 4 { // opfer, anderes, 2001:db8::1, 192.0.2.1
		t.Fatalf("ipv6 keys not canonical: %d targets", n)
	}
	now = now.Add(5 * time.Second)
	ok = 0
	for i := 0; i < 10; i++ {
		if th.allow(chk("https://opfer.example/")) {
			ok++
		}
	}
	if ok != 5 {
		t.Fatalf("refill: %d", ok)
	}
	// Server-Grenze
	g := newThrottle(6000, 10, slog.New(slog.NewTextHandler(io.Discard, nil)))
	g.now = func() time.Time { return now }
	ok = 0
	for i := 0; i < 50; i++ {
		if g.allow(chk("https://ziel" + string(rune('a'+i%26)) + ".example/")) {
			ok++
		}
	}
	if ok != 10 {
		t.Fatalf("server limit: %d", ok)
	}
}
