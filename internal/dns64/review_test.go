package dns64

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Neustart (neue Einstellungen) und Abschalten gleichzeitig: am Ende ist das Modul aus und der Port frei.
func TestRestartVersusStop(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	for round := 0; round < 5; round++ {
		if err := m.Start(ctx); err != nil || m.running() == nil {
			t.Fatalf("start: %v %s", err, m.startError())
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = m.restart(ctx) }()
		go func() {
			defer wg.Done()
			sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			_ = m.Stop(sctx)
		}()
		wg.Wait()
		// Stop vor dem Neustart: der Neustart sieht das Modul aus; Stop danach: stoppt den neu gestarteten Dienst
		if m.running() != nil {
			t.Fatalf("round %d: dns service still running after stop", round)
		}
		m.mu.Lock()
		on := m.life != nil
		m.mu.Unlock()
		if on {
			t.Fatal("module still on")
		}
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("round %d: port still bound: %v", round, err)
		}
		pc.Close()
	}
}

func TestConfigAddRemove(t *testing.T) {
	m, _ := testModule(t)
	c := m.loadConfig(context.Background())
	s := upstream.Server{Name: "Test", URL: "tls://dns.example", IPs: []string{"192.0.2.1"}}
	if err := c.addUpstream(s); err != nil {
		t.Fatal(err)
	}
	if err := c.addUpstream(s); err == nil {
		t.Fatal("duplicate upstream accepted")
	}
	if err := c.addList("Eigene", "https://lists.example/hosts.txt"); err != nil {
		t.Fatal(err)
	}
	if err := c.addList("", "ftp://x"); err == nil {
		t.Fatal("invalid list url accepted")
	}
	if c.removeCustom(upstream.Presets[0].URL) {
		t.Fatal("preset removed")
	}
	if !c.removeCustom("tls://dns.example") || !c.removeCustom("https://lists.example/hosts.txt") {
		t.Fatal("custom entries not removed")
	}
}
