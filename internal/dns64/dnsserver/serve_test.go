package dnsserver

import (
	"net"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Shutdown direkt nach Serve muss den Socket schliessen (vorher lief ActivateAndServe unter Last manchmal erst
// nach dem Shutdown an, und der Port blieb belegt).
func TestServeThenShutdownFreesPort(t *testing.T) {
	for i := 0; i < 50; i++ {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := pc.LocalAddr().String()
		var wg sync.WaitGroup
		srv := &dns.Server{PacketConn: pc, Net: "udp", Handler: dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {})}
		Serve(srv, &wg, nil)
		if err := srv.Shutdown(); err != nil {
			t.Fatalf("round %d: shutdown: %v", i, err)
		}
		wg.Wait()
		again, err := net.ListenPacket("udp", addr)
		if err != nil {
			t.Fatalf("round %d: port still bound: %v", i, err)
		}
		again.Close()
	}
}

// Scheitert ActivateAndServe vor dem Start, kehrt Serve trotzdem zurueck.
func TestServeFailsBeforeStart(t *testing.T) {
	var wg sync.WaitGroup
	var got error
	Serve(&dns.Server{Net: "udp"}, &wg, func(err error) { got = err })
	wg.Wait()
	if got == nil {
		t.Fatal("missing error for server without socket")
	}
}
