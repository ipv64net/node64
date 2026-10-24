package dns64

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// Pruefnamen ueber die echten Ports (hier statt des Docker-Gateways die eigene Adresse) kommen beim eigenen Dienst
// an; ein Port ohne Dienst nicht. Fehlende Ports stehen in der Port-Uebersicht und auf den Seiten mit Beispiel.
func TestPublishedProbe(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	port = startUp(t, m, port)
	e := m.running()
	c := m.loadConfig(ctx)
	targets := m.probeTargets(c, netip.MustParseAddr("127.0.0.1"))
	if len(targets) != 2 {
		t.Fatalf("targets = %d", len(targets))
	}
	for key, send := range targets {
		if !e.local.Probe(ctx, send) {
			t.Fatalf("%s: probe did not arrive", key)
		}
	}
	c.Port = freePort(t) // nichts lauscht dort
	for key, send := range m.probeTargets(c, netip.MustParseAddr("127.0.0.1")) {
		if e.local.Probe(ctx, send) {
			t.Fatalf("%s: probe arrived without a listener", key)
		}
	}

	key := strconv.Itoa(port) + "/udp"
	m.pub.Store(&pubState{Bridge: true, Gateway: "172.17.0.1", Missing: []string{key}})
	var udp, tcp string
	for _, x := range m.Ports(ctx, true) {
		if x.Purpose == "DNS" && x.Proto == "udp" {
			udp = x.Error
		} else if x.Purpose == "DNS" {
			tcp = x.Error
		}
	}
	if !strings.Contains(udp, "-p "+strconv.Itoa(port)+":"+strconv.Itoa(port)+"/udp") || tcp != "" {
		t.Fatalf("port errors udp=%q tcp=%q", udp, tcp)
	}
	v := m.pubView(ctx, e)
	p := strconv.Itoa(port)
	if !v.Bridge || v.Publish != "-p "+p+":"+p+"/udp" || v.Compose != `"`+p+":"+p+`/udp"` {
		t.Fatalf("view = %+v", v)
	}
	if !m.pubMissing(port, "udp") || m.pubMissing(port, "tcp") {
		t.Fatal("pubMissing")
	}
}
