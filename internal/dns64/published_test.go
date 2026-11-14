package dns64

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// Issue #137: Port nur an eine Host-Adresse gebunden (192.168.2.8:53:53/udp) - ueber das Gateway kommt der
// Pruefname nicht an. Kein Hinweis, sobald das Port-Binding des eigenen Containers (Docker-API) den Port zeigt
// oder Anfragen ueber dieses Protokoll von ausserhalb der Container-Netze ankommen; Absender aus dem Docker-Netz
// (Gateway) zaehlen nicht.
func TestPublishedHostIPBinding(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	oldBridge, oldNets, oldSelf := pubBridge, ownNets, pubSelf
	pubBridge = func() bool { return false } // der Lauf im Hintergrund prueft nicht dazwischen
	ownNets = func() []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")} }
	pubSelf = func() (string, error) { return "node64", nil }
	fd := &fakeBindings{}
	srv := httptest.NewServer(fd)
	oldHost := dockerDNSHost
	dockerDNSHost = func() string { return srv.URL }
	t.Cleanup(func() { pubBridge, ownNets, pubSelf, dockerDNSHost = oldBridge, oldNets, oldSelf, oldHost; srv.Close() })

	port = startUp(t, m, port)
	e := m.running()
	c := m.loadConfig(ctx)
	p := strconv.Itoa(port)
	// "Gateway" ohne Dienst (DNS64 lauscht nur auf 127.0.0.1): wie ein nur an die LAN-Adresse gebundener Port
	gw := netip.MustParseAddr("127.0.0.2")
	m.checkPublishedAt(ctx, e, c, true, gw)
	if v := m.pubView(ctx, e); len(v.Missing) != 2 {
		t.Fatalf("ohne Binding und Ankunft: missing = %v", v.Missing)
	}

	m.pubArrived(netip.MustParseAddr("172.20.0.1"), "udp") // Gateway bzw. Docker-Netz: kein Beleg
	if v := m.pubView(ctx, e); len(v.Missing) != 2 {
		t.Fatalf("Ankunft aus dem Docker-Netz zaehlt: missing = %v", v.Missing)
	}
	m.pubArrived(netip.MustParseAddr("192.168.2.50"), "udp") // echter LAN-Client ueber UDP
	if v := m.pubView(ctx, e); len(v.Missing) != 1 || v.Missing[0] != p+"/tcp" || v.Publish != "-p "+p+":"+p+"/tcp" {
		t.Fatalf("nach LAN-Ankunft ueber UDP: %+v", v)
	}
	if m.pubMissing(port, "udp") || !m.pubMissing(port, "tcp") {
		t.Fatal("Port-Uebersicht folgt den Ankuenften nicht")
	}

	// Docker-API: TCP nur an die LAN-Adresse gebunden, dazu eine Bindung nur an 127.0.0.1 (zaehlt nicht)
	m.pubSeen.Clear()
	fd.ports = map[string]any{p + "/tcp": []map[string]string{{"HostIp": "192.168.2.8", "HostPort": p}},
		p + "/udp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": p}}}
	m.checkPublishedAt(ctx, e, c, true, gw)
	if v := m.pubView(ctx, e); len(v.Missing) != 1 || v.Missing[0] != p+"/udp" {
		t.Fatalf("mit Binding: missing = %v", v.Missing)
	}
	if fd.path != "/containers/node64/json" {
		t.Fatalf("docker path = %q", fd.path)
	}
}

// fakeBindings liefert /containers/{id}/json mit den Port-Bindings ports.
type fakeBindings struct {
	ports map[string]any
	path  string
}

func (f *fakeBindings) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.path = r.URL.Path
	_ = json.NewEncoder(w).Encode(map[string]any{"NetworkSettings": map[string]any{"Ports": f.ports}})
}
