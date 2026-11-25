package notify

import (
	"context"
	"strings"
	"testing"
	"time"
)

// #278: Meldungen, die der hub fuer den Check einer einzelnen Node verschickt, nennen in "Node:" diese Node statt des
// Portals; Sammelmeldungen nur, wenn alle Checks von derselben Node kommen.
func TestNodeLineOfMeasuringNode(t *testing.T) {
	d, st, rec := testDispatcher(t, map[string]string{SetNodeName: "ipv64.net Healthchecks"})
	addChannel(t, st, "default", true)
	at := time.Date(2026, 11, 24, 9, 34, 31, 0, time.UTC)
	cloud := CheckInfo{Name: "TEST", Type: "port", Target: "192.168.177.1", Token: "t1", NotifyDown: true, NotifyUp: true,
		NodeName: "docker-netcup", NodeLocation: "Netcup"}

	m := d.compose("de", Alert{Kind: KindDown, Check: cloud, Time: at, Reason: "port_closed"})
	if !strings.Contains(m.Text, "Node: docker-netcup (Netcup)") || strings.Contains(m.Text, "ipv64.net Healthchecks") {
		t.Fatalf("node line: %s", m.Text)
	}
	if n, _ := m.Payload["node"].(map[string]any); n["name"] != "docker-netcup" || n["location"] != "Netcup" {
		t.Fatalf("payload node: %v", m.Payload["node"])
	}
	// ohne messende Node (online, mehrere Nodes): Einstellung des Absenders
	online := cloud
	online.NodeName, online.NodeLocation = "", ""
	if m := d.compose("de", Alert{Kind: KindDown, Check: online, Time: at}); !strings.Contains(m.Text, "Node: ipv64.net Healthchecks") {
		t.Fatalf("default node line: %s", m.Text)
	}

	// Sammelmeldung der Ruhezeit: alle von derselben Node -> deren Name
	other := cloud
	other.Name, other.Token = "NAS", "t2"
	d.sendDigest(context.Background(), 0, []Alert{{Kind: KindDown, Check: cloud, Time: at}, {Kind: KindDown, Check: other, Time: at}})
	if msg := waitMsgs(t, rec, 1)[0]; !strings.Contains(msg.Text, "Node: docker-netcup (Netcup)") {
		t.Fatalf("digest same node: %s", msg.Text)
	}
	// verschiedene Nodes -> der Absender
	home := other
	home.NodeName, home.NodeLocation = "node64", "Zuhause"
	d.sendDigest(context.Background(), 0, []Alert{{Kind: KindDown, Check: cloud, Time: at}, {Kind: KindDown, Check: home, Time: at}})
	if msg := waitMsgs(t, rec, 2)[1]; !strings.Contains(msg.Text, "Node: ipv64.net Healthchecks") {
		t.Fatalf("digest mixed nodes: %s", msg.Text)
	}
}
