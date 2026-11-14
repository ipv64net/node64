package ipam64

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/ipam64/oui"
	"github.com/ipv64net/node64/internal/notify"
)

// Konfliktregeln mit Daempfung: Ueberschneidung statt Tausch, fremde MAC erst nach 5 Minuten, Lease gegen feste Adresse.
func TestConflictRules(t *testing.T) {
	now := time.Now()
	row := func(mac string, first, last time.Duration) seenRow {
		return seenRow{MAC: mac, First: now.Add(-first), Last: now.Add(-last)}
	}
	cases := []struct {
		name string
		a    acc
		want string
	}{
		{"swap", acc{recent: []seenRow{row("aa", 14*time.Minute, 10*time.Minute), row("bb", 9*time.Minute, 0)}}, ""},
		{"dup", acc{recent: []seenRow{row("aa", 14*time.Minute, time.Minute), row("bb", 9*time.Minute, 0)}}, "dup"},
		{"foreign short", acc{assigned: []string{"aa"}, recent: []seenRow{row("bb", 2*time.Minute, 0)}}, ""},
		{"foreign", acc{assigned: []string{"aa"}, recent: []seenRow{row("bb", 6*time.Minute, 0)}}, "mac"},
		{"lease vs fixed", acc{e: Entry{UID: "u"}, ipamMAC: "aa", leaseMAC: "bb"}, "lease"},
		{"lease = reservation", acc{e: Entry{UID: "u"}, ipamMAC: "aa", ipamDHCP: true, leaseMAC: "bb"}, ""},
		{"own lease", acc{e: Entry{UID: "u"}, ipamMAC: "aa", leaseMAC: "aa"}, ""},
	}
	for _, c := range cases {
		if got := c.a.conflict(); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// Hinweise, unbekannte Geraete, Ignorieren und Benachrichtigungen.
func TestFindingsAndNotify(t *testing.T) {
	m, f, _ := modTest(t)
	ctx := context.Background()
	m.SetNetworks(func(context.Context) []NetHint {
		return []NetHint{{Name: "LAN", Subnet: netip.MustParsePrefix("192.168.1.0/24"), Start: ip("192.168.1.100"), End: ip("192.168.1.199"), Domain: "home.lan"}}
	})
	m.SetSource(SrcDHCP, func(context.Context) []Sighting {
		return []Sighting{{Addr: "192.168.1.50", MAC: "02:00:00:00:00:51", Name: "tablet", Kind: KindDHCP, Seen: time.Now()}}
	})
	m.SetSource(SrcDNS, func(context.Context) []Sighting { return []Sighting{{Addr: "192.168.1.40", Name: "nas-alt.home.lan"}} })
	m.SetForeign(func(context.Context) []ForeignDHCP {
		return []ForeignDHCP{{Net: "192.168.1.0/24", Server: "192.168.1.254"}}
	})
	mustPrefix(t, m, Prefix{Prefix: "192.168.1.0/24"})
	for _, a := range []Address{{Address: "192.168.1.50", Name: "beamer", MAC: "02:00:00:00:00:50"}, {Address: "192.168.1.40", Name: "nas-alt"}} {
		if _, err := m.SaveAddress(ctx, a, "t"); err != nil {
			t.Fatal(err)
		}
	}
	f.tab = map[netip.Addr]Neighbor{
		ip("192.168.1.150"): {MAC: "50:c7:bf:15:50:50", Age: time.Second}, // fest eingestellt im Pool
		ip("192.168.1.60"):  {MAC: "da:00:00:00:00:60", Age: time.Second}, // zufaellige MAC, unbekannt
	}
	if err := m.poll(ctx); err != nil {
		t.Fatal(err)
	}
	found, err := m.Findings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, x := range found {
		kinds[x.Kind] = x.IP
	}
	if kinds["lease"] != "192.168.1.50" || kinds["pool"] != "192.168.1.150" || kinds["stale"] != "192.168.1.40" || kinds["foreign"] != "192.168.1.254" {
		t.Fatalf("findings: %+v", found)
	}
	unk, _ := m.Unknown(ctx)
	if len(unk) != 2 {
		t.Fatalf("unknown: %+v", unk)
	}
	for _, e := range unk {
		if e.IP == "192.168.1.60" && e.Vendor != "random" {
			t.Fatalf("vendor: %+v", e)
		}
	}
	if err := m.SetIgnored(ctx, "DA-00-00-00-00-60", true); err != nil {
		t.Fatal(err)
	}
	if unk, _ = m.Unknown(ctx); len(unk) != 1 || unk[0].IP != "192.168.1.150" {
		t.Fatalf("ignored: %+v", unk)
	}
	// Benachrichtigungen: Konflikt einmal, neue Geraete erst nach der Schonfrist
	var sent []notify.Alert
	m.SetNotifier(func(a notify.Alert) { sent = append(sent, a) })
	m.started = time.Now().Add(-2 * time.Hour)
	if err := m.SetNotifyFlags(ctx, true, true); err != nil {
		t.Fatal(err)
	}
	m.notifyCheck(ctx)
	m.notifyCheck(ctx)
	var conflicts, devices int
	for _, a := range sent {
		if a.Kind != notify.KindIPAM {
			t.Fatalf("kind: %v", a.Kind)
		}
		switch {
		case strings.HasPrefix(a.Data["text"], "notify.text.ipam64_conflict_lease"):
			conflicts++
		case a.Data["text"] == "notify.text.ipam64_new_device":
			devices++
		}
	}
	if conflicts != 1 || devices != 1 {
		t.Fatalf("sent: %d conflicts, %d devices: %+v", conflicts, devices, sent)
	}
	if c, d := m.NotifyFlags(ctx); !c || !d {
		t.Fatal("flags")
	}
}

func TestOUI(t *testing.T) {
	if !oui.Random("da:00:00:00:00:01") || oui.Random("00:11:32:aa:10:10") || oui.Random("kaputt") {
		t.Fatal("random")
	}
	if oui.Lookup("da:00:00:00:00:01") != "" {
		t.Fatal("random mac has no vendor")
	}
	if oui.Size() < 10000 || oui.Lookup("00:11:32:aa:10:10") != "Synology Incorporated" || oui.Lookup("DC-A6-32-0A-64-02") != "Raspberry Pi Trading Ltd" {
		t.Fatalf("vendor list: %d entries", oui.Size())
	}
}
