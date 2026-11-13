package monitor64

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
)

// Adresse eines Hosts: Hostname, IPv4 und IPv6 in allen ueblichen Schreibweisen; was daraus fuer die Zugaenge wird.
func TestCleanAddressIPv6(t *testing.T) {
	for _, tc := range []struct {
		in, want   string
		agent, pve string
		trap       string
	}{
		{"nas", "nas", "nas:6556", "https://nas:8006", ""},
		{"nas:2222", "nas:2222", "nas:2222", "https://nas:2222", ""},
		{"10.0.0.5", "10.0.0.5", "10.0.0.5:6556", "https://10.0.0.5:8006", "10.0.0.5"},
		{"2001:db8::1", "2001:db8::1", "[2001:db8::1]:6556", "https://[2001:db8::1]:8006", "2001:db8::1"},
		{" [2001:db8::1] ", "2001:db8::1", "[2001:db8::1]:6556", "https://[2001:db8::1]:8006", "2001:db8::1"},
		{"[2001:db8::1]:2222", "[2001:db8::1]:2222", "[2001:db8::1]:2222", "https://[2001:db8::1]:2222", "2001:db8::1"},
		{"::1", "::1", "[::1]:6556", "https://[::1]:8006", "::1"},
		{"fe80::1%eth0", "fe80::1%eth0", "[fe80::1%eth0]:6556", "https://[fe80::1%eth0]:8006", "fe80::1"},
		{"[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "[fe80::1%eth0]:22", "https://[fe80::1%eth0]:22", "fe80::1"},
		{"::ffff:192.168.1.5", "::ffff:192.168.1.5", "[::ffff:192.168.1.5]:6556", "https://[::ffff:192.168.1.5]:8006", "192.168.1.5"},
	} {
		got, ok := cleanAddress(tc.in)
		if !ok || got != tc.want {
			t.Errorf("cleanAddress(%q) = %q, %v, erwartet %q", tc.in, got, ok, tc.want)
			continue
		}
		if a := accessAddr(got, 0, 6556); a != tc.agent {
			t.Errorf("%q: Agent %q, erwartet %q", tc.in, a, tc.agent)
		}
		if u := "https://" + hostPort(got, 8006); u != tc.pve {
			t.Errorf("%q: PVE %q, erwartet %q", tc.in, u, tc.pve)
		}
		if tc.trap != "" {
			if as := resolveAddrs(context.Background(), got); len(as) != 1 || as[0] != netip.MustParseAddr(tc.trap) {
				t.Errorf("%q: Trap-Absender %v, erwartet %s", tc.in, as, tc.trap)
			}
		}
	}
	for _, bad := range []string{"", "[2001:db8::1", "2001:db8::1]:22", "[nas]:22", "[2001:db8::1]:0", "[2001:db8::1]:x", "[2001:db8::1]22",
		"nas:99999", "nas:ssh", ":22", "a:b:c", "2001:db8::zz", "nas%eth0", "10.0.0.5 ; rm", "[10.0.0.5]:22"} {
		if got, ok := cleanAddress(bad); ok {
			t.Errorf("cleanAddress(%q) angenommen als %q", bad, got)
		}
	}
}

// Assistent "Linux per SSH": laeuft die Node im Docker-Bridge-Netz, sieht ein Host im LAN nicht die Adresse des
// Containers, sondern die des Docker-Hosts – dann gibt es keine Adresse, sondern den Hinweis. Liegt das Ziel im
// Bridge-Netz selbst (Docker-Host ueber das Gateway, andere Container), stimmt die Container-Adresse.
func TestNatHidden(t *testing.T) {
	_, br, _ := net.ParseCIDR("172.17.0.0/16")
	_, lo, _ := net.ParseCIDR("127.0.0.0/8")
	nets := []*net.IPNet{lo, br}
	local := net.ParseIP("172.17.0.3")
	for _, tc := range []struct {
		bridge bool
		remote string
		want   bool
	}{
		{true, "192.168.1.50", true},   // Host im LAN
		{true, "172.17.0.1", false},    // Docker-Host ueber das Gateway
		{true, "172.17.0.9", false},    // anderer Container
		{true, "127.0.0.1", false},     // die Node selbst
		{true, "2001:db8::5", true},    // IPv6-Ziel ausserhalb
		{false, "192.168.1.50", false}, // Host-Netz bzw. kein Container
	} {
		if got := natHidden(tc.bridge, local, net.ParseIP(tc.remote), nets); got != tc.want {
			t.Errorf("bridge=%v Ziel %s: %v, erwartet %v", tc.bridge, tc.remote, got, tc.want)
		}
	}
	if natHidden(true, nil, net.ParseIP("192.168.1.50"), nets) {
		t.Error("ohne eigene Adresse")
	}
}

// PBS: Hoechstalter der Backups in Stunden (Forum 5129: wer woechentlich sichert, bekam mit festen 26 h eine
// Dauerwarnung). Nur beim Zugang pbs, 1 bis 8760; leer bzw. 0 = 26 Stunden.
func TestBackupMaxAgeConfig(t *testing.T) {
	out, err := cleanAccessConfig("pbs", []byte(`{"token_id":"monitor@pbs!node64","backup_max_age_h":170}`))
	if err != nil {
		t.Fatal(err)
	}
	var c accessConfig
	if err := json.Unmarshal(out, &c); err != nil || c.BackupMaxAgeH != 170 {
		t.Fatalf("gespeichert: %s (%v)", out, err)
	}
	if out, err := cleanAccessConfig("pbs", []byte(`{"token_id":"monitor@pbs!node64"}`)); err != nil || strings.Contains(string(out), "backup_max_age_h") {
		t.Fatalf("ohne Angabe: %s %v", out, err)
	}
	for _, bad := range []string{`{"backup_max_age_h":-1}`, `{"backup_max_age_h":9000}`} {
		if _, err := cleanAccessConfig("pbs", []byte(bad)); err == nil {
			t.Errorf("%s angenommen", bad)
		}
	}
	if _, err := cleanAccessConfig("pve", []byte(`{"token_id":"monitor@pve!node64","backup_max_age_h":48}`)); err == nil {
		t.Error("Hoechstalter bei Proxmox VE angenommen")
	}
}
