package trap

import (
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/snmp"
)

// Test mit echten Traps (z. B. snmptrap/snmpinform aus einem net-snmp-Container), normal uebersprungen:
//
//	M64_TRAP_LISTEN=:1162 M64_TRAP_SENDER=m64-snmpd M64_TRAP_COMMUNITY=... M64_TRAP_V3="user:level:auth:authpass:priv:privpass"
//	M64_TRAP_EXPECT=4 M64_TRAP_READY=/src/.trap-ready go test -run Integration
//
// Der Test meldet Bereitschaft ueber die Datei M64_TRAP_READY und wartet auf M64_TRAP_EXPECT angenommene Traps.
func TestIntegrationTraps(t *testing.T) {
	listen := os.Getenv("M64_TRAP_LISTEN")
	if listen == "" {
		t.Skip("M64_TRAP_LISTEN nicht gesetzt")
	}
	var addrs []netip.Addr
	ips, err := net.LookupIP(os.Getenv("M64_TRAP_SENDER"))
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range ips {
		a, _ := netip.AddrFromSlice(ip)
		addrs = append(addrs, a.Unmap())
	}
	h := Host{ID: "sender", Addrs: addrs, Communities: []string{os.Getenv("M64_TRAP_COMMUNITY")}}
	for _, spec := range strings.Split(os.Getenv("M64_TRAP_V3"), ";") {
		f := strings.Split(spec, ":")
		if len(f) == 6 {
			h.Users = append(h.Users, User{Name: f[0], Level: f[1], AuthProto: f[2], PrivProto: f[4], Secret: snmp.Secret{AuthPass: f[3], PrivPass: f[5]}})
		}
	}
	want, _ := strconv.Atoi(os.Getenv("M64_TRAP_EXPECT"))
	evs := make(chan Event, 64)
	r, err := New(Config{Listen: listen}, func(e Event) { evs <- e })
	if err != nil {
		t.Fatal(err)
	}
	if err := r.SetHosts([]Host{h}); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()
	t.Logf("Empfaenger %s, Absender %v, Engine-ID %s", r.Addr(), addrs, r.EngineID())
	if p := os.Getenv("M64_TRAP_READY"); p != "" {
		_ = os.WriteFile(p, []byte(r.EngineID()), 0o644)
		defer os.Remove(p)
	}
	accepted := 0
	deadline := time.After(120 * time.Second)
	for accepted < want {
		select {
		case e := <-evs:
			t.Logf("Event: v%s inform=%v known=%v rejected=%q user=%q trap=%s (%s) kind=%s service=%q ifIndex=%d ifName=%q varbinds=%d",
				e.Version, e.Inform, e.Known, e.Rejected, e.User, e.TrapOID, e.TrapName, e.Kind, e.Service, e.IfIndex, e.IfName, len(e.Varbinds))
			if e.Known && e.Rejected == "" {
				accepted++
			}
		case <-deadline:
			t.Fatalf("nur %d von %d Traps angenommen; Stats %+v", accepted, want, r.Stats())
		}
	}
	t.Logf("Stats %+v", r.Stats())
}
