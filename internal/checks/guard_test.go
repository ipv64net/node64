package checks

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPublicAddr(t *testing.T) {
	for _, s := range []string{"1.1.1.1", "188.245.6.138", "2a01:4f8:c014:46b::1", "2606:4700:4700::1111"} {
		if !PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should be public", s)
		}
	}
	for _, s := range []string{"10.10.0.11", "10.100.0.110", "127.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0",
		"0.1.2.3", "198.18.0.1", "240.0.0.1", "255.255.255.255", "224.0.0.1", "::1", "::", "fd00::1", "fe80::1", "::ffff:10.0.0.1",
		"64:ff9b::a00:1", "2002:a00:1::1", "2001:db8::1", "ff02::1", "fec0::1", "::a00:1", "::8.8.8.8"} {
		if PublicAddr(netip.MustParseAddr(s)) {
			t.Errorf("%s should not be public", s)
		}
	}
}

// IsPrivateTarget: Adressen nach PublicAddr (auch v4-gemappt, ausgeschrieben, mit Zone), Namen nur localhost/.local.
func TestIsPrivateTargetIPv6(t *testing.T) {
	for _, c := range [][2]string{{"http", "http://[::ffff:7f00:1]/"}, {"icmp", "::ffff:10.0.0.1"}, {"icmp", "0:0:0:0:0:0:0:1"},
		{"icmp", "::"}, {"icmp", "fe90::1"}, {"icmp", "fe80::1%eth0"}, {"tcp", "[fd00::1]:22"}, {"http", "https://u:p@[fec0::1]:8443/x"},
		{"http", "2001:db8::1"}, {"tcp", "100.64.1.2:80"}, {"dns", "nas.local."}, {"http", "http://localhost:8080/"}} {
		if !IsPrivateTarget(c[0], c[1]) {
			t.Errorf("%s %s should be private", c[0], c[1])
		}
	}
	for _, c := range [][2]string{{"dns", "fcbayern.com"}, {"http", "https://fdroid.org/"}, {"icmp", "fe.example.org"},
		{"tcp", "[2606:4700:4700::1111]:53"}, {"http", "2a01:4f8:c014:46b::1"}, {"tcp", "1.1.1.1:53"}} {
		if IsPrivateTarget(c[0], c[1]) {
			t.Errorf("%s %s should be public", c[0], c[1])
		}
	}
}

// Auf den ipv64-Servern: kein Ziel im internen Netz – weder direkt, noch ueber einen Hostnamen, eine Weiterleitung
// oder einen DNS-Server; ohne DenyPrivate (Node) geht das wie bisher.
func TestDenyPrivate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	r := testRunner()
	r.DenyPrivate = true
	for _, d := range []Definition{
		def(TypeHTTP, srv.URL, nil),               // IP direkt
		def(TypeHTTP, "http://intern.test/", nil), // Hostname, der auf 127.0.0.1 zeigt
		def(TypePort, "intern.test:6379", nil),    // Port-Check ins interne Netz
		def(TypeDocker, "unix:///var/run/docker.sock", nil),
	} {
		res := r.Run(context.Background(), d)
		if len(res) != 1 || res[0].Status != Down || !strings.Contains(res[0].Message, "private or reserved") {
			t.Fatalf("%s %s: %+v", d.Type, d.Target, res)
		}
	}
	// Node: gleiche Pruefung erlaubt
	r.DenyPrivate = false
	if res := r.Run(context.Background(), def(TypeHTTP, srv.URL, nil)); res[0].Status != Up {
		t.Fatalf("node: %+v", res)
	}
	// Weiterleitung bzw. Verbindung zu einem internen Ziel scheitert am Dialer
	ctx := withDenyPrivate(context.Background())
	_, err := guard(ctx, &net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", strings.TrimPrefix(srv.URL, "http://"))
	if !errors.Is(err, ErrPrivateAddress) {
		t.Fatalf("dial: %v", err)
	}
	if _, err := guard(context.Background(), &net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", strings.TrimPrefix(srv.URL, "http://")); err != nil {
		t.Fatalf("dial without guard: %v", err)
	}
	// DNS-Check mit eigenem Server im internen Netz
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	dsrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		a := new(dns.Msg)
		a.SetReply(m)
		_ = w.WriteMsg(a)
	})}
	go func() { _ = dsrv.ActivateAndServe() }()
	defer dsrv.Shutdown()
	_, _, err = exchange(ctx, "example.org.", dns.TypeA, []string{pc.LocalAddr().String()}, true, false, time.Second)
	if err == nil || !strings.Contains(err.Error(), "private or reserved") {
		t.Fatalf("dns: %v", err)
	}
}
