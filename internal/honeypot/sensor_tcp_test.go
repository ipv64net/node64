package honeypot

import (
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSensorTCP(t *testing.T) {
	p := sensorFreePort(t)
	_, rec := sensorStart(t, Config{Services: []Service{{SvcTCP, p, ""}}})
	send := func(b []byte) {
		c, err := net.Dial("tcp", sensorAddrOf(p))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write(b)
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Read(make([]byte, 1)) // wartet, bis der Sensor schliesst
	}

	send([]byte("hello\r\n"))
	e := rec.wait(t, func(e Event) bool { return string(e.Payload) == "hello\r\n" })
	if e.Kind != KindProbe || e.Service != SvcTCP || e.Port != p || e.Detail != "" {
		t.Fatalf("Probe: %+v", e)
	}

	// RDP-Verbindungsaufbau mit Cookie
	rdp := []byte("\x03\x00\x00\x2b\x26\xe0\x00\x00\x00\x00\x00Cookie: mstshash=Administr\r\n\x01\x00\x08\x00\x03\x00\x00\x00")
	send(rdp)
	e = rec.wait(t, func(e Event) bool { return e.Detail == "rdp" })
	if e.Username != "Administr" {
		t.Fatalf("RDP: %+v", e)
	}

	// HTTP auf fremdem Port
	send([]byte("GET /shell?cd+/tmp HTTP/1.1\r\nHost: 192.0.2.1:" + strconv.Itoa(p) + "\r\nUser-Agent: Hello, world\r\n\r\n"))
	e = rec.wait(t, func(e Event) bool { return e.Detail == "http" })
	if e.Method != "GET" || e.Path != "/shell?cd+/tmp" || e.UA != "Hello, world" || !strings.HasPrefix(e.Host, "192.0.2.1") {
		t.Fatalf("HTTP: %+v", e)
	}

	// TLS-ClientHello mit SNI
	c, err := net.Dial("tcp", sensorAddrOf(p))
	if err != nil {
		t.Fatal(err)
	}
	tc := tls.Client(c, &tls.Config{ServerName: "victim.example.org", InsecureSkipVerify: true})
	_ = tc.SetDeadline(time.Now().Add(8 * time.Second))
	_ = tc.Handshake()
	tc.Close()
	e = rec.wait(t, func(e Event) bool { return e.Detail == "tls" })
	if e.Host != "victim.example.org" || len(e.Payload) != MaxPayload {
		t.Fatalf("TLS: host %q, payload %d", e.Host, len(e.Payload))
	}
}

func TestSensorPortScan(t *testing.T) {
	var svcs []Service
	var nums []int
	for i := 0; i < sensorScanPorts; i++ {
		p := sensorFreePort(t)
		svcs = append(svcs, Service{SvcTCP, p, ""})
		nums = append(nums, p)
	}
	slices.Sort(nums)
	var ports []string
	for _, p := range nums {
		ports = append(ports, strconv.Itoa(p))
	}
	_, rec := sensorStart(t, Config{Services: svcs, Scan: true})
	touch := func() {
		for _, s := range svcs {
			c, err := net.Dial("tcp", sensorAddrOf(s.Port))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = c.Write([]byte("x"))
			c.Close()
		}
	}
	touch()
	e := rec.wait(t, sensorKind(KindPortScan))
	if e.Service != SvcScan || e.Detail != strings.Join(ports, ",") || e.Src.String() != "127.0.0.1" {
		t.Fatalf("Port-Scan: %+v", e)
	}
	touch()
	rec.wait(t, func(e Event) bool {
		return e.Kind == KindProbe && e.Port == svcs[len(svcs)-1].Port && rec.count(sensorKind(KindProbe)) >= 2*len(svcs)
	})
	if n := rec.count(sensorKind(KindPortScan)); n != 1 {
		t.Fatalf("Port-Scan %d mal gemeldet", n)
	}
}

func TestSensorScanWindow(t *testing.T) {
	var sc sensorScan
	src := netip.MustParseAddr("198.51.100.7")
	now := time.Now()
	for i, p := range []int{22, 23, 80} {
		if sc.touch(src, p, now.Add(time.Duration(i)*time.Second)) != nil {
			t.Fatal("zu frueh gemeldet")
		}
	}
	if sc.touch(src, 22, now.Add(4*time.Second)) != nil {
		t.Fatal("gleicher Port zaehlt doppelt")
	}
	if got := sc.touch(src, 443, now.Add(5*time.Second)); len(got) != 4 {
		t.Fatalf("nicht gemeldet: %v", got)
	}
	if sc.touch(src, 8080, now.Add(6*time.Second)) != nil {
		t.Fatal("im selben Fenster zweimal gemeldet")
	}
	// neues Fenster: wieder meldbar
	later := now.Add(sensorScanWindow + 10*time.Second)
	var got []int
	for i, p := range []int{22, 23, 80, 443} {
		got = sc.touch(src, p, later.Add(time.Duration(i)*time.Second))
	}
	if len(got) != 4 {
		t.Fatalf("neues Fenster: %v", got)
	}
	// Obergrenze: neue Quellen werden ignoriert, solange voll
	sc.reset()
	base := netip.MustParseAddr("10.0.0.0").As4()
	for i := 0; i < sensorScanMax+10; i++ {
		b := base
		b[2], b[3] = byte(i>>8), byte(i)
		sc.touch(netip.AddrFrom4(b), 22, now)
	}
	if len(sc.m) > sensorScanMax {
		t.Fatalf("Obergrenze ueberschritten: %d", len(sc.m))
	}
}
