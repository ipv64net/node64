package cdnedge

import (
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

func freeListenPort(t *testing.T, network string) int {
	t.Helper()
	var addr string
	if network == "udp" {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		addr = pc.LocalAddr().String()
		pc.Close()
	} else {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		addr = ln.Addr().String()
		ln.Close()
	}
	_, p, _ := net.SplitHostPort(addr)
	n, _ := strconv.Atoi(p)
	return n
}

// Sperre nach dem Aufbau: eine offene Portmapper-Verbindung wird mit der neuen Konfiguration getrennt.
func TestLiveBlockedClosesOpenConn(t *testing.T) {
	back, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	go func() {
		for {
			c, err := back.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(c, c); c.Close() }() // Echo, bleibt offen
		}
	}()
	cf, kf, pool, _ := testCA(t, "edge.test")
	s := startEdge(t, &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), PortRange: "1024-65535"}, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	listen := freeListenPort(t, "tcp")
	conf := func(blocked string) *apiConfig {
		return &apiConfig{Hosts: []apiHost{{ID: 1, Name: "l.test", Mode: 3, UserID: 1, Blocked: blocked,
			Target:   &apiTarget{Addrs: []string{"127.0.0.1"}, Port: 80, Scheme: "http"},
			Mappings: []apiMapping{{Listen: listen, Transport: "tcp", Port: port(back.Addr().String())}}}}}
	}
	s.applyConfig(conf(""))
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(listen), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 10)
	if _, err := c.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	if n, err := c.Read(b); err != nil || string(b[:n]) != "hi" {
		t.Fatalf("echo: %q %v", b[:n], err)
	}
	for i := 0; i < 50 && s.liveCount() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.liveCount() != 1 {
		t.Fatalf("tracked: %d", s.liveCount())
	}
	s.applyConfig(conf("traffic")) // gesperrt (z. B. Traffic aufgebraucht)
	if _, err := c.Read(b); err == nil {
		t.Fatal("open connection must be closed after the name is blocked")
	}
	for i := 0; i < 50 && s.liveCount() != 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if s.liveCount() != 0 {
		t.Fatalf("still tracked: %d", s.liveCount())
	}
}

// UDP: das Ziel darf einem Besucher nicht viel mehr schicken, als von ihm kam (gefaelschte Absender).
func TestPortmapUDPAmplification(t *testing.T) {
	back, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	go func() { // auf jedes Datagramm 100 Antworten zu je 1000 Bytes
		b := make([]byte, 2048)
		big := make([]byte, 1000)
		for {
			_, from, err := back.ReadFromUDP(b)
			if err != nil {
				return
			}
			for i := 0; i < 100; i++ {
				_, _ = back.WriteToUDP(big, from)
			}
		}
	}()
	cf, kf, pool, _ := testCA(t, "edge.test")
	s := startEdge(t, &Config{Name: "A", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), PortRange: "1024-65535"}, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	listen := freeListenPort(t, "udp")
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "a.test", Mode: 3, UserID: 1,
		Target:   &apiTarget{Addrs: []string{"127.0.0.1"}, Port: 80, Scheme: "http"},
		Mappings: []apiMapping{{Listen: listen, Transport: "udp", Port: port(back.LocalAddr().String())}}}}})
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listen})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x")) // 1 Byte rein
	got := 0
	b := make([]byte, 2048)
	for {
		_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err := c.Read(b)
		if err != nil {
			break
		}
		got += n
	}
	if got == 0 || got > udpFree+udpAmp*1 {
		t.Fatalf("visitor got %d bytes for 1 byte sent (limit %d)", got, udpFree+udpAmp)
	}
}
