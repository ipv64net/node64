package cdnedge

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Portmapper (T8): TCP und UDP an das Ziel, Liste, SSRF-Schutz, Zielwechsel, Bereich, Ports schliessen,
// Stufe 0 (keine Webseite).
func TestPortmap(t *testing.T) {
	// Ziele: TCP-Echo mit Kennung, zwei UDP-Echos
	tcpBack, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpBack.Close()
	go func() {
		for {
			c, err := tcpBack.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				b := make([]byte, 100)
				n, _ := c.Read(b)
				_, _ = c.Write(append([]byte("T:"), b[:n]...))
			}()
		}
	}()
	udpEcho := func(tag string) *net.UDPConn {
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			b := make([]byte, 100)
			for {
				n, from, err := pc.ReadFromUDP(b)
				if err != nil {
					return
				}
				_, _ = pc.WriteToUDP(append([]byte(tag+":"), b[:n]...), from)
			}
		}()
		return pc
	}
	u1, u2 := udpEcho("U1"), udpEcho("U2")
	defer u1.Close()
	defer u2.Close()
	port := func(a net.Addr) int { _, p, _ := net.SplitHostPort(a.String()); n, _ := strconv.Atoi(p); return n }
	freeUDP := func() int {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return port(pc.LocalAddr())
	}
	freeTCP := func() int { _, p, _ := net.SplitHostPort(freeAddr(t)); n, _ := strconv.Atoi(p); return n }

	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), PortRange: "1024-65535"}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	lt, lu, lacl, lbad := freeTCP(), freeUDP(), freeTCP(), freeTCP()
	tgt := func(addr string) *apiTarget {
		return &apiTarget{Addrs: []string{addr}, Port: 80, Scheme: "http", Frontend: 0}
	}
	conf := func(udpTarget int) *apiConfig {
		return &apiConfig{Hosts: []apiHost{
			{ID: 1, Name: "p.test", Mode: 3, UserID: 1, Target: tgt("127.0.0.1"), Mappings: []apiMapping{
				{Listen: lt, Transport: "tcp", Port: port(tcpBack.Addr())}, {Listen: lu, Transport: "udp", Port: udpTarget},
				{Listen: 1000, Transport: "tcp", Port: port(tcpBack.Addr())}}}, // ausserhalb des Bereichs
			{ID: 2, Name: "acl.test", Mode: 3, UserID: 1, Target: tgt("127.0.0.1"), ACL: &apiACL{Default: "deny"},
				Mappings: []apiMapping{{Listen: lacl, Transport: "tcp", Port: port(tcpBack.Addr())}}},
			{ID: 3, Name: "bad.test", Mode: 3, UserID: 1, Target: tgt("10.0.0.1"), // kein oeffentliches Ziel
				Mappings: []apiMapping{{Listen: lbad, Transport: "tcp", Port: port(tcpBack.Addr())}}},
		}}
	}
	s.applyConfig(conf(port(u1.LocalAddr())))
	tcpTalk := func(p int) string {
		t.Helper()
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(p), 3*time.Second)
		if err != nil {
			return "dial: " + err.Error()
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		_, _ = c.Write([]byte("hi"))
		b, _ := io.ReadAll(c)
		return string(b)
	}
	if got := tcpTalk(lt); got != "T:hi" {
		t.Fatalf("tcp mapping: %q", got)
	}
	if got := tcpTalk(lacl); got != "" {
		t.Fatalf("tcp mapping with deny list: %q", got)
	}
	if got := tcpTalk(lbad); got != "" {
		t.Fatalf("tcp mapping to a private target: %q", got)
	}
	if tc, _ := s.pm.open(); tc != 3 {
		t.Fatalf("open tcp ports: %d (port 1000 must be ignored)", tc)
	}
	// UDP: zwei Besucher, Antworten an den richtigen
	udpClient := func() *net.UDPConn {
		c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: lu})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	udpTalk := func(c *net.UDPConn, msg string) string {
		t.Helper()
		_, _ = c.Write([]byte(msg))
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		b := make([]byte, 100)
		n, err := c.Read(b)
		if err != nil {
			return "err: " + err.Error()
		}
		return string(b[:n])
	}
	c1, c2 := udpClient(), udpClient()
	defer c1.Close()
	defer c2.Close()
	if a, b := udpTalk(c1, "one"), udpTalk(c2, "two"); a != "U1:one" || b != "U1:two" {
		t.Fatalf("udp mapping: %q %q", a, b)
	}
	st := s.stats.of("p.test")
	// Zaehler steigen erst nach dem Weiterleiten der Antwort: mit Frist warten
	for deadline := time.Now().Add(5 * time.Second); st.BytesOut.Load() < 4+6+6 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if st.Conns.Load() != 3 || st.BytesIn.Load() != 2+3+3 || st.BytesOut.Load() != 4+6+6 {
		t.Fatalf("stats: conns %d in %d out %d", st.Conns.Load(), st.BytesIn.Load(), st.BytesOut.Load())
	}
	// Ziel-Port geaendert: dieselbe Sitzung geht ans neue Ziel
	s.applyConfig(conf(port(u2.LocalAddr())))
	if got := udpTalk(c1, "again"); got != "U2:again" {
		t.Fatalf("udp after target change: %q", got)
	}
	// Stufe 0: keine Webseite auf Port 80
	req, _ := http.NewRequest("GET", "http://"+cfg.ListenHTTP+"/", nil)
	req.Host = "p.test"
	if resp, err := http.DefaultClient.Do(req); err == nil {
		resp.Body.Close()
		t.Fatalf("frontend 0 answered on port 80: %d", resp.StatusCode)
	}
	// Mapping entfernt: Ports zu
	s.applyConfig(&apiConfig{})
	if tc, uc := s.pm.open(); tc != 0 || uc != 0 {
		t.Fatalf("ports still open: tcp %d udp %d", tc, uc)
	}
	if got := tcpTalk(lt); !strings.HasPrefix(got, "dial:") {
		t.Fatalf("closed port still answers: %q", got)
	}
}

func TestPortRange(t *testing.T) {
	for in, want := range map[string][2]int{"": {50000, 62000}, "off": {0, 0}, "40000-41000": {40000, 41000}, "80-90": {0, 0}, "5-4": {0, 0}} {
		if lo, hi := parsePortRange(in); lo != want[0] || hi != want[1] {
			t.Errorf("%q: %d-%d", in, lo, hi)
		}
	}
}

// UDP nimmt immer IPv6 zuerst, auch wenn "IPv6 bevorzugen" aus ist (an der IPv4 lauscht hier nichts).
func TestPortmapUDPIPv6First(t *testing.T) {
	back, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skip("kein IPv6 auf dem Testrechner")
	}
	defer back.Close()
	go func() {
		b := make([]byte, 100)
		for {
			n, from, err := back.ReadFromUDP(b)
			if err != nil {
				return
			}
			_, _ = back.WriteToUDP(append([]byte("v6:"), b[:n]...), from)
		}
	}()
	_, bp, _ := net.SplitHostPort(back.LocalAddr().String())
	tport, _ := strconv.Atoi(bp)
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	_, lp, _ := net.SplitHostPort(pc.LocalAddr().String())
	listen, _ := strconv.Atoi(lp)
	pc.Close()
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), PortRange: "1024-65535"}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "u.test", Mode: 3, UserID: 1,
		Target:   &apiTarget{Addrs: []string{"127.0.0.1", "::1"}, Port: 80, Scheme: "http", PreferIPv6: false},
		Mappings: []apiMapping{{Listen: listen, Transport: "udp", Port: tport}}}}})
	c, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: listen})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte("x"))
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	b := make([]byte, 100)
	n, err := c.Read(b)
	if err != nil || string(b[:n]) != "v6:x" {
		t.Fatalf("udp did not go to the IPv6 target: %q %v", b[:n], err)
	}
}

// Leerlauf: eine ruhende TCP-Verbindung wird getrennt, eine aktive bleibt.
func TestPortmapTCPIdle(t *testing.T) {
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
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }() // liest, antwortet nie
		}
	}()
	cf, kf, pool, _ := testCA(t, "edge.test")
	cfg := &Config{Name: "B", ListenHTTP: freeAddr(t), TLSCert: cf, TLSKey: kf, DataDir: t.TempDir(), PortRange: "1024-65535"}
	s := startEdge(t, cfg, pool)
	s.targetOK = func(a netip.Addr) bool { return a.IsLoopback() }
	s.pm.idle = 300 * time.Millisecond
	lp := port(freeAddr(t))
	_, bp, _ := net.SplitHostPort(back.Addr().String())
	tp, _ := strconv.Atoi(bp)
	s.applyConfig(&apiConfig{Hosts: []apiHost{{ID: 1, Name: "i.test", Mode: 3, UserID: 1,
		Target: &apiTarget{Addrs: []string{"127.0.0.1"}, Port: 80, Scheme: "http"}, Mappings: []apiMapping{{Listen: lp, Transport: "tcp", Port: tp}}}}})
	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(lp), 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	quiet, busy := dial(), dial()
	defer quiet.Close()
	defer busy.Close()
	start := time.Now()
	for time.Since(start) < 900*time.Millisecond {
		if _, err := busy.Write([]byte("x")); err != nil {
			t.Fatalf("active connection cut after %v: %v", time.Since(start), err)
		}
		time.Sleep(60 * time.Millisecond)
	}
	_ = quiet.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := quiet.Read(make([]byte, 1)); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle connection not cut: %v", err)
	}
}
