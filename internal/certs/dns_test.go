package certs

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Ist ein Nameserver nur ueber eine Familie erreichbar (z. B. IPv6-only-Anschluss), gilt der TXT-Record trotzdem
// als sichtbar: die nicht erreichbare IPv4-Adresse haelt die Pruefung nicht auf.
func TestWaitTXTEitherFamily(t *testing.T) {
	pc, err := net.ListenPacket("udp", "[::1]:0")
	if err != nil {
		t.Skip("no IPv6 loopback:", err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"token"}})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()

	dead, _ := net.ListenPacket("udp", "127.0.0.1:0") // IPv4-Adresse ohne DNS-Dienst
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	old := lookupNS
	defer func() { lookupNS = old }()
	lookupNS = func(context.Context, string) ([]nameserver, error) {
		return []nameserver{{Name: "ns1.test", Addrs: []string{deadAddr, pc.LocalAddr().String()}}}, nil
	}
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatal(err)
	}
}

// testNS: Nameserver auf 127.0.0.1 (UDP und TCP auf demselben Port), Antwort je Transport frei waehlbar.
func testNS(t *testing.T, udp, tcp dns.HandlerFunc) string {
	t.Helper()
	var l net.Listener
	var pc net.PacketConn
	for i := 0; i < 20; i++ { // freien Port finden, der fuer beide Transporte frei ist
		var err error
		if l, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if pc, err = net.ListenPacket("udp", l.Addr().String()); err == nil {
			break
		}
		l.Close()
		l = nil
	}
	if l == nil {
		t.Skip("no port free for udp and tcp")
	}
	su := &dns.Server{PacketConn: pc, Handler: udp}
	st := &dns.Server{Listener: l, Handler: tcp}
	go func() { _ = su.ActivateAndServe() }()
	go func() { _ = st.ActivateAndServe() }()
	t.Cleanup(func() { _ = su.Shutdown(); _ = st.Shutdown() })
	return l.Addr().String()
}

// answer: Antwort mit TXT-Wert (leer = NXDOMAIN), aa = zustaendig.
func answer(aa bool, val string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = aa
		if val == "" {
			m.Rcode = dns.RcodeNameError
		} else {
			m.Answer = append(m.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{val}})
		}
		_ = w.WriteMsg(m)
	}
}

func fastTXT(t *testing.T, ns []nameserver, wait time.Duration) {
	oldNS, oldWait, oldEvery, oldPub := lookupNS, waitDNS, txtEvery, publicCheck
	t.Cleanup(func() { lookupNS, waitDNS, txtEvery, publicCheck = oldNS, oldWait, oldEvery, oldPub })
	lookupNS = func(context.Context, string) ([]nameserver, error) { return ns, nil }
	waitDNS, txtEvery = wait, 10*time.Millisecond
	publicCheck = func(context.Context, string, string) (bool, error) { return false, nil }
}

// Leitet das Netz UDP 53 auf einen eigenen Resolver um (Antwort ohne AA), fragt die Pruefung per TCP nach.
func TestWaitTXTTCPFallback(t *testing.T) {
	addr := testNS(t, answer(false, ""), answer(true, "token"))
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, time.Second)
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatal(err)
	}
}

// Kein Nameserver direkt erreichbar (Port 53 umgeleitet): oeffentliche Resolver ueber DoH entscheiden; zeigen auch
// die nichts, nennt der Fehler den Grund.
func TestWaitTXTRedirectedUsesPublic(t *testing.T) {
	addr := testNS(t, answer(false, ""), answer(false, ""))
	ns := []nameserver{{Name: "ns1.test", Addrs: []string{addr}}, {Name: "ns2.test", Addrs: []string{addr}}}
	fastTXT(t, ns, 5*time.Second)
	asked := 0
	publicCheck = func(_ context.Context, fqdn, want string) (bool, error) {
		asked++
		return fqdn == "_acme-challenge.example.org" && want == "token", nil
	}
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil || asked == 0 {
		t.Fatalf("public check: %v (asked %d)", err, asked)
	}
	fastTXT(t, ns, 200*time.Millisecond)
	err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token")
	if err == nil || !strings.Contains(err.Error(), "port 53 blocked or redirected") || !strings.Contains(err.Error(), "ns2.test: answer not authoritative") {
		t.Fatalf("error: %v", err)
	}
}

// Antworten die Nameserver zustaendig, aber ohne den Wert, nennt der Fehler je Nameserver den Stand; oeffentliche
// Resolver werden dann nicht gefragt (die Nameserver sind ja erreichbar).
func TestWaitTXTMissingDetail(t *testing.T) {
	addr := testNS(t, answer(true, ""), answer(true, ""))
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, 200*time.Millisecond)
	publicCheck = func(context.Context, string, string) (bool, error) {
		t.Error("public resolvers asked")
		return true, nil
	}
	err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token")
	if err == nil || !strings.Contains(err.Error(), "ns1.test: record not there yet (NXDOMAIN)") || strings.Contains(err.Error(), "port 53") {
		t.Fatalf("error: %v", err)
	}
}
