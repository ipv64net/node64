package certs

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
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

// Sperrt der System-Resolver die Nameserver (DNS-Filter antwortet 0.0.0.0) oder antwortet gar nicht, kommen die
// Nameserver ueber oeffentliche Resolver.
func TestLookupNSFallsBackWhenBlocked(t *testing.T) {
	fake := func(ip string, nsErr error) nsLookup {
		return nsLookup{
			cname: func(context.Context, string) string { return "" },
			ns: func(_ context.Context, name string) ([]string, error) {
				if name != "example.org" {
					return nil, nil
				}
				return []string{"ns1.example.net."}, nsErr
			},
			ip: func(_ context.Context, fam, _ string) []netip.Addr {
				if fam == "ip6" {
					return nil
				}
				return []netip.Addr{netip.MustParseAddr(ip)}
			},
		}
	}
	oldSys, oldPub := systemNS, publicNS
	t.Cleanup(func() { systemNS, publicNS = oldSys, oldPub })
	systemNS, publicNS = fake("0.0.0.0", nil), fake("203.0.113.53", nil)
	ns, err := lookupNS(context.Background(), "_acme-challenge.example.org")
	if err != nil || len(ns) != 1 || ns[0].Addrs[0] != "203.0.113.53:53" {
		t.Fatalf("fallback: %v %v", ns, err)
	}
	publicNS = fake("::", nil)
	if _, err := lookupNS(context.Background(), "example.org"); err == nil || !strings.Contains(err.Error(), "blocked or missing") {
		t.Fatalf("blocked everywhere: %v", err)
	}
}

// Die oeffentliche Pruefung fragt alle Resolver: ein gesperrter (keine Antwort) haelt sie nicht auf; sind alle
// unerreichbar, nennt der Fehler jeden.
func TestPublicTXTSkipsUnreachable(t *testing.T) {
	dead, _ := net.ListenPacket("udp", "127.0.0.1:0")
	deadAddr := dead.LocalAddr().String()
	dead.Close()
	good := testNS(t, answer(false, "token"), answer(false, "token"))
	ps := newPathSet([]checkPath{{Name: "blocked", plain: deadAddr}, {Name: "good", plain: good}})
	defer ps.close()
	ctx := withPaths(context.Background(), ps)
	if ok, err := publicTXT(ctx, "_acme-challenge.example.org", "token"); !ok || err != nil {
		t.Fatalf("found: %v %v", ok, err)
	}
	if ok, err := publicTXT(ctx, "_acme-challenge.example.org", "other"); ok || err != nil {
		t.Fatalf("missing: %v %v", ok, err)
	}
	ps2 := newPathSet([]checkPath{{Name: "blocked1", plain: deadAddr}, {Name: "blocked2", plain: deadAddr}})
	defer ps2.close()
	_, err := publicTXT(withPaths(context.Background(), ps2), "x.example.org", "token")
	if err == nil || !strings.Contains(err.Error(), "blocked1: ") || !strings.Contains(err.Error(), "blocked2: ") {
		t.Fatalf("unreachable: %v", err)
	}
}

// Kein Nameserver direkt und kein oeffentlicher Resolver erreichbar: die Meldung sagt das (statt nur „TXT fehlt“).
func TestWaitTXTNoPathMessage(t *testing.T) {
	addr := testNS(t, answer(false, ""), answer(false, ""))
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, 200*time.Millisecond)
	publicCheck = func(context.Context, string, string) (bool, error) {
		return false, errors.New("Cloudflare (DoH): timeout")
	}
	err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token")
	if err == nil || !strings.Contains(err.Error(), "no public resolver reachable either (Cloudflare (DoH): timeout)") {
		t.Fatalf("error: %v", err)
	}
}

func TestParseCheckResolvers(t *testing.T) {
	got, err := ParseCheckResolvers("192.168.1.1\n[2001:db8::1]:5353, https://dns.quad9.net/dns-query\n\n tls://dns.example ")
	if err != nil || strings.Join(got, "|") != "192.168.1.1:53|[2001:db8::1]:5353|https://dns.quad9.net/dns-query|tls://dns.example" {
		t.Fatalf("%q %v", got, err)
	}
	if p, _ := parsePath("https://dns.quad9.net/dns-query"); len(p.srv.IPs) == 0 {
		t.Fatal("preset IPs not taken over")
	}
	for _, bad := range []string{"dns.example", "http://x", "1.2.3.4:99999"} {
		if _, err := ParseCheckResolvers(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// Liefert ein Nameserver-Verbund kurz nach dem Anlegen abwechselnd neu und leer (Cache vor mehreren Backends), gilt
// der Wert erst als sichtbar, wenn er mehrere Runden hintereinander ueberall da ist (Test 2026-10-29: Let's Encrypt
// fand sonst „No TXT record“ bzw. den alten Wert).
func TestWaitTXTFlapping(t *testing.T) {
	var mu sync.Mutex
	n := 0
	flap := func(w dns.ResponseWriter, r *dns.Msg) { // die ersten 6 Antworten wechseln, danach immer der Wert
		mu.Lock()
		n++
		val := "token"
		if n <= 6 && n%2 == 0 {
			val = ""
		}
		mu.Unlock()
		answer(true, val)(w, r)
	}
	addr := testNS(t, flap, flap)
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, 2*time.Second)
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n < 6+stableRounds {
		t.Fatalf("returned after %d answers while the record was still flapping", n)
	}
}

// Ohne zustaendige Antwort (Port 53 umgeleitet) muessen auch die oeffentlichen Resolver mehrere Runden hintereinander
// den Wert liefern; ein einzelner Treffer genuegt nicht (Review 2026-10-29).
func TestWaitTXTPublicStable(t *testing.T) {
	addr := testNS(t, answer(false, ""), answer(false, "")) // umgeleitet: nie zustaendig
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, 2*time.Second)
	seq := []bool{true, false, true, true, true}
	calls := 0
	publicCheck = func(context.Context, string, string) (bool, error) {
		calls++
		if calls > len(seq) {
			return true, nil
		}
		return seq[calls-1], nil
	}
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatal(err)
	}
	if calls != len(seq) {
		t.Fatalf("public check must need %d stable rounds, returned after %d calls", stableRounds, calls)
	}
}

// Laeuft bei Fristablauf gerade eine stabile Folge, wird sie zu Ende geprueft statt mit „0 of N“ abzubrechen.
func TestWaitTXTDeadlineFinishesStableRun(t *testing.T) {
	addr := testNS(t, answer(true, "token"), answer(true, "token"))
	fastTXT(t, []nameserver{{Name: "ns1.test", Addrs: []string{addr}}}, time.Millisecond)
	if err := waitTXT(context.Background(), "example.org", "_acme-challenge.example.org", "token"); err != nil {
		t.Fatalf("stable run at the deadline must finish: %v", err)
	}
}
