package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeWhois: TCP-Server, der je Anfrage eine feste Antwort liefert und die Anfragen merkt.
func fakeWhois(t *testing.T, answer func(q string) string) (addr string, got func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var qs []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 512)
				n, _ := c.Read(buf)
				q := strings.TrimSpace(string(buf[:n]))
				mu.Lock()
				qs = append(qs, q)
				mu.Unlock()
				_, _ = io.WriteString(c, answer(q))
			}(c)
		}
	}()
	t.Cleanup(func() { l.Close() })
	return l.Addr().String(), func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), qs...) }
}

// fakeRDAP: Bootstrap (nur TLD "test", Netz 192.0.2.0/24) und Antworten fuer Domains und IPs.
func fakeRDAP(t *testing.T, domains map[string]string) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/boot/dns.json":
			fmt.Fprintf(w, `{"services":[[["test"],["%s/rdap/"]]]}`, srv.URL)
		case r.URL.Path == "/boot/ipv4.json":
			fmt.Fprintf(w, `{"services":[[["192.0.2.0/24"],["%s/rdap/"]]]}`, srv.URL)
		case r.URL.Path == "/boot/ipv6.json", r.URL.Path == "/boot/asn.json":
			_, _ = io.WriteString(w, `{"services":[]}`)
		case strings.HasPrefix(r.URL.Path, "/rdap/domain/"):
			body, ok := domains[strings.TrimPrefix(r.URL.Path, "/rdap/domain/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/rdap+json")
			_, _ = io.WriteString(w, body)
		case r.URL.Path == "/rdap/ip/192.0.2.10":
			_, _ = io.WriteString(w, `{"objectClassName":"ip network","handle":"NET-192-0-2","name":"TEST-NET-1","startAddress":"192.0.2.0","endAddress":"192.0.2.255","country":"DE",
				"cidr0_cidrs":[{"v4prefix":"192.0.2.0","length":24}],
				"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Beispiel GmbH"],["adr",{"label":"Musterweg 1\nBerlin"},"text",["","","Musterweg 1","Berlin","","10115","DE"]]]]},
				            {"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","abuse@example.test"]]]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	old, oldIANA := rdapBootstrapURL, whoisIANA
	rdapBootstrapURL = srv.URL + "/boot/"
	dead, _ := net.Listen("tcp", "127.0.0.1:0") // WHOIS-Ersatz: ohne eigenen Server nie ins Internet
	whoisIANA = dead.Addr().String()
	dead.Close()
	rdapCache.mu.Lock()
	rdapCache.data = nil
	rdapCache.mu.Unlock()
	t.Cleanup(func() {
		rdapBootstrapURL, whoisIANA = old, oldIANA
		rdapCache.mu.Lock()
		rdapCache.data = nil
		rdapCache.mu.Unlock()
	})
}

func rdapDomain(name string, expires time.Time) string {
	return fmt.Sprintf(`{"objectClassName":"domain","ldhName":"%s","status":["active","client transfer prohibited"],
		"events":[{"eventAction":"registration","eventDate":"2010-05-01T10:00:00Z"},{"eventAction":"expiration","eventDate":"%s"}],
		"nameservers":[{"ldhName":"NS2.EXAMPLE.TEST"},{"ldhName":"ns1.example.test"}],
		"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Test Registrar AG"]]]}]}`,
		name, expires.UTC().Format(time.RFC3339))
}

func whoisDef(target string, params any) Definition {
	b, _ := json.Marshal(params)
	return Definition{Type: TypeWhois, Target: target, Params: b, Timeouts: Timeouts{Connect: 2 * time.Second, Total: 5 * time.Second}}
}

func TestWhoisKind(t *testing.T) {
	for in, want := range map[string]string{"example.de": "domain example.de", "https://Bücher.example/x": "domain xn--bcher-kva.example",
		"192.0.2.1": "ip 192.0.2.1", "2001:db8::1/32": "ip 2001:db8::/32", "AS3320": "asn 3320", "as 3320": "", "3320": "asn 3320", "localhost": ""} {
		k, q, err := whoisKind(in)
		got := k + " " + q
		if err != nil {
			got = ""
		}
		if got != want {
			t.Errorf("whoisKind(%q) = %q, want %q", in, got, want)
		}
	}
	if err := Validate(whoisDef("example.de", map[string]any{"source": "ftp"})); err == nil {
		t.Error("bad source accepted")
	}
	if err := Validate(whoisDef("example.de", map[string]any{"min_days": -1})); err == nil {
		t.Error("negative min_days accepted")
	}
	if err := Validate(whoisDef("example.de", map[string]any{"contains": []string{"nameserver: ns1.example.de"}})); err != nil {
		t.Error(err)
	}
}

// RDAP: Angaben in den Details, Ablauf-Schwelle, erwartete Werte, nicht registriert.
func TestWhoisRDAPDomain(t *testing.T) {
	fakeRDAP(t, map[string]string{
		"ok.test":   rdapDomain("ok.test", time.Now().Add(100*24*time.Hour)),
		"soon.test": rdapDomain("soon.test", time.Now().Add(5*24*time.Hour)),
		"gone.test": rdapDomain("gone.test", time.Now().Add(-48*time.Hour)),
	})
	r := testRunner()
	res := r.Run(context.Background(), whoisDef("ok.test", map[string]any{"contains": []string{"nameserver: ns2.example.test", "Registrar AG"}}))
	if len(res) != 1 || res[0].Status != Up {
		t.Fatalf("ok: %+v", res)
	}
	d := res[0].Details
	if d["source"] != "rdap" || d["registrar"] != "Test Registrar AG" || fmt.Sprint(d["nameservers"]) != "[ns1.example.test ns2.example.test]" || d["created"] != "2010-05-01" ||
		!strings.Contains(res[0].Message, "Test Registrar AG") {
		t.Fatalf("details: %+v / %s", d, res[0].Message)
	}
	if res = r.Run(context.Background(), whoisDef("ok.test", map[string]any{"contains": []string{"registrar: Andere"}})); res[0].Reason != ReasonWhoisMismatch {
		t.Fatalf("mismatch: %+v", res[0])
	}
	if res = r.Run(context.Background(), whoisDef("soon.test", map[string]any{})); res[0].Reason != ReasonWhoisExpiring {
		t.Fatalf("expiring: %+v", res[0])
	}
	zero := 0
	if res = r.Run(context.Background(), whoisDef("soon.test", map[string]any{"min_days": zero})); res[0].Status != Up {
		t.Fatalf("min_days 0: %+v", res[0])
	}
	if res = r.Run(context.Background(), whoisDef("gone.test", map[string]any{})); res[0].Reason != ReasonWhoisExpired {
		t.Fatalf("expired: %+v", res[0])
	}
	if res = r.Run(context.Background(), whoisDef("frei.test", map[string]any{})); res[0].Reason != ReasonWhoisNotFound {
		t.Fatalf("not found: %+v", res[0])
	}
}

// RDAP fuer ein Netz: Name, CIDR, Organisation, Stadt, Land, Abuse.
func TestWhoisRDAPNetwork(t *testing.T) {
	fakeRDAP(t, nil)
	res := testRunner().Run(context.Background(), whoisDef("192.0.2.10", map[string]any{"contains": []string{"city: Berlin", "cidr: 192.0.2.0/24", "country: de"}}))
	if len(res) != 1 || res[0].Status != Up {
		t.Fatalf("net: %+v", res)
	}
	d := res[0].Details
	if d["kind"] != "ip" || d["name"] != "TEST-NET-1" || d["org"] != "Beispiel GmbH" || d["city"] != "Berlin" || d["country"] != "DE" || d["abuse"] != "abuse@example.test" ||
		fmt.Sprint(d["cidr"]) != "[192.0.2.0/24]" {
		t.Fatalf("details: %+v", d)
	}
}

// Ohne RDAP-Server (z. B. .de): WHOIS ueber die IANA-Kette, DENIC-Format; "Status: free" = nicht registriert.
func TestWhoisFallbackPort43(t *testing.T) {
	fakeRDAP(t, nil)
	reg, regGot := fakeWhois(t, func(q string) string {
		if strings.Contains(q, "frei.de") {
			return "Domain: frei.de\nStatus: free\n"
		}
		return "% Restricted rights.\nDomain: example.de\nNserver: ns1.ipv64.net\nNserver: ns2.ipv64.net\nStatus: connect\nChanged: 2024-03-01T10:00:00+01:00\n"
	})
	iana, _ := fakeWhois(t, func(q string) string {
		return "% IANA WHOIS server\nrefer:        " + reg + "\n\ndomain:       DE\n"
	})
	old := whoisIANA
	whoisIANA = iana
	t.Cleanup(func() { whoisIANA = old })
	r := testRunner()
	res := r.Run(context.Background(), whoisDef("example.de", map[string]any{"contains": []string{"nameserver: ns2.ipv64.net"}}))
	if len(res) != 1 || res[0].Status != Up {
		t.Fatalf("de: %+v", res)
	}
	d := res[0].Details
	if d["source"] != "whois" || fmt.Sprint(d["nameservers"]) != "[ns1.ipv64.net ns2.ipv64.net]" || fmt.Sprint(d["status"]) != "[connect]" || d["updated"] != "2024-03-01" {
		t.Fatalf("details: %+v", d)
	}
	if res = r.Run(context.Background(), whoisDef("frei.de", map[string]any{})); res[0].Reason != ReasonWhoisNotFound {
		t.Fatalf("free: %+v", res[0])
	}
	if q := regGot(); len(q) == 0 || q[0] != "example.de" {
		t.Fatalf("queries: %v", q)
	}
}

// RIR-Antwort (RIPE-Format) per WHOIS: Netz, Route, Ursprungs-AS, Organisation, Adresse.
func TestWhoisParseRIPE(t *testing.T) {
	i := parseWhoisText(`% This is the RIPE Database query service.
inetnum:        203.0.113.0 - 203.0.113.255
netname:        EXAMPLE-NET
descr:          Example Hosting
country:        DE
org-name:       Example Hosting GmbH
address:        Hauptstr. 5
address:        Nuernberg
abuse-mailbox:  abuse@example.net

route:          203.0.113.0/24
origin:         AS64500
`, "ip")
	if i.Name != "EXAMPLE-NET" || i.Range != "203.0.113.0 - 203.0.113.255" || fmt.Sprint(i.CIDR) != "[203.0.113.0/24]" || i.ASN != "64500" ||
		i.Org != "Example Hosting GmbH" || i.Country != "DE" || i.Address != "Hauptstr. 5, Nuernberg" || i.Abuse != "abuse@example.net" || i.NotFound {
		t.Fatalf("parsed: %+v", i)
	}
	if i.missing([]string{"asn: 64500", "Nuernberg"}) != "" || i.missing([]string{"netname: OTHER"}) == "" {
		t.Fatal("rules")
	}
	g := parseWhoisText("Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar, Inc.\nRegistry Expiry Date: 2031-08-13T04:00:00Z\nName Server: A.IANA-SERVERS.NET\nDomain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited\n", "domain")
	if g.Registrar != "Example Registrar, Inc." || g.Expires.Format("2006-01-02") != "2031-08-13" || fmt.Sprint(g.Nameservers) != "[a.iana-servers.net]" || fmt.Sprint(g.Status) != "[clientDeleteProhibited]" {
		t.Fatalf("gtld: %+v", g)
	}
	if !parseWhoisText("No match for \"NIX.COM\".\n", "domain").NotFound {
		t.Fatal("no match")
	}
}

// Auf den ipv64-Servern (DenyPrivate): RDAP/WHOIS-Server im internen Netz werden nicht erreicht.
func TestWhoisDenyPrivate(t *testing.T) {
	fakeRDAP(t, map[string]string{"ok.test": rdapDomain("ok.test", time.Now().Add(100*24*time.Hour))})
	r := testRunner()
	r.DenyPrivate = true
	res := r.Run(context.Background(), whoisDef("ok.test", map[string]any{}))
	if len(res) != 1 || res[0].Status != Down || !strings.Contains(res[0].Message, "private or reserved") {
		t.Fatalf("deny: %+v", res)
	}
}
