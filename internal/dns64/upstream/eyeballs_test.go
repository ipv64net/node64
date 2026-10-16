package upstream

import (
	"crypto/tls"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestInterleave(t *testing.T) {
	in := []string{"1.1.1.1:853", "1.0.0.1:853", "[2606:4700::1111]:853", "[2606:4700::1001]:853"}
	if got := interleave(in, 0); !slices.Equal(got, []string{"[2606:4700::1111]:853", "1.1.1.1:853", "[2606:4700::1001]:853", "1.0.0.1:853"}) {
		t.Fatalf("v6 first: %v", got)
	}
	if got := interleave(in, 4); !slices.Equal(got, []string{"1.1.1.1:853", "[2606:4700::1111]:853", "1.0.0.1:853", "[2606:4700::1001]:853"}) {
		t.Fatalf("v4 first: %v", got)
	}
	if got := interleave([]string{"dns.example:853"}, 0); !slices.Equal(got, []string{"dns.example:853"}) {
		t.Fatalf("name: %v", got)
	}
}

// Haengt die IPv6-Adresse (Verbindung kommt zustande, TLS antwortet nie), antwortet DoT nach 250 ms ueber IPv4
// statt nach einem Timeout; danach wird IPv4 zuerst versucht.
func TestHappyEyeballsDoT(t *testing.T) {
	cert := testCert(t, "dot.test")
	ln4, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln4.Addr().(*net.TCPAddr).Port)
	hang, err := net.Listen("tcp", net.JoinHostPort("::1", port))
	if err != nil {
		t.Skip("no IPv6 loopback: ", err)
	}
	defer hang.Close()
	go func() { // nimmt an, schweigt
		for {
			c, err := hang.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	srv := &dns.Server{Listener: ln4, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(answer(r, 6)) })}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	r := New([]Server{{Name: "DoT", URL: "tls://dot.test:" + port, IPs: []string{"::1", "127.0.0.1"}}}, ModeParallel)
	defer r.Close()
	start := time.Now()
	if ip, _ := ask(t, r); ip != "192.0.2.6" {
		t.Fatalf("answer %s", ip)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("took %v, want about 250 ms", d)
	}
	if p := r.ups[0].ex.(*dot).pref.Load(); p != 4 {
		t.Fatalf("preferred family %d, want 4", p)
	}
}
