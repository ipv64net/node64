package upstream

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// testCert erzeugt ein selbstsigniertes Zertifikat fuer name und traegt es als Wurzel ein.
func testCert(t *testing.T, name string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	if testRoots == nil {
		testRoots = x509.NewCertPool()
	}
	testRoots.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// answer beantwortet jede A-Frage mit 192.0.2.<n>.
func answer(r *dns.Msg, n byte) *dns.Msg {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, n)}}
	return m
}

func ask(t *testing.T, r *Resolver) (string, string) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.Id = 4711
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, up, err := r.Exchange(ctx, q)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Id != 4711 || len(resp.Answer) != 1 {
		t.Fatalf("answer = %v", resp)
	}
	return resp.Answer[0].(*dns.A).A.String(), up
}

func TestDoT(t *testing.T) {
	cert := testCert(t, "dot.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{Listener: ln, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) { _ = w.WriteMsg(answer(r, 1)) })}
	go func() { _ = srv.ActivateAndServe() }()
	defer srv.Shutdown()
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	r := New([]Server{{Name: "DoT", URL: "tls://dot.test:" + port, IPs: []string{"127.0.0.1"}}}, ModeParallel)
	defer r.Close()
	for i := 0; i < 3; i++ { // dieselbe Verbindung wird wiederverwendet
		if ip, up := ask(t, r); ip != "192.0.2.1" || up != "DoT" {
			t.Fatalf("got %s from %s", ip, up)
		}
	}
	d := r.ups[0].ex.(*dot)
	if len(d.idle) != 1 {
		t.Fatalf("idle connections = %d, want 1 (reuse)", len(d.idle))
	}
	// falscher Name im Zertifikat: abgelehnt
	bad := New([]Server{{Name: "bad", URL: "tls://other.test:" + port, IPs: []string{"127.0.0.1"}}}, ModeParallel)
	defer bad.Close()
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	if _, _, err := bad.Exchange(context.Background(), q); err == nil {
		t.Fatal("certificate for another name accepted")
	}
}

func TestDoQ(t *testing.T) {
	cert := testCert(t, "doq.test")
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"doq"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			go func() {
				for {
					s, err := c.AcceptStream(context.Background())
					if err != nil {
						return
					}
					var n [2]byte
					if _, err := io.ReadFull(s, n[:]); err != nil {
						return
					}
					body := make([]byte, binary.BigEndian.Uint16(n[:]))
					if _, err := io.ReadFull(s, body); err != nil {
						return
					}
					q := new(dns.Msg)
					if q.Unpack(body) != nil || q.Id != 0 { // RFC 9250: ID 0
						s.CancelWrite(1)
						continue
					}
					out, _ := answer(q, 2).Pack()
					binary.BigEndian.PutUint16(n[:], uint16(len(out)))
					_, _ = s.Write(append(n[:], out...))
					_ = s.Close()
				}
			}()
		}
	}()
	port := strconv.Itoa(ln.Addr().(*net.UDPAddr).Port)
	r := New([]Server{{Name: "DoQ", URL: "quic://doq.test:" + port, IPs: []string{"127.0.0.1"}}}, ModeParallel)
	defer r.Close()
	for i := 0; i < 3; i++ {
		if ip, up := ask(t, r); ip != "192.0.2.2" || up != "DoQ" {
			t.Fatalf("got %s from %s", ip, up)
		}
	}
	if st := r.Stats(); st[0].Proto != "doq" || st[0].Requests != 3 || st[0].Errors != 0 {
		t.Fatalf("stats = %+v", st[0])
	}
}

func TestDoHAndOrdered(t *testing.T) {
	cert := testCert(t, "doh.test")
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if q.Unpack(body) != nil {
			http.Error(w, "bad", 400)
			return
		}
		out, _ := answer(q, 3).Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(out)
	})
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	// der Reihe nach: der erste Server ist nicht erreichbar, der zweite antwortet
	r := New([]Server{
		{Name: "down", URL: "tls://down.test:1", IPs: []string{"127.0.0.1"}},
		{Name: "DoH", URL: "https://doh.test:" + port + "/dns-query", IPs: []string{"127.0.0.1"}},
	}, ModeOrdered)
	defer r.Close()
	if ip, up := ask(t, r); ip != "192.0.2.3" || up != "DoH" {
		t.Fatalf("got %s from %s", ip, up)
	}
	if st := r.Stats(); st[0].Errors != 1 || st[1].Wins != 1 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestProto(t *testing.T) {
	for in, want := range map[string]string{"https://dns.google/dns-query": "doh", "tls://dns.quad9.net": "dot", "quic://dns.adguard-dns.com:853": "doq", "udp://1.1.1.1": "", "tls://": ""} {
		if got := Proto(in); got != want {
			t.Errorf("Proto(%q) = %q, want %q", in, got, want)
		}
	}
}
