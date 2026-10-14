package dns64

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/ipv64net/node64/internal/dns64/querylog"
)

func logFilter(n int) querylog.LogFilter { return querylog.LogFilter{Limit: n} }

func TestEncryptedServices(t *testing.T) {
	m, port := testModule(t)
	ctx := context.Background()
	c := m.loadConfig(ctx)
	c.DoH, c.DoT, c.DoQ = true, true, true
	c.DoHPort, c.DoTPort = freePort(t), freePort(t)
	c.Names = []string{"dns.home.lan"}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	before := runtime.NumGoroutine()
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	e := m.running()
	if len(e.enc.errs) != 0 || len(e.enc.addrs) != 3 {
		t.Fatalf("encrypted: errs=%v addrs=%v", e.enc.errs, e.enc.addrs)
	}
	// Geraete vertrauen der Heimnetz-CA; der Server-Name muss im Zertifikat stehen
	pemCA, err := os.ReadFile(m.caFile())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCA)
	tlsc := func(alpn string) *tls.Config {
		return &tls.Config{RootCAs: roots, ServerName: "dns.home.lan", NextProtos: []string{alpn}, MinVersion: tls.VersionTLS12}
	}
	query := func() *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("nas.home.lan.", dns.TypeA)
		return q
	}
	check := func(proto string, r *dns.Msg) {
		t.Helper()
		if len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
			t.Fatalf("%s: %v", proto, r)
		}
	}

	// DoT
	dc := &dns.Client{Net: "tcp-tls", TLSConfig: tlsc("dot"), Timeout: 3 * time.Second}
	r, _, err := dc.Exchange(query(), net.JoinHostPort("127.0.0.1", strconv.Itoa(c.DoTPort)))
	if err != nil {
		t.Fatalf("dot: %v", err)
	}
	check("dot", r)

	// DoH (POST und GET)
	hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsc("h2"), ForceAttemptHTTP2: true}}
	defer hc.CloseIdleConnections()
	wire, _ := query().Pack()
	url := "https://127.0.0.1:" + strconv.Itoa(c.DoHPort) + "/dns-query"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(wire))
	req.Host = "dns.home.lan"
	req.Header.Set("Content-Type", "application/dns-message")
	for _, rq := range []*http.Request{req, mustGet(t, url+"?dns="+base64.RawURLEncoding.EncodeToString(wire))} {
		resp, err := hc.Do(rq)
		if err != nil {
			t.Fatalf("doh: %v", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/dns-message" {
			t.Fatalf("doh status %d", resp.StatusCode)
		}
		r := new(dns.Msg)
		if err := r.Unpack(body); err != nil {
			t.Fatal(err)
		}
		check("doh "+rq.Method, r)
	}

	// DoQ
	qc, err := quic.DialAddr(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(c.DoTPort)), tlsc("doq"), nil)
	if err != nil {
		t.Fatalf("doq dial: %v", err)
	}
	s, err := qc.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q := query()
	q.Id = 0
	wire, _ = q.Pack()
	_, _ = s.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(wire))), wire...))
	_ = s.Close()
	var n [2]byte
	if _, err := io.ReadFull(s, n[:]); err != nil {
		t.Fatalf("doq read: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(s, body); err != nil {
		t.Fatal(err)
	}
	r = new(dns.Msg)
	if err := r.Unpack(body); err != nil || r.Id != 0 {
		t.Fatalf("doq answer: %v id=%d", err, r.Id)
	}
	check("doq", r)
	_ = qc.CloseWithError(0, "")

	// Protokoll steht im Abfrage-Log
	time.Sleep(1500 * time.Millisecond) // Log wird jede Sekunde geschrieben
	rows, _, err := e.store.Recent(ctx, logFilter(10))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.Proto] = true
	}
	for _, p := range []string{"dot", "doh", "doq"} {
		if !seen[p] {
			t.Fatalf("proto %s missing in log: %v", p, seen)
		}
	}

	// Stopp: alle Ports frei, keine Goroutinen uebrig
	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := m.Stop(sctx); err != nil {
		t.Fatal(err)
	}
	hc.CloseIdleConnections()
	for _, p := range []int{port, c.DoHPort, c.DoTPort} {
		l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("tcp %d still bound: %v", p, err)
		}
		l.Close()
		pc, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(p)))
		if err != nil {
			t.Fatalf("udp %d still bound: %v", p, err)
		}
		pc.Close()
	}
	for i := 0; i < 100 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if g := runtime.NumGoroutine(); g > before {
		buf := make([]byte, 1<<16)
		t.Fatalf("goroutines: %d before, %d after\n%s", before, g, buf[:runtime.Stack(buf, true)])
	}
}

func mustGet(t *testing.T, url string) *http.Request {
	r, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "dns.home.lan"
	return r
}

func TestMobileconfig(t *testing.T) {
	for _, proto := range []string{"doh", "dot"} {
		out := mobileconfig(proto, "dns.home.lan", "https://dns.home.lan/dns-query", []byte{1, 2, 3})
		d := xml.NewDecoder(strings.NewReader(out))
		d.Strict = true
		d.Entity = xml.HTMLEntity
		for {
			if _, err := d.Token(); err == io.EOF {
				break
			} else if err != nil {
				t.Fatalf("%s: %v", proto, err)
			}
		}
		if !strings.Contains(out, "com.apple.dnsSettings.managed") || !strings.Contains(out, "com.apple.security.root") {
			t.Fatalf("%s: payloads missing", proto)
		}
	}
	if dohURL("192.168.10.30", 443) != "https://192.168.10.30/dns-query" || dohURL("fd00::1", 8443) != "https://[fd00::1]:8443/dns-query" {
		t.Fatal("doh url")
	}
}
