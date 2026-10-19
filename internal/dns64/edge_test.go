package dns64

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/edge"
)

type noCerts struct{}

func (noCerts) ForName(string) *tls.Certificate { return nil }
func (noCerts) ByID(int64) *tls.Certificate     { return nil }

// DoH auf dem HTTPS-Port des Eingangs: kein eigener Listener, Antwort ueber den Eingang auf den DNS64-Namen und
// per IP (Fallback), andere Pfade 404, kein Port-Claim fuer DoH; nach dem Stopp ist der Port wieder frei.
func TestDoHViaEdge(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	hp := freePort(t)
	e, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPSPort: hp, Default: edge.DefaultNotFound}, noCerts{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	m.SetEdge(e)
	c := m.loadConfig(ctx)
	c.DoH, c.DoHPort, c.Names = true, hp, []string{"dns.home.lan"}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := m.AddRecord(ctx, Record{Name: "nas.home.lan", Type: "A", Value: "192.168.1.10"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	if x := m.running().enc; x.release == nil || x.doh != nil || x.errs["doh"] != "" {
		t.Fatalf("doh not on the entrance: ingress=%v own=%v err=%q", x.release != nil, x.doh != nil, x.errs["doh"])
	}
	for _, cl := range m.Ports(ctx, true) {
		if cl.Purpose == "DoH" {
			t.Fatal("DoH claim must be left to the entrance")
		}
	}
	waitHTTPS(t, e, true)

	pemCA, err := os.ReadFile(m.caFile())
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pemCA)
	q := new(dns.Msg)
	q.SetQuestion("nas.home.lan.", dns.TypeA)
	wire, _ := q.Pack()
	url := "https://127.0.0.1:" + strconv.Itoa(hp)
	do := func(tc *tls.Config, path string) (int, []byte) {
		t.Helper()
		hc := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}}
		defer hc.CloseIdleConnections()
		req, _ := http.NewRequest(http.MethodPost, url+path, bytes.NewReader(wire))
		req.Header.Set("Content-Type", "application/dns-message")
		if tc.ServerName != "" {
			req.Host = tc.ServerName // wie https://dns.home.lan/dns-query
		}
		resp, err := hc.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}
	answer := func(how string, code int, body []byte) {
		t.Helper()
		r := new(dns.Msg)
		if code != 200 || r.Unpack(body) != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
			t.Fatalf("%s: status %d answer %v", how, code, r)
		}
	}
	// per Name (SNI), Zertifikat der Heimnetz-CA
	code, body := do(&tls.Config{RootCAs: roots, ServerName: "dns.home.lan", MinVersion: tls.VersionTLS12}, "/dns-query")
	answer("by name", code, body)
	// per IP (ohne SNI): Fallback-Route, ebenfalls das DNS64-Zertifikat
	ipConf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, //nolint:gosec // geprueft wird unten die CA
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool()})
			return err
		}}
	code, body = do(ipConf, "/dns-query")
	answer("by ip", code, body)
	if code, _ := do(ipConf, "/"); code != http.StatusNotFound {
		t.Fatalf("other path: status %d, want 404", code)
	}

	sctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := m.Stop(sctx); err != nil {
		t.Fatal(err)
	}
	waitHTTPS(t, e, false)
	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(hp)))
	if err != nil {
		t.Fatalf("https port still bound: %v", err)
	}
	l.Close()
}

// Ein Name, der schon einem anderen Abnehmer gehoert, faellt fuer DoH weg; der Rest bleibt angemeldet.
func TestDoHEdgeNameTaken(t *testing.T) {
	m, _ := testModule(t)
	ctx := context.Background()
	hp := freePort(t)
	e, err := edge.New(edge.Config{Bind: "127.0.0.1", HTTPSPort: hp, Default: edge.DefaultNotFound}, noCerts{}, nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close(ctx)
	if err := e.Set("cdn64", []edge.Route{{Names: []string{"dns.home.lan"}, Handler: http.NotFoundHandler()}}); err != nil {
		t.Fatal(err)
	}
	m.SetEdge(e)
	c := m.loadConfig(ctx)
	c.DoH, c.DoHPort, c.Names = true, hp, []string{"dns.home.lan", "doh.home.lan"}
	if err := m.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil || m.running() == nil {
		t.Fatalf("start: %v %s", err, m.startError())
	}
	if x := m.running().enc; x.release == nil || x.errs["doh"] != "" {
		t.Fatalf("doh not registered: %q", x.errs["doh"])
	}
	owner := map[string]string{}
	for _, n := range e.Status().Names {
		owner[n.Name] = n.Owner
	}
	if owner["dns.home.lan"] != "cdn64" || owner["doh.home.lan"] != Name {
		t.Fatalf("names = %v", owner)
	}
}

func waitHTTPS(t *testing.T, e *edge.Edge, running bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		for _, l := range e.Status().Listeners {
			if l.Name == "https" && l.Running == running {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("https listener running=%v not reached: %+v", running, e.Status().Listeners)
}
