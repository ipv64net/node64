package dnsserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/cache"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// writeList legt die zwischengespeicherte Datei einer Liste an (Name wie filter.fileFor).
func writeList(t *testing.T, dir, url, body string) {
	t.Helper()
	h := sha256.Sum256([]byte(url))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "list-"+hex.EncodeToString(h[:6])+".txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Eine Domain aus einer Freigabe-Liste wird nicht ueber ein gesperrtes CNAME-Ziel gesperrt (wie eigene
// Freigaben); ohne Freigabe greift die CNAME-Pruefung weiter.
func TestReleaseListSkipsCNAMECheck(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	block := filter.List{Name: "ads", URL: "https://block.example/ads.txt"}
	allow := filter.List{Name: "ok", URL: "https://allow.example/ok.txt"}
	writeList(t, filepath.Join(dir, "lists"), block.URL, "||tracker.example^\n")
	writeList(t, filepath.Join(dir, "allow"), allow.URL, "shop.example\n")
	a, _ := filter.LoadAllowlist(filepath.Join(dir, "allow.txt"))
	fm, err := filter.NewManager(filepath.Join(dir, "lists"), []filter.List{block}, 0, a, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	if fm.Release, err = filter.NewReleaseManager(filepath.Join(dir, "allow"), []filter.List{allow}, 0, nil, log); err != nil {
		t.Fatal(err)
	}
	st, err := querylog.Open(filepath.Join(dir, "q.db"), time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx)
	defer st.CloseNow()
	s := &Server{Logger: log, Log: st, Filter: fm, Cache: cache.New(100)}
	s.acl = newClientACL(nil)

	// zwischengespeicherte Antworten: Name CNAME auf ein gesperrtes Ziel
	for _, n := range []string{"shop.example", "other.example"} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{
			&dns.CNAME{Hdr: dns.RR_Header{Name: dns.Fqdn(n), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "cdn.tracker.example."},
			&dns.A{Hdr: dns.RR_Header{Name: "cdn.tracker.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.7")},
		}
		s.Cache.Set(q, resp)
	}
	client := netip.MustParseAddr("127.0.0.1")
	answer := func(n string) string {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		resp := s.Answer(q, client, "udp")
		for _, rr := range resp.Answer {
			if x, ok := rr.(*dns.A); ok {
				return x.A.String()
			}
		}
		return ""
	}
	if got := answer("shop.example"); got != "192.0.2.7" {
		t.Fatalf("released name blocked via CNAME: %q", got)
	}
	if got := answer("other.example"); got == "192.0.2.7" {
		t.Fatal("CNAME cloaking not blocked")
	}
}
