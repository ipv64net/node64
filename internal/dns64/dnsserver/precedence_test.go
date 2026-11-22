package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/ipv64net/node64/internal/dns64/cache"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/querylog"
)

// Rangfolge fuer ein Geraet in einer Gruppe (Forum 5239, so in Oberflaeche und Doku beschrieben): Eine globale
// Freigabe hebt die Blocklisten der Gruppe auf, nicht aber Sperren und Kategorien der Gruppe und nicht den Schutz
// gegen Umgehen (iCloud Private Relay); eine Freigabe der Gruppe geht vor der eigenen Sperrliste.
func TestGroupPrecedenceGlobalAllow(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	kids := filter.List{Name: "kids", URL: "https://block.example/kids.txt"}
	writeList(t, filepath.Join(dir, "lists"), kids.URL, "||kids.example^\n||ads.example^\n")
	a, _ := filter.LoadAllowlist(filepath.Join(dir, "allow.txt"))
	for _, d := range []string{"kids.example", "grpblock.example", "tiktok.com", "mask.icloud.com"} {
		if _, err := a.Add(d); err != nil {
			t.Fatal(err)
		}
	}
	deny, _ := filter.LoadDenylist(filepath.Join(dir, "deny.txt"))
	for _, d := range []string{"school.example", "own.example"} {
		if _, err := deny.Add(d); err != nil {
			t.Fatal(err)
		}
	}
	fm, err := filter.NewManager(filepath.Join(dir, "lists"), []filter.List{kids}, 0, a, nil, log)
	if err != nil {
		t.Fatal(err)
	}
	fm.Deny = deny
	fm.SetGlobal(0) // Geraete ohne Gruppe: keine Blockliste
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
	p := &Policy{Group: "Kinder", Mask: fm.Mask([]string{kids.URL}), Allow: filter.NewDomainSet([]string{"school.example"}),
		Block: filter.NewDomainSet([]string{"grpblock.example"}), Cats: []Category{{Key: "social", Set: filter.GroupCategory("social")}}, Bypass: true}
	child := netip.MustParseAddr("127.0.0.2")
	s.Policy = func(ip netip.Addr) *Policy {
		if ip == child {
			return p
		}
		return nil
	}

	names := []string{"kids.example", "ads.example", "grpblock.example", "tiktok.com", "mask.icloud.com", "school.example", "own.example"}
	for _, n := range names { // Antworten aus dem Cache statt vom Upstream
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(n), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.ParseIP("192.0.2.7")}}
		s.Cache.Set(q, resp)
	}
	answer := func(n string, client netip.Addr) string {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		for _, rr := range s.Answer(q, client, "udp").Answer {
			if x, ok := rr.(*dns.A); ok {
				return x.A.String()
			}
		}
		return ""
	}
	for n, want := range map[string]string{
		"kids.example":     "192.0.2.7", // Blockliste der Gruppe, global freigegeben: frei
		"ads.example":      "0.0.0.0",   // Blockliste der Gruppe
		"grpblock.example": "0.0.0.0",   // Sperre der Gruppe schlaegt die globale Freigabe
		"tiktok.com":       "0.0.0.0",   // Kategorie der Gruppe schlaegt die globale Freigabe
		"mask.icloud.com":  "",          // Schutz gegen Umgehen: NXDOMAIN trotz Freigabe
		"school.example":   "192.0.2.7", // Freigabe der Gruppe schlaegt die eigene Sperrliste
		"own.example":      "0.0.0.0",   // eigene Sperrliste gilt auch in der Gruppe
	} {
		if got := answer(n, child); got != want {
			t.Errorf("group %s: %q, want %q", n, got, want)
		}
	}
	// ohne Gruppe: keine Blockliste, die eigene Sperrliste gilt
	if got := answer("ads.example", netip.MustParseAddr("127.0.0.1")); got != "192.0.2.7" {
		t.Errorf("no group ads.example: %q", got)
	}
	if got := answer("school.example", netip.MustParseAddr("127.0.0.1")); got != "0.0.0.0" {
		t.Errorf("no group school.example: %q", got)
	}
}
