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

	"github.com/ipv64net/node64/internal/dns64/querylog"
)

func rrA(name, ip string) dns.RR {
	return &dns.A{Hdr: dns.RR_Header{Name: dns.Fqdn(name), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP(ip)}
}

func TestAnswerReason(t *testing.T) {
	msg := func(rrs ...dns.RR) *dns.Msg { return &dns.Msg{Answer: rrs} }
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: "a.lan.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET}, Target: "b.lan."}
	ptr := &dns.PTR{Hdr: dns.RR_Header{Name: "1.0.0.10.in-addr.arpa.", Rrtype: dns.TypePTR, Class: dns.ClassINET}, Ptr: "nas.lan."}
	for _, c := range []struct {
		m     *dns.Msg
		qtype uint16
		want  string
	}{
		{msg(rrA("a.lan", "10.10.78.16")), dns.TypeA, "answer:10.10.78.16"},
		{msg(rrA("a", "10.0.0.1"), rrA("a", "10.0.0.2"), rrA("a", "10.0.0.3"), rrA("a", "10.0.0.4"), rrA("a", "10.0.0.5")), dns.TypeA, "answer:10.0.0.1, 10.0.0.2, 10.0.0.3 +2"},
		{msg(cname, rrA("b.lan", "10.0.0.9")), dns.TypeA, "answer:10.0.0.9"},
		{msg(cname), dns.TypeA, "answer:CNAME b.lan"},
		{msg(), dns.TypeA, "answer:"}, // NODATA
		{msg(ptr), dns.TypePTR, "answer:nas.lan"},
	} {
		if got := answerReason(c.m, c.qtype); got != c.want {
			t.Errorf("%v: %q, want %q", c.m.Answer, got, c.want)
		}
	}
}

type typedRecords map[string]map[uint16][]dns.RR

func (r typedRecords) Lookup(name string, qtype uint16) ([]dns.RR, bool) {
	byType, ok := r[name]
	if !ok {
		return nil, false
	}
	return byType[qtype], true
}

// Eigener Eintrag (#50): das Abfrage-Log zeigt die gelieferte Antwort bzw. NODATA, wenn der Name ohne Eintrag des
// angefragten Typs existiert (PTR statt A angelegt).
func TestAnswerLoggedForCustom(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	st, err := querylog.Open(filepath.Join(t.TempDir(), "q.db"), time.Hour, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go st.Run(ctx) // Schreiber des Abfrage-Logs
	defer st.CloseNow()
	s := &Server{Logger: log, Log: st, Records: typedRecords{
		"nas.lan": {dns.TypeA: {rrA("nas.lan", "10.10.78.16")}},
		"pc.lan":  {dns.TypePTR: nil}, // nur ein (falscher) PTR: A-Anfrage = NODATA
	}}
	s.acl = newClientACL(nil)
	client := netip.MustParseAddr("127.0.0.1")
	for _, n := range []string{"nas.lan", "pc.lan"} {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn(n), dns.TypeA)
		s.Answer(q, client, "udp")
	}
	want := map[string]string{"nas.lan": "answer:10.10.78.16", "pc.lan": "answer:"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, _, err := st.Recent(context.Background(), querylog.LogFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range rows {
			got[r.Domain] = r.Reason
		}
		if len(got) == 2 {
			for d, w := range want {
				if got[d] != w {
					t.Fatalf("%s: reason %q, want %q", d, got[d], w)
				}
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("log rows: %v", got)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
