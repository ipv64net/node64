package certs

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// Resolver fuer lego (Anbieter anderer DNS-Dienste): lego bestimmt die Zone eines Namens per SOA und folgt CNAMEs
// ueber seine "rekursiven Nameserver" - ohne Einstellung die des Systems. Hat der lokale Resolver eine eigene Zone
// fuer einen Teil der Domain (Split-DNS: Zone in DNS64, Pi-hole, Router mit eigener Endung), liefert er dort ein SOA,
// lego haelt diesen Teil fuer die Zone und der Anbieter kennt sie nicht (node64#45: *.sub.domain.tld bei Cloudflare,
// "failed to find zone sub.domain.tld"). Darum fragt lego einen kleinen Weiterleiter auf 127.0.0.1, der die
// oeffentlichen Resolver der DNS-01-Pruefung nutzt (eigene zuerst, DoH ueber feste IPs, Port 53) und erst ohne
// Antwort von dort den System-Resolver. Er muss lego's einziger Nameserver sein: lego fragt bei leerer Antwort den
// naechsten (und bekaeme vom lokalen Resolver wieder dessen SOA).

const (
	legoDNSWait   = 7 * time.Second // oeffentliche Resolver (lego wartet 10 s je Anfrage)
	legoDNSSystem = 2 * time.Second // danach je System-Resolver
)

// legoDNS ist der Weiterleiter (ein UDP- und ein TCP-Listener auf demselben Port).
type legoDNS struct {
	paths  func() []checkPath
	system []string // ip:port aus resolv.conf
	srv    []*dns.Server
}

// startLegoDNS startet den Weiterleiter; addr = 127.0.0.1:Port.
func startLegoDNS(paths func() []checkPath, system []string) (*legoDNS, string, error) {
	f := &legoDNS{paths: paths, system: system}
	var lastErr error
	for i := 0; i < 5; i++ { // UDP und TCP brauchen denselben freien Port
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, "", err
		}
		addr := pc.LocalAddr().String()
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			_ = pc.Close()
			lastErr = err
			continue
		}
		u := &dns.Server{PacketConn: pc, Handler: f}
		t := &dns.Server{Listener: ln, Handler: f}
		f.srv = []*dns.Server{u, t}
		go func() { _ = u.ActivateAndServe() }()
		go func() { _ = t.ActivateAndServe() }()
		return f, addr, nil
	}
	return nil, "", lastErr
}

func (f *legoDNS) close() {
	for _, s := range f.srv {
		_ = s.Shutdown()
	}
}

func (f *legoDNS) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), legoDNSWait)
	r := f.public(ctx, q)
	cancel()
	if r == nil {
		r = f.fromSystem(q)
	}
	if r == nil {
		r = new(dns.Msg)
		r.SetRcode(q, dns.RcodeServerFailure)
	}
	r.Id = q.Id
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if o := q.IsEdns0(); o != nil {
			size = int(o.UDPSize())
		}
		r.Truncate(size) // lego fragt dann per TCP
	}
	_ = w.WriteMsg(r)
}

// public: erste Antwort (NOERROR/NXDOMAIN) eines oeffentlichen Resolvers; alle gleichzeitig, nil = keiner.
func (f *legoDNS) public(ctx context.Context, q *dns.Msg) *dns.Msg {
	ps := newPathSet(f.paths())
	if len(ps.paths) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	got := make(chan *dns.Msg, len(ps.paths))
	var wg sync.WaitGroup
	for i := range ps.paths {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r, err := ps.exchange(ctx, i, q.Copy())
			if err != nil {
				r = nil
			}
			got <- r
		}(i)
	}
	var out *dns.Msg
	for range ps.paths {
		if r := <-got; r != nil {
			out = r
			break
		}
	}
	cancel()
	wg.Wait() // erst danach die Verbindungen schliessen
	ps.close()
	return out
}

// fromSystem: wie bisher der Resolver des Systems (kein oeffentlicher erreichbar).
func (f *legoDNS) fromSystem(q *dns.Msg) *dns.Msg {
	c := &dns.Client{Timeout: legoDNSSystem}
	for _, s := range f.system {
		r, _, err := c.Exchange(q.Copy(), s)
		if err == nil && r != nil && r.Truncated {
			tc := &dns.Client{Net: "tcp", Timeout: legoDNSSystem}
			r, _, err = tc.Exchange(q.Copy(), s)
		}
		if err == nil && r != nil {
			return r
		}
	}
	return nil
}

// systemNameservers: Nameserver aus resolv.conf (ip:port), wie lego sie sonst nimmt.
func systemNameservers() []string {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out
}

// useLegoDNS: lego fragt ab jetzt nur den Weiterleiter (einmal je Prozess; Fehler = lego bleibt beim System).
func (m *Manager) useLegoDNS() {
	m.legoOnce.Do(func() {
		_, addr, err := startLegoDNS(func() []checkPath { return m.paths(context.Background()) }, systemNameservers())
		if err != nil {
			m.log.Warn("acme: local resolver for DNS providers not started, using the system resolver", "err", err)
			return
		}
		if err := setLegoNameservers(addr); err != nil {
			m.log.Warn("acme: local resolver for DNS providers not set", "err", err)
		}
	})
}

// setLegoNameservers setzt lego's rekursive Nameserver (global; die Option braucht keine Challenge).
func setLegoNameservers(addrs ...string) error {
	if len(addrs) == 0 {
		return errors.New("no nameserver")
	}
	for _, a := range addrs {
		if _, p, err := net.SplitHostPort(a); err != nil || p == "" {
			return errors.New("bad nameserver " + strconv.Quote(a))
		}
	}
	return dns01.AddRecursiveNameservers(addrs)(nil)
}
