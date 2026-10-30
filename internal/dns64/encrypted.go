package dns64

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
)

// Verschluesselte Anfragen der Geraete im Heimnetz: DoH (RFC 8484, eigener HTTPS-Port), DoT (RFC 7858, 853/TCP)
// und DoQ (RFC 9250, 853/UDP). Jeder Dienst startet fuer sich; scheitert einer (Port belegt), laufen die
// anderen und das normale DNS weiter, der Fehler steht auf der Seite. Es gelten dieselben Client-Netze wie
// fuer DNS auf Port 53.

const maxDoHBody = 65535

// encrypted haelt die laufenden verschluesselten Dienste.
type encrypted struct {
	names    []string          // Namen und IPs im Zertifikat
	notAfter time.Time         // Ablauf des Zertifikats
	errs     map[string]string // doh/dot/doq -> Fehler beim Start
	addrs    map[string]string // doh/dot/doq -> Adresse

	dot     *dns.Server
	doh     *http.Server
	release func() // DoH beim gemeinsamen Eingang abmelden (nil = nicht angemeldet)
	doq     *quic.Listener
	mu      sync.Mutex
	qcon    map[*quic.Conn]struct{}
	wg      sync.WaitGroup
}

// startEncrypted startet die eingeschalteten Dienste (nie fatal fuer das Modul).
func (m *Module) startEncrypted(c config, srv *dnsserver.Server) *encrypted {
	x := &encrypted{errs: map[string]string{}, addrs: map[string]string{}, qcon: map[*quic.Conn]struct{}{}}
	if !c.DoH && !c.DoT && !c.DoQ {
		return x
	}
	crt, names, err := m.serverCert(c)
	if err != nil {
		for _, p := range []string{"doh", "dot", "doq"} {
			x.errs[p] = "certificate: " + err.Error()
		}
		m.log.Error("dns64 certificate", "err", err)
		return x
	}
	x.names = names
	m.cur.Store(&crt)
	if leaf, err := x509.ParseCertificate(crt.Certificate[0]); err == nil {
		x.notAfter = leaf.NotAfter
	}
	// das Zertifikat kommt bei jeder Verbindung aus m.cur: ein neues (Let's Encrypt) gilt sofort
	base := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.cur.Load(), nil }}
	if c.DoT {
		addr := net.JoinHostPort(c.Bind, strconv.Itoa(c.DoTPort))
		cfg := base.Clone()
		cfg.NextProtos = []string{"dot"}
		if ln, err := tls.Listen("tcp", addr, cfg); err != nil {
			x.errs["dot"] = err.Error()
		} else {
			x.addrs["dot"] = addr
			x.dot = &dns.Server{Listener: ln, Net: "tcp-tls", Handler: srv.Handler("dot"), IdleTimeout: func() time.Duration { return 30 * time.Second }}
			dnsserver.Serve(x.dot, &x.wg, nil)
		}
	}
	if c.DoQ {
		addr := net.JoinHostPort(c.Bind, strconv.Itoa(c.DoTPort))
		cfg := base.Clone()
		cfg.MinVersion, cfg.NextProtos = tls.VersionTLS13, []string{"doq"}
		if ln, err := quic.ListenAddr(addr, cfg, &quic.Config{MaxIdleTimeout: 30 * time.Second, MaxIncomingStreams: 256}); err != nil {
			x.errs["doq"] = err.Error()
		} else {
			x.addrs["doq"] = addr
			x.doq = ln
			x.wg.Add(1)
			go func() { defer x.wg.Done(); x.serveDoQ(srv) }()
		}
	}
	if m.dohViaEdge(c) {
		if err := m.startDoHEdge(x, names, srv); err != nil {
			x.errs["doh"] = err.Error()
		} else {
			x.addrs["doh"] = net.JoinHostPort(m.ingress.Config().Bind, strconv.Itoa(c.DoHPort))
		}
	} else if c.DoH {
		addr := net.JoinHostPort(c.Bind, strconv.Itoa(c.DoHPort))
		cfg := base.Clone()
		cfg.NextProtos = []string{"h2", "http/1.1"}
		if ln, err := tls.Listen("tcp", addr, cfg); err != nil {
			x.errs["doh"] = err.Error()
		} else {
			x.addrs["doh"] = addr
			mux := http.NewServeMux()
			mux.Handle("/dns-query", dohHandler(srv))
			x.doh = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 2 * time.Minute, TLSConfig: cfg,
				ErrorLog: log.New(io.Discard, "", 0)} // TLS-Fehler von Geraeten ohne Vertrauen in die CA nicht ins Log
			x.wg.Add(1)
			go func() { defer x.wg.Done(); _ = x.doh.Serve(ln) }()
		}
	}
	for p, e := range x.errs {
		m.log.Warn("dns64 encrypted service not started", "proto", p, "err", e)
	}
	if len(x.addrs) > 0 {
		m.log.Info("dns64 encrypted services", "listen", x.addrs)
	}
	return x
}

func (x *encrypted) stop(ctx context.Context) {
	if x.dot != nil {
		_ = x.dot.ShutdownContext(ctx)
	}
	if x.doh != nil {
		_ = x.doh.Shutdown(ctx)
	}
	if x.release != nil {
		x.release()
	}
	if x.doq != nil {
		_ = x.doq.Close()
		x.mu.Lock()
		for c := range x.qcon {
			_ = c.CloseWithError(0, "")
		}
		x.mu.Unlock()
	}
	done := make(chan struct{})
	go func() { x.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func clientAddr(a net.Addr) netip.Addr {
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap().WithZone("") // ohne Zone (fe80::1%eth0), sonst greifen Gruppenregeln nicht
	}
	return netip.Addr{}
}

// serveDoQ nimmt QUIC-Verbindungen an; je Stream eine Anfrage (RFC 9250).
func (x *encrypted) serveDoQ(srv *dnsserver.Server) {
	for {
		c, err := x.doq.Accept(context.Background())
		if err != nil {
			return
		}
		ip := clientAddr(c.RemoteAddr())
		if !srv.Allowed(ip) {
			_ = c.CloseWithError(0, "refused") // nicht erlaubtes Netz: Verbindung gleich wieder zu
			continue
		}
		x.mu.Lock()
		x.qcon[c] = struct{}{}
		x.mu.Unlock()
		x.wg.Add(1)
		go func() {
			defer x.wg.Done()
			defer func() { x.mu.Lock(); delete(x.qcon, c); x.mu.Unlock() }()
			for {
				s, err := c.AcceptStream(context.Background())
				if err != nil {
					return
				}
				x.wg.Add(1)
				go func() { defer x.wg.Done(); doqStream(s, srv, ip) }()
			}
		}()
	}
}

func doqStream(s *quic.Stream, srv *dnsserver.Server, ip netip.Addr) {
	_ = s.SetDeadline(time.Now().Add(10 * time.Second))
	var n [2]byte
	if _, err := io.ReadFull(s, n[:]); err != nil {
		s.CancelRead(0x2)
		s.CancelWrite(0x2)
		return
	}
	body := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(s, body); err != nil {
		s.CancelRead(0x2)
		s.CancelWrite(0x2)
		return
	}
	req := new(dns.Msg)
	if err := req.Unpack(body); err != nil || len(req.Question) != 1 {
		s.CancelWrite(0x2)
		return
	}
	resp := srv.Answer(req, ip, "doq")
	resp.Id = 0
	out, err := resp.Pack()
	if err != nil {
		s.CancelWrite(0x2)
		return
	}
	binary.BigEndian.PutUint16(n[:], uint16(len(out)))
	_, _ = s.Write(append(n[:], out...))
	_ = s.Close()
}

// dohHandler beantwortet GET ?dns=<base64url> und POST application/dns-message (RFC 8484).
func dohHandler(srv *dnsserver.Server) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientAddr(addrString(r.RemoteAddr))
		if !srv.Allowed(ip) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var wire []byte
		var err error
		switch r.Method {
		case http.MethodGet:
			wire, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
		case http.MethodPost:
			if ct := r.Header.Get("Content-Type"); ct != "application/dns-message" {
				http.Error(w, "unsupported media type", http.StatusUnsupportedMediaType)
				return
			}
			wire, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxDoHBody))
		default:
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		req := new(dns.Msg)
		if err == nil && len(wire) == 0 {
			err = errors.New("empty query")
		}
		if err == nil {
			err = req.Unpack(wire)
		}
		if err != nil || len(req.Question) != 1 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		resp := srv.Answer(req, ip, "doh")
		out, err := resp.Pack()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		w.Header().Set("Cache-Control", "max-age="+strconv.Itoa(minTTL(resp)))
		_, _ = w.Write(out)
	})
}

type addrString string

func (a addrString) Network() string { return "tcp" }
func (a addrString) String() string  { return string(a) }

// minTTL ist die kleinste TTL der Antwort (fuer Cache-Control), 0 ohne Eintraege.
func minTTL(m *dns.Msg) int {
	ttl := -1
	for _, rr := range append(append([]dns.RR{}, m.Answer...), m.Ns...) {
		if t := int(rr.Header().Ttl); ttl < 0 || t < ttl {
			ttl = t
		}
	}
	if ttl < 0 {
		return 0
	}
	return ttl
}
