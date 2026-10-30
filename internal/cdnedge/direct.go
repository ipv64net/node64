package cdnedge

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"sort"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/httpcompress"
)

// Modus 3 (direkt zum Ziel, Abschnitt 7 der Planung): wie das alte CDN, ohne Node. TLS endet hier (oder nur HTTP),
// die Anfrage geht an das Ziel des Nutzers - die aktuellen Adressen aus seinen DNS-Eintraegen (DynDNS aktualisiert
// sie, ipv64 gibt sie mit der Konfiguration weiter) oder ein fester Name bzw. eine feste IP. Ziele muessen oeffentlich
// sein: keine privaten, Loopback-, Link-Local-, CGNAT- oder Server-eigenen Adressen, geprueft bei jeder Verbindung und
// nach jeder Namensaufloesung (SSRF). Echte Besucher-IP per X-Forwarded-For/X-Real-IP, WebSockets, Cache (cache.go).

// apiTarget: Ziel eines Modus-3-Namens (von ipv64).
type apiTarget struct {
	Addrs        []string `json:"addrs"`         // aktuelle Adressen (Quelle "records" oder feste IP)
	Host         string   `json:"host"`          // fester Name (die Server loesen auf); leer = Addrs
	Port         int      `json:"port"`          // Standard 443 bzw. 80
	Scheme       string   `json:"scheme"`        // http | https
	Verify       bool     `json:"verify_tls"`    // Zertifikat des Ziels pruefen
	PreferIPv6   bool     `json:"prefer_ipv6"`   // IPv6 zuerst (Standard)
	Frontend     int      `json:"frontend"`      // 1 nur HTTP, 2 HTTPS mit Umleitung (Standard), 3 nur HTTPS
	CacheMB      int      `json:"cache_mb"`      // 0 = kein Cache
	CacheMinutes int      `json:"cache_minutes"` // ungenutzte Eintraege fallen danach weg
}

// apiACL: Erlauben-/Sperrliste eines Namens (alle Modi). Default "allow": alle ausser der Liste; "deny": nur die Liste.
type apiACL struct {
	Default string   `json:"default"`
	List    []string `json:"list"`
}

// target ist das geprueft uebernommene Ziel.
type target struct {
	addrs        []netip.Addr
	host         string
	port         int
	https        bool
	verify       bool
	preferIPv6   bool
	frontend     int
	cacheMB      int
	cacheMinutes int
	gen          string // Stand des Ziels: eigener Verbindungspool je Stand (Aenderung per DynDNS greift sofort)
}

func newTarget(t *apiTarget) *target {
	if t == nil {
		return nil
	}
	x := &target{host: normName(t.Host), port: t.Port, https: t.Scheme == "https", verify: t.Verify, preferIPv6: t.PreferIPv6,
		frontend: t.Frontend, cacheMB: t.CacheMB, cacheMinutes: t.CacheMinutes}
	for _, s := range t.Addrs {
		if a, err := netip.ParseAddr(s); err == nil {
			x.addrs = append(x.addrs, a.Unmap())
		}
	}
	if x.port <= 0 || x.port > 65535 {
		x.port = map[bool]int{true: 443, false: 80}[x.https]
	}
	if x.frontend < 0 || x.frontend > 3 { // 0 = keine Webseite (nur Portmapper)
		x.frontend = 2
	}
	h := sha256.Sum256([]byte(fmt.Sprint(x.addrs, x.host, x.port, x.https, x.verify)))
	x.gen = hex.EncodeToString(h[:6])
	return x
}

// acl ist die geprueft uebernommene Liste.
type acl struct {
	allowAll bool // Default "allow": die Liste sperrt
	list     []netip.Prefix
}

func newACL(a *apiACL) *acl {
	if a == nil || (a.Default != "allow" && a.Default != "deny") {
		return nil
	}
	return &acl{allowAll: a.Default == "allow", list: prefixes(a.List)}
}

// allows: darf die Adresse den Namen erreichen?
func (a *acl) allows(ip netip.Addr) bool {
	if a == nil {
		return true
	}
	ip = ip.Unmap()
	hit := false
	for _, p := range a.list {
		if p.Contains(ip) {
			hit = true
			break
		}
	}
	return a.allowAll != hit
}

// ---------------------------------------------------------------- SSRF-Schutz

var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// publicTarget: nur oeffentliche Unicast-Adressen, nicht die der Server selbst.
func (s *Server) publicTarget(a netip.Addr) bool {
	a = a.Unmap()
	if s.targetOK != nil { // Tests: lokale Ziele
		return s.targetOK(a)
	}
	if !a.IsValid() || !a.IsGlobalUnicast() || a.IsPrivate() || cgnat.Contains(a) || a.Is4In6() {
		return false
	}
	for _, bad := range []string{"192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"2001:db8::/32", "64:ff9b::/96", "64:ff9b:1::/48", "2002::/16", "2001::/32"} {
		if netip.MustParsePrefix(bad).Contains(a) {
			return false
		}
	}
	if c := s.apiCfg.Load(); c != nil {
		for _, e := range c.Edges {
			for _, ip := range e.IPs {
				if x, err := netip.ParseAddr(ip); err == nil && x.Unmap() == a {
					return false
				}
			}
		}
	}
	return true
}

// targetAddrs: Adressen fuer eine Verbindung (fester Name: jetzt aufloesen), oeffentliche zuerst nach Vorliebe.
func (s *Server) targetAddrs(ctx context.Context, t *target) ([]netip.Addr, error) {
	addrs := t.addrs
	if t.host != "" {
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(rctx, "ip", t.host)
		cancel()
		if err != nil {
			return nil, fmt.Errorf("target %s: %w", t.host, err)
		}
		addrs = ips
	}
	var ok []netip.Addr
	for _, a := range addrs {
		if s.publicTarget(a) {
			ok = append(ok, a.Unmap())
		}
	}
	if len(ok) == 0 {
		return nil, errBadTarget
	}
	sort.SliceStable(ok, func(i, j int) bool { return ok[i].Is6() == t.preferIPv6 && ok[j].Is6() != t.preferIPv6 })
	return ok, nil
}

var errBadTarget = errors.New("no public target address")

// ---------------------------------------------------------------- Weiterleitung

func (s *Server) directInit() *httputil.ReverseProxy {
	tr := &http.Transport{DialContext: s.directDial, DialTLSContext: s.directDialTLS, MaxIdleConnsPerHost: 32, IdleConnTimeout: 60 * time.Second,
		MaxResponseHeaderBytes: 1 << 20, ExpectContinueTimeout: time.Second, ForceAttemptHTTP2: false}
	return &httputil.ReverseProxy{Transport: tr, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: s.directError,
		ModifyResponse: func(resp *http.Response) error { // 5xx des Ziels: Fehlerseite fuer Browser; Cache: nur ganz gelesene Antworten
			_ = originErrorPage(resp)
			httpcompress.TrackBody(resp)
			return nil
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			tq, _ := pr.In.Context().Value(termCtxKey{}).(*termReq)
			scheme, gen := "http", "x"
			if tq != nil && tq.re.Target != nil {
				gen = tq.re.Target.gen
				if tq.re.Target.https {
					scheme = "https"
				}
			}
			// Pool je Name und Stand des Ziels (die Adresse waehlt der Dial)
			pr.Out.URL.Scheme, pr.Out.URL.Host, pr.Out.Host = scheme, gen+"."+hostOnly(pr.In.Host), pr.In.Host
			pr.SetXForwarded()
			if ap, err := netip.ParseAddrPort(pr.In.RemoteAddr); err == nil {
				pr.Out.Header.Set("X-Real-IP", ap.Addr().Unmap().String())
			}
		}}
}

// directDial: Verbindung zum Ziel (geprueft, Vorliebe IPv6/IPv4, je Adresse 5 s), gezaehlt wie ein Tunnel-Stream.
func (s *Server) directDial(ctx context.Context, _, _ string) (net.Conn, error) {
	tq, _ := ctx.Value(termCtxKey{}).(*termReq)
	if tq == nil || tq.re.Target == nil {
		return nil, errors.New("no target")
	}
	t := tq.re.Target
	addrs, err := s.targetAddrs(ctx, t)
	if err != nil {
		return nil, err
	}
	st := s.stats.of(tq.re.Name)
	var last error
	for _, a := range addrs {
		d := net.Dialer{Timeout: 5 * time.Second}
		c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a.String(), strconv.Itoa(t.port)))
		if err != nil {
			last = err
			continue
		}
		if ra := addrOf(c.RemoteAddr()); !s.publicTarget(ra) { // nach dem Verbinden noch einmal (kein Umweg ueber DNS-Rebinding)
			_ = c.Close()
			last = errBadTarget
			continue
		}
		st.conn(tq.ip)
		return &termConn{Conn: c, st: st, bw: s.bw, uid: tq.re.UserID, noOut: true}, nil // Antwort zaehlt outCounter
	}
	st.NoTunnel.Add(1)
	return nil, last
}

func (s *Server) directDialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := s.directDial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	tq, _ := ctx.Value(termCtxKey{}).(*termReq)
	tc := tls.Client(c, &tls.Config{ServerName: tq.host, InsecureSkipVerify: !tq.re.Target.verify, MinVersion: tls.VersionTLS12, //nolint:gosec // wie das alte CDN: Pruefung waehlbar
		NextProtos: []string{"http/1.1"}})
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return tc, nil
}

// directError: Ziel nicht erreichbar oder nicht erlaubt.
func (s *Server) directError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, context.Canceled) {
		return
	}
	if errors.Is(err, errBadTarget) {
		termPage(w, r, http.StatusBadGateway, hostOnly(r.Host), "Das eingetragene Ziel ist keine öffentliche Adresse.", "The configured target is not a public address.")
		return
	}
	termPage(w, r, http.StatusBadGateway, hostOnly(r.Host), "Der Server hinter dieser Adresse ist gerade nicht erreichbar. Bitte später noch einmal versuchen.",
		"The server behind this address is not reachable right now. Please try again later.")
}

// frontendHTTP: Port 80 eines Modus-3-Namens - nur HTTP (Stufe 1, oder solange das Zertifikat fehlt) bedienen,
// sonst umleiten (Stufe 2) bzw. abweisen (Stufe 3).
func frontendPlain(t *target, haveCert bool) string {
	switch {
	case t.frontend == 0:
		return "off"
	case t.frontend == 1 || (t.frontend == 2 && !haveCert):
		return "serve"
	case t.frontend == 2:
		return "redirect"
	}
	return "refuse"
}

func (s *Server) refuseHTTP(w http.ResponseWriter, r *http.Request) {
	termPage(w, r, http.StatusForbidden, hostOnly(r.Host), "Diese Adresse ist nur über HTTPS erreichbar.", "This address is only available via HTTPS.")
}
