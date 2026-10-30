package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/dns64/dnsserver"
	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/upstream"
)

// Einstellungen des Moduls (Kern-Tabelle settings, Schluessel dns64.*). Upstreams und Listen als JSON, neue
// Vorlagen erscheinen automatisch (aus).

const (
	setUpstreams = "dns64.upstreams"      // JSON []upstreamSetting
	setUpMode    = "dns64.upstream_mode"  // fastest | parallel | ordered
	setUpCount   = "dns64.upstream_count" // fastest: so viele Upstreams gleichzeitig
	setLists     = "dns64.lists"          // JSON []listSetting
	setListHours = "dns64.list_hours"     // Aktualisierung der Blocklisten
	setBlockMode = "dns64.block_mode"     // zero | nxdomain
	setCacheSize = "dns64.cache_size"
	setAnonymize = "dns64.anonymize"      // off | mask | hide
	setAllowNets = "dns64.allow_nets"     // weitere Client-Netze, eins je Zeile
	setCanary    = "dns64.firefox_canary" // 1 = use-application-dns.net -> NXDOMAIN (Firefox schaltet sein DoH ab)
	setDoH       = "dns64.doh"            // 1 = DoH fuer Geraete
	setDoT       = "dns64.dot"
	setDoQ       = "dns64.doq"
	setDoHPort   = "dns64.doh_port"
	setDoTPort   = "dns64.dot_port" // DoT (TCP) und DoQ (UDP)
	setNames     = "dns64.names"    // Namen fuer Geraete und Zertifikat
	setCertMode  = "dns64.cert_mode"
)

const (
	blockZero = "zero"
	blockNX   = "nxdomain"
	anonOff   = "off"
	anonMask  = "mask" // IPv4 /24, IPv6 /48
	anonHide  = "hide" // gar keine Client-Adresse
)

var listHours = []int{6, 12, 24, 48}

type upstreamSetting struct {
	upstream.Server
	Enabled bool `json:"enabled"`
	Custom  bool `json:"custom,omitempty"`
}

// Proto ist das Protokoll fuer die Anzeige (DoH, DoT, DoQ).
func (u upstreamSetting) Proto() string { return protoLabel(upstream.Proto(u.URL)) }

func protoLabel(p string) string {
	return map[string]string{"doh": "DoH", "dot": "DoT", "doq": "DoQ", "dns": "DNS"}[p]
}

type listSetting struct {
	filter.List
	Enabled bool `json:"enabled"`
	Custom  bool `json:"custom,omitempty"`
}

// config ist der vollstaendige Stand der Einstellungen.
type config struct {
	Port      int               `json:"port"`
	Bind      string            `json:"bind"`
	Router    string            `json:"router"`
	Retention int               `json:"retention_days"`
	UpMode    string            `json:"upstream_mode"`
	UpCount   int               `json:"upstream_count"` // fastest: 1..6 gleichzeitig
	Upstreams []upstreamSetting `json:"upstreams"`
	Lists     []listSetting     `json:"lists"`
	ListHours int               `json:"list_hours"`
	BlockMode string            `json:"block_mode"`
	CacheSize int               `json:"cache_size"`
	Anonymize string            `json:"anonymize"`
	AllowNets []string          `json:"allow_nets"`
	Canary    bool              `json:"firefox_canary"` // Firefox nutzt DNS64 statt seines eigenen DoH
	DoH       bool              `json:"doh"`
	DoT       bool              `json:"dot"`
	DoQ       bool              `json:"doq"`
	DoHPort   int               `json:"doh_port"`
	DoTPort   int               `json:"dot_port"`
	Names     []string          `json:"names"`
	CertMode  string            `json:"cert_mode"`
	CertID    int64             `json:"cert_id,omitempty"` // central: Zertifikat der Verwaltung
	NotifyUp  bool              `json:"notify_upstream"`
	NotifyLst bool              `json:"notify_lists"`
	// Let's Encrypt (cert_mode acme)
	ACMEDomain  string `json:"acme_domain"`
	ACMEPrefix  string `json:"acme_prefix"`
	ACMEEmail   string `json:"acme_email"`
	ACMEStaging bool   `json:"acme_staging"`
}

func (m *Module) intSetting(ctx context.Context, key string, def, lo, hi int) int {
	n, err := strconv.Atoi(m.core.SettingOr(ctx, key, strconv.Itoa(def)))
	if err != nil || n < lo || n > hi {
		return def
	}
	return n
}

func oneOf(v, def string, allowed ...string) string {
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	return def
}

// loadConfig liest die Einstellungen mit Standardwerten.
func (m *Module) loadConfig(ctx context.Context) config {
	c := config{
		Port:        m.port(ctx),
		Bind:        m.core.SettingOr(ctx, setBind, ""),
		Router:      m.core.SettingOr(ctx, setRouter, ""),
		Retention:   m.retention(ctx),
		UpMode:      oneOf(m.core.SettingOr(ctx, setUpMode, ""), upstream.ModeFastest, upstream.ModeFastest, upstream.ModeParallel, upstream.ModeOrdered),
		UpCount:     m.intSetting(ctx, setUpCount, upstream.DefaultTop, 1, upstream.MaxTop),
		ListHours:   m.intSetting(ctx, setListHours, 24, 1, 168),
		BlockMode:   oneOf(m.core.SettingOr(ctx, setBlockMode, ""), blockZero, blockZero, blockNX),
		CacheSize:   m.intSetting(ctx, setCacheSize, cacheSize, 1000, 200000),
		Anonymize:   oneOf(m.core.SettingOr(ctx, setAnonymize, ""), anonOff, anonOff, anonMask, anonHide),
		AllowNets:   splitLines(m.core.SettingOr(ctx, setAllowNets, "")),
		Canary:      m.core.SettingOr(ctx, setCanary, "1") == "1",
		DoH:         m.core.SettingOr(ctx, setDoH, "0") == "1",
		DoT:         m.core.SettingOr(ctx, setDoT, "0") == "1",
		DoQ:         m.core.SettingOr(ctx, setDoQ, "0") == "1",
		DoHPort:     m.intSetting(ctx, setDoHPort, 443, 1, 65535),
		DoTPort:     m.intSetting(ctx, setDoTPort, 853, 1, 65535),
		Names:       splitLines(m.core.SettingOr(ctx, setNames, "")),
		CertMode:    oneOf(m.core.SettingOr(ctx, setCertMode, ""), certSelf, certSelf, certNode64, certACME, certCentral),
		CertID:      int64(m.intSetting(ctx, setCertID, 0, 0, 1<<31-1)),
		NotifyUp:    m.core.SettingOr(ctx, setNotifyUpstream, "1") == "1",
		NotifyLst:   m.core.SettingOr(ctx, setNotifyLists, "1") == "1",
		ACMEDomain:  m.core.SettingOr(ctx, setACMEDom, ""),
		ACMEPrefix:  m.core.SettingOr(ctx, setACMEPre, ""),
		ACMEEmail:   m.core.SettingOr(ctx, setACMEMail, ""),
		ACMEStaging: m.core.SettingOr(ctx, setACMEStage, "0") == "1",
	}
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, setUpstreams, "")), &c.Upstreams)
	c.Upstreams = mergeUpstreams(c.Upstreams)
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, setLists, "")), &c.Lists)
	c.Lists = mergeLists(c.Lists)
	return c
}

// mergeUpstreams ergaenzt fehlende Vorlagen; ohne gespeicherten Stand gelten die Standard-Upstreams.
func mergeUpstreams(saved []upstreamSetting) []upstreamSetting {
	fresh := len(saved) == 0
	have := map[string]bool{}
	for _, s := range saved {
		have[s.URL] = true
	}
	for _, p := range upstream.Presets {
		if have[p.URL] {
			continue
		}
		on := false
		for _, d := range upstream.DefaultServers {
			on = on || (fresh && d.URL == p.URL)
		}
		saved = append(saved, upstreamSetting{Server: p, Enabled: on})
	}
	return saved
}

func mergeLists(saved []listSetting) []listSetting {
	fresh := len(saved) == 0
	saved = slices.DeleteFunc(saved, func(l listSetting) bool { return !l.Custom && filter.Retired[l.URL] }) // entfernte Vorlagen
	have := map[string]bool{}
	for _, s := range saved {
		have[s.URL] = true
	}
	for _, l := range filter.DefaultLists {
		if !have[l.URL] {
			saved = append(saved, listSetting{List: l, Enabled: fresh})
		}
	}
	for _, l := range filter.MoreLists {
		if !have[l.URL] {
			saved = append(saved, listSetting{List: l})
		}
	}
	return saved
}

// Cat ist die Kategorie einer Vorlage (Abzeichen auf der Seite Blocklisten, "" = eigene Liste).
func (l listSetting) Cat() string { return filter.Category(l.URL) }

func (c config) activeUpstreams() []upstream.Server {
	var out []upstream.Server
	for _, u := range c.Upstreams {
		if u.Enabled {
			out = append(out, u.Server)
		}
	}
	return out
}

func (c config) activeLists() []filter.List {
	out := []filter.List{}
	for _, l := range c.Lists {
		if l.Enabled {
			out = append(out, l.List)
		}
	}
	return out
}

// allowPrefixes liefert die weiteren Client-Netze (ungueltige Zeilen werden beim Speichern abgelehnt).
func (c config) allowPrefixes() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range c.AllowNets {
		if p, err := parsePrefix(s); err == nil && p.Bits() > 0 {
			out = append(out, p)
		}
	}
	return out
}

// PublicNets sind eingetragene Netze, die nicht privat sind (Warnung: offener Resolver fuer diese Netze).
func (c config) PublicNets() []string {
	var out []string
	for _, p := range c.allowPrefixes() {
		if !dnsserver.PrivatePrefix(p) {
			out = append(out, p.String())
		}
	}
	return out
}

// anonymizer liefert die Funktion fuer das Abfrage-Log (nil = volle Adresse).
func (c config) anonymizer() func(netip.Addr) string {
	switch c.Anonymize {
	case anonMask:
		return func(a netip.Addr) string {
			bits := 24
			if a.Is6() && !a.Is4In6() {
				bits = 48
			}
			p, err := a.Prefix(bits)
			if err != nil {
				return "-"
			}
			return p.Addr().String()
		}
	case anonHide:
		return func(netip.Addr) string { return "-" }
	}
	return nil
}

// saveConfig prueft und speichert die Einstellungen.
func (m *Module) saveConfig(ctx context.Context, c config) error {
	if err := c.validate(); err != nil {
		return err
	}
	ups, _ := json.Marshal(c.Upstreams)
	lists, _ := json.Marshal(c.Lists)
	for k, v := range map[string]string{
		setPort: strconv.Itoa(c.Port), setBind: c.Bind, setRouter: c.Router, setRetention: strconv.Itoa(c.Retention),
		setUpMode: c.UpMode, setUpCount: strconv.Itoa(c.UpCount), setUpstreams: string(ups), setLists: string(lists), setListHours: strconv.Itoa(c.ListHours),
		setBlockMode: c.BlockMode, setCacheSize: strconv.Itoa(c.CacheSize), setAnonymize: c.Anonymize,
		setAllowNets: strings.Join(c.AllowNets, "\n"), setCanary: b2s(c.Canary),
		setDoH: b2s(c.DoH), setDoT: b2s(c.DoT), setDoQ: b2s(c.DoQ), setDoHPort: strconv.Itoa(c.DoHPort), setDoTPort: strconv.Itoa(c.DoTPort),
		setNames: strings.Join(c.Names, "\n"), setCertMode: c.CertMode, setCertID: strconv.FormatInt(c.CertID, 10), setNotifyUpstream: b2s(c.NotifyUp), setNotifyLists: b2s(c.NotifyLst),
		setACMEDom: c.ACMEDomain, setACMEPre: c.ACMEPrefix, setACMEMail: c.ACMEEmail, setACMEStage: b2s(c.ACMEStaging),
	} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	m.clChanged(ctx, ItemSettings)
	m.clChanged(ctx, ItemLists)
	return nil
}

// cfgError ist ein Eingabefehler mit i18n-Schluessel (unter dns64.settings.).
type cfgError struct {
	Key  string
	Args []any
}

func (e *cfgError) Error() string { return "invalid setting: " + e.Key }

func errCfg(key string, args ...any) error { return &cfgError{Key: key, Args: args} }

func (c *config) validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return errCfg("err_port")
	}
	c.Bind = strings.Trim(strings.TrimSpace(c.Bind), "[]")
	if c.Bind != "" && net.ParseIP(c.Bind) == nil {
		return errCfg("err_bind")
	}
	c.Router = strings.TrimSpace(c.Router)
	if c.Router != "" {
		host := c.Router
		if h, p, err := net.SplitHostPort(c.Router); err == nil {
			if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
				return errCfg("err_router")
			}
			host = h
		}
		if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err != nil { // IPv4, IPv6, auch fe80::1%eth0
			return errCfg("err_router")
		}
	}
	if c.Retention < 1 || c.Retention > 90 {
		return errCfg("err_retention")
	}
	if c.CacheSize < 1000 || c.CacheSize > 200000 {
		return errCfg("err_cache")
	}
	if c.ListHours < 1 || c.ListHours > 168 {
		return errCfg("err_hours")
	}
	if c.DoHPort < 1 || c.DoHPort > 65535 || c.DoTPort < 1 || c.DoTPort > 65535 {
		return errCfg("err_enc_port")
	}
	if c.DoH && (c.DoHPort == c.Port || c.DoHPort == c.DoTPort) {
		return errCfg("err_enc_port")
	}
	if (c.DoT || c.DoQ) && c.DoTPort == c.Port {
		return errCfg("err_enc_port")
	}
	var names []string
	for _, n := range c.Names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n == "" {
			continue
		}
		if !validName(n) || net.ParseIP(n) != nil {
			return errCfg("err_enc_name", "name", n)
		}
		names = append(names, n)
	}
	c.Names = names
	c.CertMode = oneOf(c.CertMode, certSelf, certSelf, certNode64, certACME, certCentral)
	if c.CertMode == certCentral && c.CertID <= 0 {
		return errCfg("err_cert_id")
	}
	c.ACMEDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(c.ACMEDomain)), ".")
	c.ACMEPrefix = strings.Trim(strings.ToLower(strings.TrimSpace(c.ACMEPrefix)), ".")
	c.ACMEEmail = strings.TrimSpace(c.ACMEEmail)
	if c.ACMEDomain != "" && !validName(c.ACMEDomain) {
		return errCfg("err_acme_domain")
	}
	if c.ACMEPrefix != "" && (!validName(c.ACMEPrefix) || strings.HasPrefix(c.ACMEPrefix, "_")) {
		return errCfg("err_acme_prefix")
	}
	if c.ACMEEmail != "" && (!strings.Contains(c.ACMEEmail, "@") || strings.ContainsAny(c.ACMEEmail, " <>")) {
		return errCfg("err_acme_email")
	}
	if c.CertMode == certACME && c.ACMEDomain == "" {
		return errCfg("err_acme_domain")
	}
	c.UpMode = oneOf(c.UpMode, upstream.ModeFastest, upstream.ModeFastest, upstream.ModeParallel, upstream.ModeOrdered)
	if c.UpCount < 1 || c.UpCount > upstream.MaxTop {
		c.UpCount = upstream.DefaultTop
	}
	c.BlockMode = oneOf(c.BlockMode, blockZero, blockZero, blockNX)
	c.Anonymize = oneOf(c.Anonymize, anonOff, anonOff, anonMask, anonHide)
	var nets []string
	for _, s := range c.AllowNets {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := parsePrefix(s)
		if err != nil {
			return errCfg("err_net", "net", s)
		}
		if p.Bits() == 0 {
			return errCfg("err_net_any", "net", s)
		}
		nets = append(nets, p.String())
	}
	c.AllowNets = nets
	if len(c.activeUpstreams()) == 0 {
		return errCfg("err_no_upstream")
	}
	for i := range c.Upstreams {
		if err := checkUpstream(&c.Upstreams[i].Server); err != nil {
			return err
		}
	}
	for _, l := range c.Lists {
		if err := checkListURL(l.URL); err != nil {
			return err
		}
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p = p.Masked(); p.Addr().Is4In6() { // ::ffff:10.8.0.0/112 -> 10.8.0.0/16 (Clients kommen ohne ::ffff:)
		if p.Bits() < 96 {
			return netip.Prefix{}, errors.New("ipv4-mapped prefix shorter than /96")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p, nil
}

// checkUpstream: https:// (DoH), tls:// (DoT) oder quic:// (DoQ); Bootstrap-IPs noetig, wenn der Host kein IP
// ist (sonst Schleife ueber den eigenen Resolver). Klassisches DNS (unverschluesselt, Port 53) als IP, IP:Port oder
// dns://IP[:Port] - nur mit IP-Adresse, ein Name braeuchte wieder DNS.
func checkUpstream(s *upstream.Server) error {
	s.Name = strings.TrimSpace(s.Name)
	if plain, ok := plainUpstream(s.URL); ok {
		s.URL, s.IPs = plain, nil
		if s.Name == "" {
			s.Name, _ = url.PathUnescape(strings.TrimPrefix(plain, "dns://"))
		}
		return nil
	}
	u, err := url.Parse(strings.TrimSpace(s.URL))
	if err != nil || upstream.Proto(s.URL) == "" || upstream.Proto(s.URL) == "dns" || u.Host == "" || (u.Scheme != "https" && u.Path != "" && u.Path != "/") {
		return errCfg("err_up_url", "url", s.URL)
	}
	if u.Scheme != "https" {
		u.Path = ""
	}
	s.URL = u.String()
	if s.Name == "" {
		s.Name = u.Hostname()
	}
	var ips []string
	for _, ip := range s.IPs {
		ip = strings.Trim(strings.TrimSpace(ip), "[]")
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			return errCfg("err_up_ip", "ip", ip)
		}
		ips = append(ips, ip)
	}
	s.IPs = ips
	if len(ips) == 0 && net.ParseIP(u.Hostname()) == nil {
		return errCfg("err_up_ips", "name", s.Name)
	}
	return nil
}

// plainUpstream: klassischer DNS-Server als dns://ip:port (Eingabe IP, IP:Port, [IPv6]:Port oder dns://…).
func plainUpstream(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if h, ok := strings.CutPrefix(raw, "dns://"); ok {
		raw = strings.TrimSuffix(h, "/")
		if h, err := url.PathUnescape(raw); err == nil {
			raw = h // Zone gespeichert als %25 (dns://[fe80::1%25eth0]:53)
		}
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil && ap.Port() != 0 {
		return plainURL(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())), true
	}
	// zuerst mit Port: sonst haelt ParseAddr "]:53" fuer einen Teil der Zone
	if a, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil && !strings.ContainsAny(a.Zone(), "[]:") {
		return plainURL(netip.AddrPortFrom(a.Unmap(), 53)), true
	}
	return "", false
}

// plainURL baut dns://ip:port; url.URL maskiert die Zone einer Link-Local-Adresse (%25), sonst scheitert url.Parse.
func plainURL(ap netip.AddrPort) string {
	return (&url.URL{Scheme: "dns", Host: ap.String()}).String()
}

func checkListURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return errCfg("err_list_url", "url", raw)
	}
	return nil
}

func splitLines(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

var errNotFound = errors.New("not found")

func b2s(b bool) string {
	if b {
		return "1"
	}
	return "0"
}
