// Package checks ist der Check-Bot: je Check-Typ eine Datei, ein gemeinsames
// Interface. Das Paket haengt nur von der Standardbibliothek und pro-bing ab
// und kennt weder Datenbank noch Scheduler noch Oberflaeche. Derselbe Code
// soll spaeter unveraendert auf den ipv64-Servern laufen.
//
// Ablauf: Run loest das Ziel per DNS auf, entscheidet nach IPMode, ob IPv4,
// IPv6 oder beides geprueft wird, und ruft den passenden Checker je Adresse.
// Jedes Ergebnis traegt Status, Latenz, maschinenlesbaren Grund, Text und
// Rohdetails.
package checks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Type string

const (
	TypeICMP    Type = "icmp"
	TypeHTTP    Type = "http"
	TypeKeyword Type = "keyword"
	TypeTCP     Type = "tcp"
	TypePort    Type = "port"
	TypeCert    Type = "cert"
	TypePush    Type = "push"
	TypeJSON    Type = "json"
	TypeDNS     Type = "dns"
	TypeWhois   Type = "whois" // Registrierungsdaten (RDAP, sonst WHOIS) einer Domain, IP bzw. eines AS
)

// Types sind alle bekannten Typen in Anzeigereihenfolge.
var Types = []Type{TypeHTTP, TypeKeyword, TypeJSON, TypeDNS, TypeICMP, TypeTCP, TypePort, TypeCert, TypeWhois, TypePush, TypeDocker}

// IPMode bestimmt, welche Adressfamilie geprueft wird.
type IPMode string

const (
	IPAuto IPMode = "auto" // was DNS liefert: v4, v6 oder beides
	IPv4   IPMode = "ipv4"
	IPv6   IPMode = "ipv6"
	IPBoth IPMode = "both"
)

type Status string

const (
	Up   Status = "up"
	Down Status = "down"
)

// Reason ist der maschinenlesbare Grund eines Ergebnisses.
type Reason string

const (
	ReasonOK              Reason = "ok"
	ReasonInvalid         Reason = "invalid_definition"
	ReasonDNSFailed       Reason = "dns_failed"
	ReasonNoAddress       Reason = "no_address_for_family"
	ReasonTimeout         Reason = "timeout"
	ReasonConnectFailed   Reason = "connect_failed"
	ReasonTLSFailed       Reason = "tls_failed"
	ReasonStatusMismatch  Reason = "status_mismatch"
	ReasonTooManyRedirect Reason = "too_many_redirects"
	ReasonKeywordMissing  Reason = "keyword_missing"
	ReasonKeywordPresent  Reason = "keyword_present"
	ReasonJSONInvalid     Reason = "json_invalid"
	ReasonJSONMismatch    Reason = "json_mismatch"
	ReasonDNSMismatch     Reason = "dns_mismatch"
	ReasonDNSNXDomain     Reason = "dns_nxdomain"
	ReasonDNSSEC          Reason = "dnssec_failed"
	ReasonBannerMismatch  Reason = "banner_mismatch"
	ReasonPortClosed      Reason = "port_closed"
	ReasonPortOpen        Reason = "port_open"
	ReasonPacketLoss      Reason = "packet_loss"
	ReasonLatencyHigh     Reason = "latency_high"
	ReasonICMPDenied      Reason = "icmp_not_permitted"
	ReasonCertExpired     Reason = "cert_expired"
	ReasonCertExpiring    Reason = "cert_expiring"
	ReasonCertInvalid     Reason = "cert_invalid"
	ReasonCertHostname    Reason = "cert_hostname_mismatch"
	ReasonPushMissing     Reason = "push_missing"
	ReasonPushDown        Reason = "push_reported_down"
	ReasonDependencyDown  Reason = "dependency_down"
	ReasonInternal        Reason = "internal_error"
)

// Timeouts: Verbindungsaufbau und Gesamtdauer getrennt.
type Timeouts struct {
	Connect time.Duration
	Total   time.Duration
}

// Definition ist alles, was ein Checker ueber einen Check wissen muss.
type Definition struct {
	Token  string
	Type   Type
	Target string
	// Params sind typabhaengig (siehe Params-Structs je Datei), als JSON.
	Params   json.RawMessage
	Timeouts Timeouts
	IPMode   IPMode
}

// Result ist ein einzelnes Messergebnis.
type Result struct {
	Status  Status
	Latency time.Duration
	Reason  Reason
	Message string
	Time    time.Time // UTC
	// Family ist ipv4 oder ipv6, leer wenn nicht zutreffend.
	Family string
	// Details sind Rohdaten, z. B. Statuscode, aufgeloeste IP, Zertifikatsdaten.
	Details map[string]any
}

func (r Result) LatencyMS() float64 { return float64(r.Latency.Microseconds()) / 1000 }

// Checker fuehrt einen Check gegen eine konkrete Adresse aus. ip ist die
// bereits aufgeloeste Adresse (leer bei Typen ohne Netzwerkziel).
type Checker interface {
	Type() Type
	Check(ctx context.Context, def Definition, ip net.IP) Result
}

// Defaults fuer Timeouts und Intervalle.
const (
	DefaultConnectTimeout = 5 * time.Second
	DefaultTotalTimeout   = 10 * time.Second
	MinInterval           = 20 * time.Second // online und hybrid (ipv64 misst mit)
	MinIntervalLocal      = 5 * time.Second  // nur lokal auf den Nodes
	DefaultInterval       = 60 * time.Second
	MaxBody               = 1 << 20
	UserAgent             = "node64"
)

// Resolver loest Hostnamen auf; austauschbar fuer Tests.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Runner haelt die Checker und fuehrt Definitionen aus.
type Runner struct {
	checkers map[Type]Checker
	Resolver Resolver
	Now      func() time.Time
	// PublicIP liefert die oeffentliche Adresse der Node je Familie (DNS-Check "public_ip"); nil auf den
	// ipv64-Servern, dort laeuft so ein Check nicht.
	PublicIP func(ctx context.Context, family string) (string, error)
	// FamilyProbe sagt, ob der Node selbst ipv4 bzw. ipv6 erreichen kann.
	// Im Modus auto werden nur verfuegbare Familien geprueft; austauschbar fuer Tests.
	FamilyProbe func(family string) bool
	// Proxmox liefert den letzten Stand eines Gasts bzw. Nodes aus der Proxmox-Abfrage (Check-Typ proxmox); nil =
	// Proxmox-Ueberwachung laeuft nicht (z. B. auf den ipv64-Servern).
	Proxmox func(systemID int64, key string) ProxmoxState
	// ProxmoxUID findet die lokale ID eines Systems ueber seine Kennung im Cluster (ProxmoxParams.SystemUID);
	// nil = nur ueber die ID.
	ProxmoxUID func(uid string) (int64, bool)
	// Docker liefert die Verbindung der Docker-Ueberwachung zu einem Host (Check-Typ docker bei https:// bzw. ssh://
	// mit Zugangsdaten); nil = keine.
	Docker DockerRemote
	// DenyPrivate (ipv64-Server): nur oeffentliche Adressen erreichen – auch nach DNS-Aufloesung, Weiterleitung und
	// bei DNS-Checks mit eigenem Server oder zustaendigen Nameservern (guard.go).
	DenyPrivate bool

	famMu    sync.Mutex
	famCache map[string]famState
}

type famState struct {
	ok bool
	at time.Time
}

// NewRunner registriert alle eingebauten Checker.
func NewRunner() *Runner {
	r := &Runner{checkers: map[Type]Checker{}, Resolver: net.DefaultResolver, Now: func() time.Time { return time.Now().UTC() }, famCache: map[string]famState{}}
	r.FamilyProbe = probeFamily
	for _, c := range []Checker{&httpChecker{}, &httpChecker{keyword: true}, &httpChecker{json: true}, &dnsChecker{r: r}, &tcpChecker{}, &portChecker{}, &certChecker{}, &icmpChecker{}, dockerChecker{r: r}, proxmoxChecker{r: r}, whoisChecker{r: r}} {
		r.checkers[c.Type()] = c
	}
	return r
}

// Register ersetzt oder ergaenzt einen Checker (Tests, Erweiterungen).
func (r *Runner) Register(c Checker) { r.checkers[c.Type()] = c }

// Run fuehrt eine Definition aus. Bei IPBoth (oder IPAuto mit A und AAAA)
// kommen zwei Ergebnisse zurueck, sonst eines. Push-Checks liefern nichts,
// sie werden vom Scheduler per Watchdog bewertet.
func (r *Runner) Run(ctx context.Context, def Definition) []Result {
	now := r.Now()
	if def.Type == TypePush {
		return nil
	}
	c, ok := r.checkers[def.Type]
	if !ok {
		return []Result{{Status: Down, Reason: ReasonInvalid, Message: "unknown check type " + string(def.Type), Time: now}}
	}
	if def.Timeouts.Connect <= 0 {
		def.Timeouts.Connect = DefaultConnectTimeout
	}
	if def.Timeouts.Total <= 0 {
		def.Timeouts.Total = DefaultTotalTimeout
	}
	if def.IPMode == "" {
		def.IPMode = IPAuto
	}
	if r.DenyPrivate {
		if def.Type == TypeDocker || def.Type == TypeProxmox {
			return []Result{{Status: Down, Reason: ReasonInvalid, Message: ErrPrivateAddress.Error(), Time: now}}
		}
		ctx = withDenyPrivate(ctx)
	}
	if def.Type == TypeDocker || def.Type == TypeDNS || def.Type == TypeProxmox || def.Type == TypeWhois { // kein Ziel zum Aufloesen: Docker-API, DNS-Abfrage bzw. Stand der Proxmox-Abfrage
		cctx, cancel := context.WithTimeout(ctx, def.Timeouts.Total)
		res := c.Check(cctx, def, nil)
		cancel()
		if res.Time.IsZero() {
			res.Time = now
		}
		return []Result{res}
	}
	host := TargetHost(def)
	if host == "" {
		return []Result{{Status: Down, Reason: ReasonInvalid, Message: "target is empty", Time: now}}
	}
	ips, res := r.resolve(ctx, host, def.IPMode, def.Timeouts.Connect, now)
	if res != nil {
		return []Result{*res}
	}
	if r.DenyPrivate {
		for _, ip := range ips {
			if !PublicIP(ip) {
				return []Result{{Status: Down, Reason: ReasonInvalid, Message: ErrPrivateAddress.Error() + " (" + ip.String() + ")", Time: now, Details: map[string]any{"host": host}}}
			}
		}
	}
	var out []Result
	for _, ip := range ips {
		cctx, cancel := context.WithTimeout(ctx, def.Timeouts.Total)
		res := c.Check(cctx, def, ip)
		cancel()
		if res.Time.IsZero() {
			res.Time = now
		}
		if res.Details == nil {
			res.Details = map[string]any{}
		}
		res.Details["ip"] = ip.String()
		res.Family = family(ip)
		if res.Reason == "" {
			if res.Status == Up {
				res.Reason = ReasonOK
			} else {
				res.Reason = ReasonInternal
			}
		}
		out = append(out, res)
	}
	return out
}

// resolve liefert die zu pruefenden Adressen nach IPMode.
func (r *Runner) resolve(ctx context.Context, host string, mode IPMode, timeout time.Duration, now time.Time) ([]net.IP, *Result) {
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		fam := family(ip)
		if (mode == IPv4 && fam != "ipv4") || (mode == IPv6 && fam != "ipv6") {
			return nil, &Result{Status: Down, Reason: ReasonNoAddress, Message: fmt.Sprintf("target %s is not %s", host, mode), Time: now}
		}
		return []net.IP{ip}, nil
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := r.Resolver.LookupIPAddr(rctx, host)
	if err != nil {
		return nil, &Result{Status: Down, Reason: ReasonDNSFailed, Message: "DNS lookup failed: " + err.Error(), Time: now, Details: map[string]any{"host": host}}
	}
	var v4, v6 []net.IP
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = append(v4, a.IP)
		} else {
			v6 = append(v6, a.IP)
		}
	}
	pick := func(list []net.IP) net.IP { return list[0] }
	var ips []net.IP
	switch mode {
	case IPv4:
		if len(v4) == 0 {
			return nil, &Result{Status: Down, Reason: ReasonNoAddress, Message: "no IPv4 address for " + host, Time: now, Family: "ipv4"}
		}
		ips = []net.IP{pick(v4)}
	case IPv6:
		if len(v6) == 0 {
			return nil, &Result{Status: Down, Reason: ReasonNoAddress, Message: "no IPv6 address for " + host, Time: now, Family: "ipv6"}
		}
		ips = []net.IP{pick(v6)}
	case IPBoth:
		if len(v4) == 0 || len(v6) == 0 {
			return nil, &Result{Status: Down, Reason: ReasonNoAddress, Message: "both IPv4 and IPv6 required but " + host + " has only one family", Time: now}
		}
		ips = []net.IP{pick(v4), pick(v6)}
	default: // auto: was DNS liefert, aber nur Familien, die der Node selbst hat
		if len(v4) > 0 && r.hasFamily("ipv4") {
			ips = append(ips, pick(v4))
		}
		if len(v6) > 0 && r.hasFamily("ipv6") {
			ips = append(ips, pick(v6))
		}
		if len(ips) == 0 {
			// Keine passende Familie am Node: trotzdem pruefen, damit der Grund sichtbar wird
			if len(v4) > 0 {
				ips = append(ips, pick(v4))
			} else if len(v6) > 0 {
				ips = append(ips, pick(v6))
			}
		}
	}
	if len(ips) == 0 {
		return nil, &Result{Status: Down, Reason: ReasonDNSFailed, Message: "no address for " + host, Time: now}
	}
	return ips, nil
}

// hasFamily fragt FamilyProbe hoechstens einmal pro Minute je Familie.
func (r *Runner) hasFamily(fam string) bool {
	if r.FamilyProbe == nil {
		return true
	}
	r.famMu.Lock()
	defer r.famMu.Unlock()
	if r.famCache == nil {
		r.famCache = map[string]famState{}
	}
	if st, ok := r.famCache[fam]; ok && time.Since(st.at) < time.Minute {
		return st.ok
	}
	ok := r.FamilyProbe(fam)
	r.famCache[fam] = famState{ok: ok, at: time.Now()}
	return ok
}

// ProbeFamily meldet, ob eine Route fuer "ipv4" bzw. "ipv6" existiert (fuer andere Module).
func ProbeFamily(fam string) bool { return probeFamily(fam) }

// probeFamily prueft per UDP-"Connect" (es wird kein Paket gesendet), ob eine
// Route fuer die Familie existiert. Ohne IPv6-Route antwortet der Kernel mit
// "network is unreachable".
func probeFamily(fam string) bool {
	network, addr := "udp4", "192.0.2.1:9"
	if fam == "ipv6" {
		network, addr = "udp6", "[2001:db8::1]:9"
	}
	d := net.Dialer{Timeout: time.Second}
	c, err := d.Dial(network, addr)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func family(ip net.IP) string {
	if ip.To4() != nil {
		return "ipv4"
	}
	return "ipv6"
}

// TargetHost extrahiert den Hostnamen aus dem Ziel (URL oder Host[:Port]).
func TargetHost(def Definition) string {
	t := strings.TrimSpace(def.Target)
	if def.Type == TypeHTTP || def.Type == TypeKeyword || def.Type == TypeJSON {
		u, err := parseURL(t)
		if err != nil {
			return ""
		}
		return u.Hostname()
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		return h
	}
	return strings.Trim(t, "[]")
}

// WithoutUnknownParams entfernt Parameterfelder (oberste Ebene), die diese Version nicht kennt. Fuer Checks, die
// eine neuere Node oder der Server geschrieben hat: sonst scheitert die Uebernahme an der strengen Pruefung.
func WithoutUnknownParams(def Definition) json.RawMessage {
	for range 20 {
		err := Validate(def)
		if err == nil || !strings.HasPrefix(err.Error(), "params: json: unknown field ") {
			return def.Params
		}
		field, _ := strconv.Unquote(strings.TrimPrefix(err.Error(), "params: json: unknown field "))
		var m map[string]json.RawMessage
		if json.Unmarshal(def.Params, &m) != nil {
			return def.Params
		}
		if _, ok := m[field]; !ok {
			return def.Params
		}
		delete(m, field)
		def.Params, _ = json.Marshal(m)
	}
	return def.Params
}

// Validate prueft Typ, Ziel und Parameter einer Definition.
func Validate(def Definition) error {
	switch def.Type {
	case TypeHTTP, TypeKeyword, TypeJSON:
		u, err := parseURL(def.Target)
		if err != nil {
			return err
		}
		if u.Hostname() == "" {
			return errors.New("url has no host")
		}
		var p HTTPParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if _, err := parseStatusRanges(p.AcceptStatus); err != nil {
			return err
		}
		if def.Type == TypeKeyword && strings.TrimSpace(p.Keyword) == "" {
			return errors.New("keyword is required")
		}
		if def.Type == TypeJSON {
			if err := validateJSONRules(p.JSONRules); err != nil {
				return err
			}
		}
		if p.CertMinDays < 0 || p.CertMinDays > 3650 {
			return errors.New("cert_min_days must be between 0 and 3650")
		}
	case TypeTCP, TypePort:
		host := TargetHost(def)
		if host == "" {
			return errors.New("target host is required")
		}
		var p TCPParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if _, err := portOf(def, p.Port); err != nil {
			return err
		}
		if def.Type == TypePort && p.Expect != "" && p.Expect != "open" && p.Expect != "closed" {
			return errors.New("expect must be open or closed")
		}
	case TypeCert:
		if TargetHost(def) == "" {
			return errors.New("target host is required")
		}
		var p CertParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if p.MinDays < 0 || p.MinDays > 3650 {
			return errors.New("min_days must be between 0 and 3650")
		}
	case TypeICMP:
		if TargetHost(def) == "" {
			return errors.New("target host is required")
		}
		var p ICMPParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if p.Count < 0 || p.Count > 20 {
			return errors.New("count must be between 1 and 20")
		}
		if p.MaxLossPercent < 0 || p.MaxLossPercent > 100 {
			return errors.New("max_loss_percent must be between 0 and 100")
		}
	case TypeDocker:
		if !containerRe.MatchString(strings.TrimSpace(def.Target)) {
			return errors.New("container name or id is required (letters, digits, _ . -)")
		}
		var p DockerParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if !validDockerHost(p.Host) {
			return errors.New("docker host must start with unix://, tcp:// or http(s)://")
		}
	case TypeDNS:
		if err := validateDNS(def); err != nil {
			return err
		}
	case TypeWhois:
		if err := validateWhois(def); err != nil {
			return err
		}
	case TypeProxmox:
		if err := validateProxmox(def); err != nil {
			return err
		}
	case TypePush:
		var p PushParams
		if err := decode(def.Params, &p); err != nil {
			return err
		}
		if p.PeriodSeconds < 0 || (p.GraceSeconds != nil && *p.GraceSeconds < 0) {
			return errors.New("period_seconds and grace_seconds must not be negative")
		}
	default:
		return fmt.Errorf("unknown check type %q", def.Type)
	}
	switch def.IPMode {
	case "", IPAuto, IPv4, IPv6, IPBoth:
	default:
		return fmt.Errorf("unknown ip_mode %q", def.IPMode)
	}
	return nil
}

func decode(raw json.RawMessage, v any) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("params: %w", err)
	}
	return nil
}

// portOf nimmt den Port aus den Parametern, sonst aus host:port im Ziel.
// DisplayTarget ist das Ziel fuer Listen: bei TCP/Port/Zertifikat Host mit dem Port, der wirklich
// gemessen wird (Port-Feld vor Port im Ziel), beim Zertifikat nur, wenn er von 443 abweicht.
func DisplayTarget(def Definition) string {
	t := strings.TrimSpace(def.Target)
	if t == "" || (def.Type != TypeTCP && def.Type != TypePort && def.Type != TypeCert) {
		return t
	}
	var p TCPParams
	_ = decode(def.Params, &p)
	port, err := portOf(def, p.Port)
	if def.Type == TypeCert && (err != nil || port == 443) {
		port = 0
	}
	if err != nil || port == 0 {
		return TargetHost(def)
	}
	return net.JoinHostPort(TargetHost(def), strconv.Itoa(port))
}

// SplitTargetPort traegt bei TCP, Port und Zertifikat einen Port aus dem Ziel (host:port) ins Port-Feld
// ein, das Ziel bleibt nur Host oder IP. Stehen dort zwei verschiedene Ports, ist das ein Fehler.
// Nur fuer Eingaben (Formular, lokale API), nicht beim Sync: dort misst ein Check unveraendert weiter.
func SplitTargetPort(typ Type, target string, params json.RawMessage) (string, json.RawMessage, error) {
	if typ != TypeTCP && typ != TypePort && typ != TypeCert {
		return target, params, nil
	}
	host, ps, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return target, params, nil
	}
	tp, err := strconv.Atoi(ps)
	if err != nil || tp < 1 || tp > 65535 {
		return target, params, fmt.Errorf("target: port %q must be between 1 and 65535", ps)
	}
	p := map[string]any{}
	if len(params) > 0 {
		if err := json.Unmarshal(params, &p); err != nil {
			return target, params, fmt.Errorf("params: %w", err)
		}
	}
	if fp, _ := p["port"].(float64); fp != 0 && int(fp) != tp {
		return target, params, fmt.Errorf("the target contains port %d, the port field %d: enter the port only in the port field", tp, int(fp))
	}
	p["port"] = tp
	out, err := json.Marshal(p)
	if err != nil {
		return target, params, err
	}
	return host, out, nil
}

func portOf(def Definition, p int) (int, error) {
	if p == 0 {
		if _, ps, err := net.SplitHostPort(strings.TrimSpace(def.Target)); err == nil {
			p, _ = strconv.Atoi(ps)
		}
	}
	if p < 1 || p > 65535 {
		return 0, errors.New("port must be between 1 and 65535")
	}
	return p, nil
}

// statusRange ist ein akzeptierter Bereich von HTTP-Statuscodes.
type statusRange struct{ lo, hi int }

// parseStatusRanges liest "200-299,301,404" (leer = 200-299).
func parseStatusRanges(s string) ([]statusRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return []statusRange{{200, 299}}, nil
	}
	var out []statusRange
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("invalid status %q", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("invalid status range %q", part)
			}
		}
		if a < 100 || b > 599 || a > b {
			return nil, fmt.Errorf("status range %q out of bounds", part)
		}
		out = append(out, statusRange{a, b})
	}
	if len(out) == 0 {
		return []statusRange{{200, 299}}, nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].lo < out[j].lo })
	return out, nil
}

func statusAccepted(code int, ranges []statusRange) bool {
	for _, r := range ranges {
		if code >= r.lo && code <= r.hi {
			return true
		}
	}
	return false
}

// isTimeout erkennt Timeouts aus Netz- und Kontextfehlern.
func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dialIP verbindet zu einer festen Adresse mit Connect-Timeout.
func dialIP(ctx context.Context, ip net.IP, port int, connect time.Duration) (net.Conn, error) {
	return guard(ctx, &net.Dialer{Timeout: connect}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

func fail(reason Reason, msg string, lat time.Duration, details map[string]any) Result {
	return Result{Status: Down, Reason: reason, Message: msg, Latency: lat, Details: details}
}

func ok(msg string, lat time.Duration, details map[string]any) Result {
	return Result{Status: Up, Reason: ReasonOK, Message: msg, Latency: lat, Details: details}
}
