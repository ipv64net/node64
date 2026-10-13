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
)

// Types sind alle bekannten Typen in Anzeigereihenfolge.
var Types = []Type{TypeHTTP, TypeKeyword, TypeICMP, TypeTCP, TypePort, TypeCert, TypePush, TypeDocker}

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
	MinInterval           = 20 * time.Second
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
	// FamilyProbe sagt, ob der Node selbst ipv4 bzw. ipv6 erreichen kann.
	// Im Modus auto werden nur verfuegbare Familien geprueft; austauschbar fuer Tests.
	FamilyProbe func(family string) bool

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
	for _, c := range []Checker{&httpChecker{}, &httpChecker{keyword: true}, &tcpChecker{}, &portChecker{}, &certChecker{}, &icmpChecker{}, dockerChecker{}} {
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
	if def.Type == TypeDocker { // kein Netzwerkziel: direkt die Docker-API fragen
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
	if def.Type == TypeHTTP || def.Type == TypeKeyword {
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

// Validate prueft Typ, Ziel und Parameter einer Definition.
func Validate(def Definition) error {
	switch def.Type {
	case TypeHTTP, TypeKeyword:
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
// DisplayTarget ist das Ziel fuer Listen: bei TCP/Port mit Port, beim Zertifikat mit abweichendem Port.
func DisplayTarget(def Definition) string {
	t := strings.TrimSpace(def.Target)
	if t == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(t); err == nil {
		return t // Port steht schon im Ziel
	}
	port := 0
	switch def.Type {
	case TypeTCP, TypePort:
		var p TCPParams
		_ = decode(def.Params, &p)
		port = p.Port
	case TypeCert:
		var p CertParams
		_ = decode(def.Params, &p)
		if p.Port != 443 {
			port = p.Port
		}
	}
	if port <= 0 {
		return t
	}
	return net.JoinHostPort(strings.Trim(t, "[]"), strconv.Itoa(port))
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
	d := net.Dialer{Timeout: connect}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(port)))
}

func fail(reason Reason, msg string, lat time.Duration, details map[string]any) Result {
	return Result{Status: Down, Reason: reason, Message: msg, Latency: lat, Details: details}
}

func ok(msg string, lat time.Duration, details map[string]any) Result {
	return Result{Status: Up, Reason: ReasonOK, Message: msg, Latency: lat, Details: details}
}
