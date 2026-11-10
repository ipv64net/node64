package apis

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// NUT (Network UPS Tools, upsd auf TCP 3493, Textprotokoll). Je Runde eine Verbindung:
//
//	STARTTLS                 wenn upsd es anbietet (TLS "" ) bzw. Pflicht (TLS "require" oder Pin gesetzt)
//	USERNAME/PASSWORD        nur wenn eingetragen (zum Lesen braucht upsd keine Anmeldung)
//	                         TLS auto ohne STARTTLS: ohne Anmeldung (kein Passwort im Klartext)
//	LIST UPS                 alle USVs dieses upsd
//	LIST VAR <ups>           Variablen je USV -> Dienst ups:<name>
//	LOGOUT
//
// Messgroessen: ups.status (OL/OB/LB/RB/CHRG/OVER …), battery.charge, battery.runtime (Regel ups.runtime),
// ups.load, input.voltage, ups.temperature, ups.realpower. Zustaende: ups_on_battery, ups_low_battery (LB/FSD),
// ups_replace_battery (RB), ups_overload (OVER). Meldet upsd fuer eine USV DATA-STALE bzw. DRIVER-NOT-CONNECTED,
// fehlt ihr Dienst in dieser Runde (Teilfehler mit Praefix ups:<name>: der Kern behaelt den vorigen Stand und der
// Zugang warnt).

const (
	nutDefaultPort = "3493"
	nutMaxLine     = 8 << 10 // laengste Zeile
	nutMaxLines    = 50000   // Zeilen je Runde hoechstens
	nutMaxBytes    = 4 << 20 // Bytes je Runde hoechstens (sonst bis nutMaxLines x nutMaxLine im Speicher)
	nutMaxUPS      = 64      // USVs je upsd
	nutMaxVars     = 2000    // Variablen je USV
	nutDialTimeout = 5 * time.Second
	// ruleUPSRuntime ist die Art der Restlaufzeit (eval.KindUPSRuntime; in model fehlt noch eine Konstante)
	ruleUPSRuntime = "ups.runtime"
)

// Modi fuer NUTConfig.TLS.
const (
	NUTTLSAuto    = ""        // STARTTLS, wenn upsd es anbietet (sonst unverschluesselt und ohne Anmeldung)
	NUTTLSOff     = "off"     // nie
	NUTTLSRequire = "require" // Pflicht (auch mit Pin)
)

var nutReName = regexp.MustCompile(`^[A-Za-z0-9._@:+-]{1,64}$`)

// NUTConfig sind die Verbindungsdaten eines upsd.
type NUTConfig struct {
	Address  string   // host[:3493] (auch nut://host:port, IPv6 in Klammern)
	UPS      []string // nur diese USVs (leer = alle, die upsd nennt)
	User     string   // optional (upsd.users)
	Password string   // optional, Geheimnis (nie ausgeben)
	TLS      string   // NUTTLSAuto, NUTTLSOff, NUTTLSRequire
	Pin      string   // SHA-256 des upsd-Zertifikats (hex); gesetzt = TLS Pflicht
	Timeout  time.Duration
}

// NUT ist der Sammler eines upsd.
type NUT struct {
	cfg   NUTConfig
	addr  string // host:port
	host  string
	pin   string
	roots *x509.CertPool // nil = System-CA (Tests)
	mu    sync.Mutex
	// tlsSeen: upsd hat schon einmal STARTTLS angenommen; lehnt er es danach ab (Modus auto), ist das ein Fehler
	// statt eines stillen Wechsels auf Klartext (Downgrade durch einen Angreifer im Netz). Der Kern merkt es sich
	// ueber Neustarts (Remembered/Remember)
	tlsSeen atomic.Bool
}

// NewNUT prueft Adresse, Namen, Pin und Zugangsdaten (fragt noch nichts ab).
func NewNUT(cfg NUTConfig) (*NUT, error) {
	host, port, err := nutAddr(cfg.Address)
	if err != nil {
		return nil, err
	}
	pin, ok := proxmox.NormalizePin(cfg.Pin)
	if !ok {
		return nil, errors.New(model.T("monitor64.txt.pin_format"))
	}
	switch cfg.TLS {
	case NUTTLSAuto, NUTTLSRequire:
	case NUTTLSOff:
		if pin != "" {
			return nil, errors.New(model.T("monitor64.txt.pin_tls"))
		}
	default:
		return nil, errors.New(model.T("monitor64.txt.tls_mode_unknown", "v", cfg.TLS))
	}
	for _, u := range cfg.UPS {
		if !nutReName.MatchString(u) {
			return nil, errors.New(model.T("monitor64.txt.ups_name_invalid", "v", u))
		}
	}
	if strings.ContainsAny(cfg.User, "\r\n\x00") || strings.ContainsAny(cfg.Password, "\r\n\x00") {
		return nil, errors.New(model.T("monitor64.txt.cred_newline"))
	}
	if cfg.Password != "" && strings.TrimSpace(cfg.User) == "" {
		return nil, errors.New(model.T("monitor64.txt.pw_without_user"))
	}
	return &NUT{cfg: cfg, addr: net.JoinHostPort(host, port), host: host, pin: pin}, nil
}

// nutAddr: host[:port], nut://host[:port], [v6]:port bzw. v6 ohne Klammern.
func nutAddr(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	for _, p := range []string{"nut://", "tcp://"} {
		if len(s) > len(p) && strings.EqualFold(s[:len(p)], p) {
			s = s[len(p):]
		}
	}
	s = strings.TrimRight(s, "/")
	if s == "" {
		return "", "", errors.New(model.T("monitor64.txt.addr_missing"))
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.String(), nutDefaultPort, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		host, port = s, nutDefaultPort
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.ContainsAny(host, " /@?#") {
		return "", "", errors.New(model.T("monitor64.txt.addr_invalid", "addr", raw))
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", "", errors.New(model.T("monitor64.txt.port_invalid", "addr", raw))
	}
	return strings.ToLower(host), port, nil
}

func (n *NUT) timeout() time.Duration {
	if n.cfg.Timeout > 0 {
		return n.cfg.Timeout
	}
	return DefaultTimeout
}

func (n *NUT) secrets() []string { return []string{n.cfg.Password} }

// Remembered liefert, was sich der Kern ueber Neustarts merkt (Laufzeitstand des Zugangs): "tls:<adresse>", sobald
// upsd einmal STARTTLS angenommen hat (tlsSeen).
func (n *NUT) Remembered() []string {
	if n.tlsSeen.Load() {
		return []string{"tls:" + n.addr}
	}
	return nil
}

// Remember uebernimmt den gemerkten Stand nach einem Neustart: upsd unter dieser Adresse hat schon TLS gesprochen,
// eine spaetere Ablehnung von STARTTLS bleibt ein Fehler. Ein Stand fuer eine andere Adresse gilt nicht.
func (n *NUT) Remember(keys []string) {
	for _, k := range keys {
		if k == "tls:"+n.addr {
			n.tlsSeen.Store(true)
		}
	}
}

// Queries nennt die Befehle ("Was wird abgefragt?").
func (n *NUT) Queries() []string {
	q := []string{"STARTTLS (wenn angeboten)", "LIST UPS", "LIST VAR {ups}", "LOGOUT"}
	if n.cfg.User != "" {
		q = append([]string{"USERNAME/PASSWORD"}, q...)
	}
	return q
}

// nutConn ist eine Sitzung mit upsd.
type nutConn struct {
	c       net.Conn
	r       *bufio.Reader
	lines   int
	bytes   int
	tls     bool
	noLogin bool // Modus auto ohne STARTTLS: Anmeldung weggelassen
}

func (c *nutConn) send(cmd string) error {
	_, err := c.c.Write([]byte(cmd + "\n"))
	return err
}

// line liest eine Zeile (ohne Zeilenende); zu lange Zeilen, zu viele Zeilen und zu viele Bytes je Runde sind Fehler.
func (c *nutConn) line() (string, error) {
	c.lines++
	if c.lines > nutMaxLines {
		return "", errors.New(model.T("monitor64.txt.too_many_lines"))
	}
	b, err := c.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", errors.New(model.T("monitor64.txt.line_too_long"))
	}
	if err != nil {
		return "", err
	}
	c.bytes += len(b)
	if c.bytes > nutMaxBytes {
		return "", errors.New(model.T("monitor64.txt.resp_too_large"))
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// cmd sendet einen Befehl und erwartet eine Zeile; ERR … wird zum nutErr.
func (c *nutConn) cmd(cmd string) (string, error) {
	if err := c.send(cmd); err != nil {
		return "", err
	}
	l, err := c.line()
	if err != nil {
		return "", err
	}
	if e, ok := strings.CutPrefix(l, "ERR "); ok {
		return "", &nutErr{Code: strings.Fields(e + " x")[0]}
	}
	return l, nil
}

// nutErr ist eine Fehlerantwort von upsd (ERR <Code>).
type nutErr struct{ Code string }

func (e *nutErr) Error() string {
	if t, ok := nutErrText[e.Code]; ok {
		return e.Code + " (" + model.T(t) + ")"
	}
	return "ERR " + model.Raw(shortText(e.Code))
}

// nutErrText: Erklaerung zu den Fehlercodes von upsd.
var nutErrText = map[string]string{
	"ACCESS-DENIED": "monitor64.txt.nut_access_denied", "UNKNOWN-UPS": "monitor64.txt.nut_unknown_ups",
	"DATA-STALE": "monitor64.txt.nut_data_stale", "DRIVER-NOT-CONNECTED": "monitor64.txt.nut_driver_down",
	"INVALID-PASSWORD": "monitor64.txt.nut_bad_password", "INVALID-USERNAME": "monitor64.txt.nut_bad_user",
	"USERNAME-REQUIRED": "monitor64.txt.nut_user_required", "PASSWORD-REQUIRED": "monitor64.txt.nut_pw_required",
	"FEATURE-NOT-CONFIGURED": "monitor64.txt.nut_tls_unconfigured", "FEATURE-NOT-SUPPORTED": "monitor64.txt.nut_tls_unsupported",
}

// list liest eine Liste "BEGIN LIST <what>" … "END LIST <what>" und liefert die Zeilen dazwischen.
func (c *nutConn) list(what string, max int) ([][]string, error) {
	l, err := c.cmd("LIST " + what)
	if err != nil {
		return nil, err
	}
	if l != "BEGIN LIST "+what {
		return nil, errors.New(model.T("monitor64.txt.resp_unexpected", "v", shortText(l)))
	}
	var out [][]string
	for {
		l, err := c.line()
		if err != nil {
			return nil, err
		}
		if l == "END LIST "+what {
			return out, nil
		}
		if len(out) >= max {
			continue // weiterlesen bis zum Ende, aber nichts mehr merken
		}
		out = append(out, nutFields(l))
	}
}

// nutFields zerlegt eine Zeile in Woerter (in Anfuehrungszeichen mit \" und \\).
func nutFields(l string) []string {
	var out []string
	var b strings.Builder
	inQ, esc, has := false, false, false
	for _, r := range l {
		switch {
		case esc:
			b.WriteRune(r)
			esc = false
		case r == '\\' && inQ:
			esc = true
		case r == '"':
			inQ, has = !inQ, true
		case r == ' ' && !inQ:
			if has || b.Len() > 0 {
				out = append(out, b.String())
				b.Reset()
				has = false
			}
		default:
			b.WriteRune(r)
		}
	}
	if has || b.Len() > 0 {
		out = append(out, b.String())
	}
	return out
}

// nutQuote setzt einen Wert fuer upsd in Anfuehrungszeichen.
func nutQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// open baut die Sitzung auf (TCP, STARTTLS, Anmeldung). Fuer den Test liefert sie zusaetzlich das Ergebnis der
// Zertifikatspruefung (res mit NeedConfirm: abgebrochen, nichts gesendet).
func (n *NUT) open(ctx context.Context) (*nutConn, TestResult, error) {
	var res TestResult
	d := &net.Dialer{Timeout: nutDialTimeout}
	raw, err := d.DialContext(ctx, "tcp", n.addr)
	if err != nil {
		return nil, res, webClassify(err, n.addr)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(dl)
	}
	c := &nutConn{c: raw, r: bufio.NewReaderSize(raw, nutMaxLine)}
	fail := func(err error) (*nutConn, TestResult, error) {
		_ = raw.Close()
		return nil, res, err
	}
	need := n.cfg.TLS == NUTTLSRequire || n.pin != ""
	if n.cfg.TLS != NUTTLSOff {
		_, err := c.cmd("STARTTLS")
		var ne *nutErr
		switch {
		case err == nil:
			if c.r.Buffered() > 0 {
				return fail(errors.New(model.T("monitor64.txt.data_before_tls")))
			}
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: n.host, MinVersion: tls.VersionTLS12})
			if err := tc.HandshakeContext(ctx); err != nil {
				return fail(webClassify(err, n.addr))
			}
			leaf, trusted, err := leafOf(tc.ConnectionState(), n.host, n.roots, n.addr)
			if err != nil {
				_ = tc.Close()
				return nil, res, err
			}
			r, proceed := certResult(leaf, trusted, n.pin)
			res = r
			if !proceed {
				// Zertifikat nicht bestaetigt bzw. anders als gemerkt: nichts weiter senden
				_ = tc.Close()
				if r.NeedConfirm {
					return nil, res, errors.New(model.T("monitor64.txt.nut_cert_unconfirmed", "fp", r.Fingerprint))
				}
				return nil, res, errors.New(r.Error)
			}
			c.c, c.r, c.tls = tc, bufio.NewReaderSize(tc, nutMaxLine), true
			n.tlsSeen.Store(true)
		case errors.As(err, &ne) && !need && n.tlsSeen.Load():
			return fail(fmt.Errorf("STARTTLS: %w – %s", err, model.T("monitor64.txt.nut_tls_gone")))
		case errors.As(err, &ne) && !need:
			// upsd ohne TLS (nicht eingerichtet bzw. nicht gebaut): unverschluesselt weiter, aber ohne Anmeldung –
			// das Passwort geht nur bei ausdruecklich abgeschaltetem TLS im Klartext (zum Lesen ist keine noetig)
			c.noLogin = true
		case errors.As(err, &ne):
			return fail(fmt.Errorf("STARTTLS: %w", err))
		default:
			return fail(webClassify(err, n.addr))
		}
	}
	if u := strings.TrimSpace(n.cfg.User); u != "" && !c.noLogin {
		if _, err := c.cmd("USERNAME " + nutQuote(u)); err != nil {
			_ = c.c.Close()
			return nil, res, fmt.Errorf("USERNAME: %w", err)
		}
		if n.cfg.Password != "" {
			if _, err := c.cmd("PASSWORD " + nutQuote(n.cfg.Password)); err != nil {
				_ = c.c.Close()
				return nil, res, fmt.Errorf("PASSWORD: %w", err)
			}
		}
	}
	return c, res, nil
}

// close meldet sich ab (Antwort egal) und schliesst die Verbindung.
func (c *nutConn) close() {
	_ = c.c.SetDeadline(time.Now().Add(time.Second))
	_ = c.send("LOGOUT")
	_, _ = c.line()
	_ = c.c.Close()
}

// nutUPS ist eine USV aus LIST UPS mit ihren Variablen.
type nutUPS struct {
	Name, Desc string
	Vars       map[string]string
}

// fetch liest die USVs und ihre Variablen. Fehler einer einzelnen USV (DATA-STALE …) gehen an part.
func (n *NUT) fetch(c *nutConn, part *partial) ([]nutUPS, error) {
	rows, err := c.list("UPS", nutMaxUPS*4)
	if err != nil {
		return nil, fmt.Errorf("LIST UPS: %w", err)
	}
	want := map[string]bool{}
	for _, u := range n.cfg.UPS {
		want[u] = true
	}
	var out []nutUPS
	seen := map[string]bool{}
	for _, f := range rows {
		if len(f) < 2 || f[0] != "UPS" || seen[f[1]] {
			continue
		}
		name := f[1]
		if !nutReName.MatchString(name) {
			part.add("LIST UPS", errors.New(model.T("monitor64.txt.ups_name_skipped", "v", shortText(name))))
			continue
		}
		if len(want) > 0 && !want[name] {
			continue
		}
		seen[name] = true
		if len(out) >= nutMaxUPS {
			part.add("LIST UPS", errors.New(model.T("monitor64.txt.ups_too_many", "n", nutMaxUPS)))
			break
		}
		u := nutUPS{Name: name, Vars: map[string]string{}}
		if len(f) >= 3 {
			u.Desc = shortText(f[2])
		}
		vars, err := c.list("VAR "+name, nutMaxVars)
		if err != nil {
			var ne *nutErr
			if !errors.As(err, &ne) {
				return nil, fmt.Errorf("LIST VAR %s: %w", name, err) // Verbindung gestoert: Runde abbrechen
			}
			part.add("ups "+name, err, "ups:"+name)
			continue
		}
		for _, v := range vars {
			if len(v) >= 4 && v[0] == "VAR" && v[1] == name {
				u.Vars[v[2]] = v[3]
			}
		}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Collect ist eine Abfragerunde (nicht gleichzeitig mit sich selbst aufrufen).
func (n *NUT) Collect(ctx context.Context) ([]model.Service, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	c, _, err := n.open(ctx)
	if err != nil {
		return nil, scrubErr(err, n.secrets()...)
	}
	defer c.close()
	part := &partial{secrets: n.secrets()}
	list, err := n.fetch(c, part)
	if err != nil {
		return nil, scrubErr(err, n.secrets()...)
	}
	out := make([]model.Service, 0, len(list))
	for _, u := range list {
		out = append(out, nutService(u))
	}
	return out, part.result()
}

// Test prueft die Verbindung im Assistenten (Zertifikat bei STARTTLS, Anmeldung, USVs).
func (n *NUT) Test(ctx context.Context) TestResult {
	ctx, cancel := context.WithTimeout(ctx, n.timeout())
	defer cancel()
	c, res, err := n.open(ctx)
	if err != nil {
		if !res.NeedConfirm {
			res.Error = scrub(err.Error(), n.secrets()...)
		}
		return res
	}
	defer c.close()
	if v, err := c.cmd("VER"); err == nil {
		res.Version = shortText(v)
	}
	part := &partial{secrets: n.secrets()}
	list, err := n.fetch(c, part)
	if err != nil {
		res.Error = scrub(err.Error(), n.secrets()...)
		return res
	}
	res.OK = true
	var names []string
	for _, u := range list {
		names = append(names, u.Name+" ("+firstNonEmpty(u.Vars["ups.status"], "?")+")")
	}
	res.Summary = model.T("monitor64.txt.ups_count", "n", len(list))
	if len(names) > 0 {
		res.Summary += ": " + model.Raw(strings.Join(limitList(names, 5), ", "))
	}
	var warn []string
	if len(list) == 0 {
		warn = append(warn, model.T("monitor64.txt.nut_no_ups"))
	}
	if pe := part.result(); pe != nil {
		warn = append(warn, pe.Error())
	}
	if !c.tls {
		switch {
		case c.noLogin && n.cfg.User != "":
			warn = append(warn, model.T("monitor64.txt.nut_plain_nologin"))
		case n.cfg.Password != "":
			warn = append(warn, model.T("monitor64.txt.nut_plain_password"))
		default:
			warn = append(warn, model.T("monitor64.txt.nut_plain"))
		}
	}
	res.Warning = strings.Join(warn, "; ")
	return res
}

// nutStatusText: Woerter aus ups.status (BYPASS und ALARM heissen in beiden Sprachen gleich).
var nutStatusText = map[string]string{"OL": "monitor64.txt.ups_online", "OB": "monitor64.txt.ups_on_battery", "LB": "monitor64.txt.ups_low_battery",
	"HB": "monitor64.txt.ups_high_battery", "RB": "monitor64.txt.ups_replace_battery", "CHRG": "monitor64.txt.ups_charging",
	"DISCHRG": "monitor64.txt.ups_discharging", "CAL": "monitor64.txt.ups_calibrating", "OFF": "monitor64.txt.ups_off",
	"OVER": "monitor64.txt.ups_overload", "TRIM": "monitor64.txt.ups_trim", "BOOST": "monitor64.txt.ups_boost", "FSD": "monitor64.txt.ups_fsd_short",
	"WAIT": "monitor64.txt.ups_wait", "TEST": "monitor64.txt.ups_selftest"}

// nutStatusWord: ein Wort aus ups.status als Text.
func nutStatusWord(f string) string {
	switch f {
	case "BYPASS":
		return "Bypass"
	case "ALARM":
		return "Alarm"
	}
	if k, ok := nutStatusText[f]; ok {
		return model.T(k)
	}
	return model.Raw(shortText(f))
}

// nutNum liest eine Variable als Zahl (fehlt, kein Wert, NaN/Inf: false).
func nutNum(vars map[string]string, names ...string) (float64, bool) {
	for _, k := range names {
		v, ok := vars[k]
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		if err == nil && finite(f) {
			return f, true
		}
	}
	return 0, false
}

// minutesText: Restlaufzeit ("23 Min.", "1 Std. 5 Min."; uebersetzbar, als Parameter mit model.Sub).
func minutesText(sec float64) string {
	m := int(sec / 60)
	if m >= 60 {
		return model.T("monitor64.txt.dur_h_min", "h", m/60, "m", m%60)
	}
	return model.T("monitor64.txt.dur_min", "n", m)
}

// nutService baut den Dienst einer USV.
func nutService(u nutUPS) model.Service {
	v := u.Vars
	name := model.T("monitor64.svc.ups", "name", u.Name)
	if m := strings.TrimSpace(strings.TrimSpace(firstNonEmpty(v["device.mfr"], v["ups.mfr"])) + " " +
		strings.TrimSpace(firstNonEmpty(v["device.model"], v["ups.model"]))); m != "" {
		name += " (" + model.Raw(shortText(m)) + ")"
	} else if u.Desc != "" && u.Desc != "Unavailable" {
		name += " (" + model.Raw(u.Desc) + ")"
	}
	s := model.Service{Key: "ups:" + u.Name, Name: name, Kind: "ups", Default: true}
	flags := map[string]bool{}
	var words []string
	for _, f := range strings.Fields(v["ups.status"]) {
		f = strings.ToUpper(f)
		if flags[f] {
			continue
		}
		flags[f] = true
		words = append(words, nutStatusWord(f))
	}
	var parts []string
	if len(words) > 0 {
		parts = append(parts, strings.Join(words, ", "))
	} else {
		parts = append(parts, model.T("monitor64.txt.status_unknown"))
	}
	onBat := 0.0
	if flags["OB"] {
		onBat = 1
	}
	s.Metrics = append(s.Metrics, model.Metric{Name: "on_battery", Value: onBat})
	charge, hasCharge := nutNum(v, "battery.charge")
	if hasCharge {
		charge = min(max(charge, 0), 100)
		s.Metrics = append(s.Metrics, model.Metric{Name: "charge", Value: round2(charge), Unit: "%"})
		parts = append(parts, model.T("monitor64.txt.charge", "v", fmt.Sprintf("%.0f", charge)))
	}
	runtime, hasRun := nutNum(v, "battery.runtime")
	if hasRun && runtime >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "runtime", Value: round2(runtime), Unit: "s", Rule: ruleUPSRuntime})
		parts = append(parts, model.T("monitor64.txt.runtime", "v", model.Sub(minutesText(runtime))))
	}
	if load, ok := nutNum(v, "ups.load"); ok && load >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "load", Value: round2(load), Unit: "%"})
		parts = append(parts, model.T("monitor64.txt.load_pct", "v", fmt.Sprintf("%.0f", load)))
	}
	if p, ok := nutNum(v, "ups.realpower", "ups.power"); ok && p >= 0 {
		unit := "W"
		if _, real := v["ups.realpower"]; !real {
			unit = "VA"
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "power", Value: round2(p), Unit: unit})
	}
	if in, ok := nutNum(v, "input.voltage"); ok && in >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "input_voltage", Value: round2(in), Unit: "V"})
		parts = append(parts, model.T("monitor64.txt.input_v", "v", fmt.Sprintf("%.0f", in)))
	}
	if t, ok := nutNum(v, "ups.temperature", "battery.temperature"); ok && t > -40 && t < 150 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(t), Unit: "°C", Rule: model.RuleTemp})
		parts = append(parts, fmt.Sprintf("%.0f °C", t))
	}
	if a := strings.TrimSpace(v["ups.alarm"]); a != "" {
		parts = append(parts, "Alarm: "+model.Raw(shortText(a)))
	}
	if r := strings.TrimSpace(v["ups.test.result"]); r != "" && !strings.EqualFold(r, "No test initiated") {
		parts = append(parts, model.T("monitor64.txt.ups_selftest")+": "+model.Raw(shortText(r)))
	}
	batt := ""
	if hasCharge {
		batt = model.T("monitor64.txt.charge", "v", fmt.Sprintf("%.0f", charge))
	}
	if hasRun && runtime >= 0 {
		batt = strings.TrimPrefix(batt+", "+model.T("monitor64.txt.runtime", "v", model.Sub(minutesText(runtime))), ", ")
	}
	withBatt := func(t string) string {
		if batt != "" {
			return t + " (" + batt + ")"
		}
		return t
	}
	if flags["OB"] {
		s.Facts = append(s.Facts, model.Fact{Code: "ups_on_battery", Text: withBatt(model.T("monitor64.txt.ups_on_battery"))})
	}
	switch {
	case flags["FSD"]:
		s.Facts = append(s.Facts, model.Fact{Code: "ups_low_battery", Text: withBatt(model.T("monitor64.txt.ups_fsd"))})
	case flags["LB"]:
		s.Facts = append(s.Facts, model.Fact{Code: "ups_low_battery", Text: withBatt(model.T("monitor64.txt.ups_low_battery"))})
	}
	if flags["RB"] {
		s.Facts = append(s.Facts, model.Fact{Code: "ups_replace_battery", Text: model.T("monitor64.txt.ups_replace_battery")})
	}
	if flags["OVER"] {
		t := model.T("monitor64.txt.ups_overload")
		if load, ok := nutNum(v, "ups.load"); ok {
			t += " (" + model.T("monitor64.txt.load_pct", "v", fmt.Sprintf("%.0f", load)) + ")"
		}
		s.Facts = append(s.Facts, model.Fact{Code: "ups_overload", Text: t})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}
