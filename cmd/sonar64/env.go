package main

// Einstellung ueber Umgebungsvariablen (Vertrag Abschnitt 8). Alles wird streng geprueft; das Token erscheint nie
// in Meldungen oder im Log.

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/sonar"
)

// options ist das Ergebnis von loadEnv.
type options struct {
	Config     sonar.Config
	StatusAddr string     // leer = kein Mini-Status
	LogLevel   slog.Level // Standard info
	Warnings   []string   // fuer das Log nach dem Start
}

var (
	nodeTokenRe   = regexp.MustCompile(`^s64_[A-Za-z0-9]{40}$`)
	anchorTokenRe = regexp.MustCompile(`^s64a_[A-Za-z0-9]{40}$`)
	quietRe       = regexp.MustCompile(`^([0-9]{1,2})-([0-9]{1,2})$`)
)

// loadEnv liest die SONAR64_*-Variablen. Auch bei einem Fehler ist LogLevel gesetzt.
func loadEnv(getenv func(string) string) (options, error) {
	var o options
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }

	lvl, err := parseLogLevel(get("SONAR64_LOG_LEVEL"))
	o.LogLevel = lvl
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}

	c := &o.Config
	tok := get("SONAR64_TOKEN")
	switch {
	case tok == "":
		errs = append(errs, errors.New("SONAR64_TOKEN is required (create one on ipv64.net, \"My node\")"))
	case !nodeTokenRe.MatchString(tok) && !anchorTokenRe.MatchString(tok):
		errs = append(errs, errors.New("SONAR64_TOKEN has an invalid format (expected s64_ or s64a_ followed by 40 letters/digits)"))
	}
	c.Token = tok
	anchorTok := anchorTokenRe.MatchString(tok)

	switch m := strings.ToLower(get("SONAR64_MODE")); m {
	case "":
		c.Mode = "headless"
		if anchorTok {
			c.Mode = sonar.RoleAnchor
		}
	case "headless", sonar.RoleAnchor:
		c.Mode = m
	default:
		errs = append(errs, fmt.Errorf("SONAR64_MODE %q is invalid (headless or anchor)", m))
	}
	switch {
	case c.Mode == sonar.RoleAnchor && nodeTokenRe.MatchString(tok):
		errs = append(errs, errors.New("SONAR64_MODE=anchor needs an anchor token (s64a_), issued by ipv64.net"))
	case c.Mode == "headless" && anchorTok:
		errs = append(errs, errors.New("an anchor token (s64a_) needs SONAR64_MODE=anchor"))
	}

	if v := get("SONAR64_MEASURED"); v != "" {
		b, err := parseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("SONAR64_MEASURED: %w", err))
		}
		c.Measured = b
	}
	if c.Mode == sonar.RoleAnchor {
		c.Measured = true // Anker antworten immer
	}

	switch b := strings.ToLower(get("SONAR64_BUDGET")); b {
	case "":
		c.Budget = sonar.BudgetLow
	case sonar.BudgetLow, sonar.BudgetNormal, sonar.BudgetHigh:
		c.Budget = b
	case "großzügig":
		c.Budget = sonar.BudgetHigh
	default:
		errs = append(errs, fmt.Errorf("SONAR64_BUDGET %q is invalid (sparsam, normal or grosszuegig)", b))
	}

	if v := get("SONAR64_QUIET"); v != "" {
		q, err := parseQuiet(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("SONAR64_QUIET: %w", err))
		}
		c.Quiet = q
	}

	c.DataDir = get("SONAR64_DATA")
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if strings.ContainsRune(c.DataDir, 0) {
		errs = append(errs, errors.New("SONAR64_DATA is invalid"))
	}

	if v := get("SONAR64_STATUS"); v != "" {
		a, err := parseStatusAddr(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("SONAR64_STATUS: %w", err))
		}
		o.StatusAddr = a
	}

	if v := get("SONAR64_API"); v != "" {
		if err := checkAPIBase(v); err != nil {
			errs = append(errs, fmt.Errorf("SONAR64_API: %w", err))
		}
		c.APIBase = strings.TrimRight(v, "/")
		o.Warnings = append(o.Warnings, "SONAR64_API is set - only for tests ("+c.APIBase+")")
	}

	if v := get("SONAR64_PLAN_KEY"); v != "" {
		switch {
		case !validPubKey(v):
			errs = append(errs, errors.New("SONAR64_PLAN_KEY is not an Ed25519 public key (base64)"))
		case len(sonar.PlanKeys) > 0:
			o.Warnings = append(o.Warnings, "SONAR64_PLAN_KEY ignored - the plan keys are built in")
		default:
			c.PlanKeys = []string{v}
			o.Warnings = append(o.Warnings, "plan key from SONAR64_PLAN_KEY - only for tests/development")
		}
	}

	return o, errors.Join(errs...)
}

func parseLogLevel(v string) (slog.Level, error) {
	switch strings.ToLower(v) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, fmt.Errorf("SONAR64_LOG_LEVEL %q is invalid (debug, info, warn, error)", v)
}

func parseBool(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, fmt.Errorf("%q is not 0 or 1", v)
}

// parseQuiet liest "23-6" (Stunden [von, bis) in lokaler Zeit).
func parseQuiet(v string) ([2]int, error) {
	m := quietRe.FindStringSubmatch(v)
	if m == nil {
		return [2]int{}, fmt.Errorf("%q is invalid (hours from-to, e.g. 23-6)", v)
	}
	a, _ := strconv.Atoi(m[1])
	b, _ := strconv.Atoi(m[2])
	if a > 23 || b > 23 || a == b {
		return [2]int{}, fmt.Errorf("%q is invalid (hours 0..23, from != to)", v)
	}
	return [2]int{a, b}, nil
}

// parseStatusAddr nimmt ":8064", "127.0.0.1:8064", "[::1]:8064" oder nur "8064".
func parseStatusAddr(v string) (string, error) {
	if _, err := strconv.Atoi(v); err == nil {
		v = ":" + v
	}
	host, port, err := net.SplitHostPort(v)
	if err != nil {
		return "", fmt.Errorf("%q is not host:port", v)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return "", fmt.Errorf("port %q is invalid", port)
	}
	if host != "" && net.ParseIP(host) == nil && host != "localhost" {
		return "", fmt.Errorf("host %q must be an IP address or localhost", host)
	}
	return net.JoinHostPort(host, port), nil
}

// checkAPIBase erlaubt https, http nur zu Loopback (Tests).
func checkAPIBase(v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		// Wert nicht wiederholen: er koennte Zugangsdaten enthalten (user:pass@, ?key=)
		return errors.New("not a valid URL (scheme://host/path, without user, query or fragment)")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil
		}
		return errors.New("http only for loopback, otherwise https")
	}
	return fmt.Errorf("scheme %q is not allowed", u.Scheme)
}

func validPubKey(v string) bool {
	b, err := base64.StdEncoding.DecodeString(v)
	return err == nil && len(b) == 32
}
