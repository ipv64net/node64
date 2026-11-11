package proxmox

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Pruefung der Angaben eines Systems (Adressen, Token, Pin, Docker-Host). Die Datenhaltung der frueheren Proxmox-VE- und
// Docker-Ueberwachung der Healthchecks (Tabellen pve_*, Regeln, Verlauf) gibt es seit Healthchecks 3.0.0 nicht mehr
// (nach Monitor64 umgezogen).

// FieldError ist ein Fehler in einem Eingabefeld; Key ist der i18n-Schluessel.
type FieldError struct{ Field, Key string }

const (
	DefaultInterval = 30
	MinInterval     = 15
	MaxInterval     = 300
	DefaultPort     = "8006"
	DefaultPortPBS  = "8007"
	maxAddresses    = 16
)

var (
	pveRePin = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NormalizeAddressFor: wie NormalizeAddress, ohne Port gilt der der Art (PBS 8007).
func NormalizeAddressFor(kind, s string) (string, bool) {
	if kind == KindPBS {
		return normalizeAddress(s, DefaultPortPBS)
	}
	return normalizeAddress(s, DefaultPort)
}

func normalizeAddress(s, defPort string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is6() { // IPv6 ohne Klammern (fd00::10), sonst gilt der letzte Block als Port
		s = "[" + a.String() + "]"
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	s = zoneEscape(s) // Link-Local mit Zone (fe80::1%eth0): in URLs als %25
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Hostname() == "" || u.User != nil {
		return "", false
	}
	port := u.Port()
	if port == "" {
		port = defPort
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return "", false
	}
	host := u.Hostname()
	zone := ""
	if i := strings.Index(host, "%"); i >= 0 { // Zone (Name der Schnittstelle) nicht klein schreiben
		host, zone = host[:i], "%25"+host[i+1:]
	}
	return "https://" + strings.Replace(net.JoinHostPort(strings.ToLower(host)+zone, port), "%2525", "%25", 1), true
}

// zoneEscape: in "[fe80::1%eth0]" die Zone als "%25eth0" schreiben (url.Parse verlangt das), schon kodierte bleiben.
func zoneEscape(s string) string {
	i, j := strings.Index(s, "["), strings.Index(s, "]")
	if i < 0 || j < i {
		return s
	}
	h := s[i+1 : j]
	k := strings.Index(h, "%")
	if k < 0 || strings.HasPrefix(h[k:], "%25") {
		return s
	}
	return s[:i+1] + h[:k] + "%25" + h[k+1:] + s[j:]
}

// NormalizePin entfernt Doppelpunkte/Leerzeichen und prueft den Fingerabdruck (64 hex, leer = System-CA).
func NormalizePin(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	return s, s == "" || pveRePin.MatchString(s)
}
