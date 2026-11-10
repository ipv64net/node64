package proxmox

import (
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Pruefung der Angaben eines Systems (Adressen, Token, Pin, Docker-Host). Die Datenhaltung der frueheren Proxmox-VE- und
// Docker-Ueberwachung der Healthchecks (Tabellen pve_*, Regeln, Verlauf) gibt es seit Healthchecks 3.0.0 nicht mehr
// (nach Monitor64 umgezogen).

// FieldError ist ein Fehler in einem Eingabefeld; Key ist der i18n-Schluessel.
type FieldError struct{ Field, Key string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Key }

func pveFerr(field, key string) error { return &FieldError{Field: field, Key: key} }

const (
	DefaultInterval = 30
	MinInterval     = 15
	MaxInterval     = 300
	DefaultPort     = "8006"
	DefaultPortPBS  = "8007"
	maxAddresses    = 16
)

var (
	pveReTokenID = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+![A-Za-z][A-Za-z0-9._-]*$`)
	pveRePin     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// NormalizeAddress prueft eine Adresse und liefert sie als https://host:port (ohne Pfad). Ohne Port gilt 8006.
func NormalizeAddress(s string) (string, bool) { return normalizeAddress(s, DefaultPort) }

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
		s = "[" + a.String() + "]" // mit Zone scheitert url.Parse unten: abgelehnt
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
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
	return "https://" + net.JoinHostPort(strings.ToLower(u.Hostname()), port), true
}

// NormalizePin entfernt Doppelpunkte/Leerzeichen und prueft den Fingerabdruck (64 hex, leer = System-CA).
func NormalizePin(s string) (string, bool) {
	s = strings.ToLower(strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.TrimSpace(s)))
	return s, s == "" || pveRePin.MatchString(s)
}

// SameEndpoint sagt, ob b dieselben Adressen (Reihenfolge egal) und denselben Pin hat wie a, beides normalisiert.
// Nur dann darf ein gespeichertes Secret fuer einen Test wiederverwendet werden (sonst ginge es an ein anderes Ziel).
func SameEndpoint(a, b *System) bool {
	norm := func(l []string) []string {
		var out []string
		for _, x := range l {
			if n, ok := NormalizeAddressFor(a.Kind, x); ok && !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
		slices.Sort(out)
		return out
	}
	pa, okA := NormalizePin(a.PinSHA256)
	pb, okB := NormalizePin(b.PinSHA256)
	return okA && okB && pa == pb && slices.Equal(norm(a.Addresses), norm(b.Addresses))
}

// ValidateSystem prueft und normalisiert ein System. isNew verlangt ein Secret (beim Aendern: leer = behalten).
// Docker-Hosts haben eine Adresse (unix://, tcp://, http(s)://, ssh://) und kein Token; Secret (Zugangsdaten als JSON) und
// Pin nur bei https:// und ssh:// (docker_remote.go).
func ValidateSystem(sys *System, isNew bool) error {
	sys.Name = strings.TrimSpace(sys.Name)
	if len(sys.Name) > 100 {
		return pveFerr("name", "pve.err.name")
	}
	switch sys.Kind {
	case "":
		sys.Kind = KindPVE
	case KindPVE, KindPBS:
	case KindDocker:
		return validateDocker(sys, isNew)
	default:
		return pveFerr("kind", "pve.err.kind")
	}
	var addrs []string
	have := map[string]bool{}
	for _, a := range sys.Addresses {
		if strings.TrimSpace(a) == "" {
			continue
		}
		n, ok := NormalizeAddressFor(sys.Kind, a)
		if !ok {
			return pveFerr("addresses", "pve.err.address")
		}
		if !have[n] {
			have[n] = true
			addrs = append(addrs, n)
		}
	}
	if len(addrs) == 0 || len(addrs) > maxAddresses {
		return pveFerr("addresses", "pve.err.address")
	}
	sys.Addresses = addrs
	sys.TokenID = strings.TrimSpace(sys.TokenID)
	if len(sys.TokenID) > 200 || !pveReTokenID.MatchString(sys.TokenID) {
		return pveFerr("token_id", "pve.err.token_id")
	}
	sys.Secret = strings.TrimSpace(sys.Secret)
	if (isNew && sys.Secret == "") || len(sys.Secret) > 256 || strings.ContainsAny(sys.Secret, " \t\r\n") {
		return pveFerr("secret", "pve.err.secret")
	}
	pin, ok := NormalizePin(sys.PinSHA256)
	if !ok {
		return pveFerr("pin_sha256", "pve.err.pin")
	}
	sys.PinSHA256 = pin
	if sys.Interval == 0 {
		sys.Interval = DefaultInterval
	}
	if sys.Interval < MinInterval || sys.Interval > MaxInterval {
		return pveFerr("interval", "pve.err.interval")
	}
	return nil
}

// validateDocker prueft einen Docker-Host (leere Adresse = Standard, NODE64_DOCKER_HOST bzw. der Socket). isNew verlangt
// bei ssh:// einen Schluessel (beim Aendern: leeres Secret = behalten).
func validateDocker(sys *System, isNew bool) error {
	var addrs []string
	for _, a := range sys.Addresses {
		if a = strings.TrimSpace(a); a != "" {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) == 0 {
		addrs = []string{DefaultDockerHost()}
	}
	if len(addrs) != 1 || len(addrs[0]) > 300 || !ValidDockerHost(addrs[0]) {
		return pveFerr("addresses", "pve.err.docker_host")
	}
	sys.Addresses = addrs
	sys.TokenID = ""
	if !DockerUsesSecret(addrs[0]) {
		sys.Secret, sys.PinSHA256 = "", ""
	} else {
		pin, ok := NormalizeDockerPin(sys.PinSHA256)
		if !ok {
			return pveFerr("pin_sha256", "pve.err.pin")
		}
		sys.PinSHA256 = pin
		if DockerScheme(addrs[0]) == "ssh" && pin == "" {
			return pveFerr("pin_sha256", "docker.err.hostkey")
		}
		if len(sys.Secret) > dockerMaxSecret {
			return pveFerr("key", "docker.err.key")
		}
		if sys.Secret != "" || (isNew && DockerScheme(addrs[0]) == "ssh") {
			if err := validateDockerCreds(addrs[0], ParseDockerCreds(sys.Secret)); err != nil {
				return err
			}
		}
	}
	if sys.Interval == 0 {
		sys.Interval = DefaultInterval
	}
	if sys.Interval < MinInterval || sys.Interval > MaxInterval {
		return pveFerr("interval", "pve.err.interval")
	}
	return nil
}

var reUID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ValidUID: Kennung eines Systems (32 hex).
func ValidUID(uid string) bool { return reUID.MatchString(uid) }

var pveReKey = regexp.MustCompile(`^(node/[A-Za-z0-9._-]{1,64}|(qemu|lxc)/[1-9][0-9]{0,9}|docker/[A-Za-z0-9][A-Za-z0-9_.-]{0,127})$`)

// ValidKey sagt, ob key eine Ebene bezeichnet ("" = System).
func ValidKey(key string) bool { return key == "" || pveReKey.MatchString(key) }
