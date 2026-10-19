package filter

import (
	"strings"

	"golang.org/x/net/idna"
)

type ruleKind uint8

const (
	ruleNone     ruleKind = iota
	ruleExact             // blocks exactly this name (hosts / plain domain lists)
	ruleWildcard          // blocks this name and all subdomains (||example.com^)
	ruleAllow             // exception for this name and all subdomains (@@||example.com^)
)

// hostsIgnore are entries every hosts file contains that must never be blocked.
var hostsIgnore = map[string]bool{
	"localhost":             true,
	"localhost.localdomain": true,
	"local":                 true,
	"broadcasthost":         true,
	"ip6-localhost":         true,
	"ip6-loopback":          true,
	"ip6-localnet":          true,
	"ip6-mcastprefix":       true,
	"ip6-allnodes":          true,
	"ip6-allrouters":        true,
	"ip6-allhosts":          true,
	"0.0.0.0":               true,
}

// parseLine understands the three formats used by common DNS blocklists:
// hosts files ("0.0.0.0 ads.example.com"), plain domain lists and the
// DNS-relevant subset of Adblock syntax ("||ads.example.com^"). Browser-only
// rules (paths, cosmetic filters, modifiers) are ignored.
func parseLine(line string) (string, ruleKind) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", ruleNone
	}
	switch line[0] {
	case '#', '!', '[':
		return "", ruleNone
	}

	if strings.HasPrefix(line, "@@||") {
		if d, ok := adblockDomain(line[4:]); ok {
			return d, ruleAllow
		}
		return "", ruleNone
	}
	if strings.HasPrefix(line, "||") {
		if d, ok := adblockDomain(line[2:]); ok {
			return d, ruleWildcard
		}
		return "", ruleNone
	}

	// Inline comments need whitespace before '#'; "example.com##.ad" is a
	// cosmetic browser rule and must not turn into a block of example.com.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		if i > 0 && (line[i-1] == ' ' || line[i-1] == '\t') {
			line = strings.TrimSpace(line[:i])
		} else {
			return "", ruleNone
		}
	}
	fields := strings.Fields(line)
	switch len(fields) {
	case 1:
		if rest, wild := strings.CutPrefix(fields[0], "*."); wild { // "*.example.com" = Domain samt Subdomains
			if d, ok := normalizeDomain(rest); ok {
				return d, ruleWildcard
			}
			return "", ruleNone
		}
		if d, ok := normalizeDomain(fields[0]); ok {
			return d, ruleExact
		}
	case 2:
		// hosts format; lists with several names per line are rare enough to skip
		if isSinkIP(fields[0]) && !hostsIgnore[strings.ToLower(fields[1])] {
			if d, ok := normalizeDomain(fields[1]); ok {
				return d, ruleExact
			}
		}
	}
	return "", ruleNone
}

// adblockDomain extracts the domain from the part after "||". Only rules that
// target a whole domain are accepted: "example.com^", optionally followed by
// "|" or the "$important" modifier.
func adblockDomain(s string) (string, bool) {
	end := strings.IndexByte(s, '^')
	if end < 0 {
		return "", false
	}
	switch rest := s[end+1:]; rest {
	case "", "|", "$important":
	default:
		return "", false
	}
	return normalizeDomain(strings.TrimPrefix(s[:end], "*."))
}

func isSinkIP(s string) bool {
	switch s {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:0":
		return true
	}
	return false
}

// ToASCII wandelt internationalisierte Namen (IDN, z. B. "bücher.example") in Punycode ("xn--bcher-kva.example")
// um, wie sie im DNS stehen; reine ASCII-Namen und ein fuehrendes "*." bleiben, wie sie sind. Ungueltige Namen
// kommen unveraendert zurueck (die Pruefung danach lehnt sie ab).
func ToASCII(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			ascii = false
			break
		}
	}
	if ascii {
		return s
	}
	wild, rest := "", s
	if strings.HasPrefix(s, "*.") {
		wild, rest = "*.", s[2:]
	}
	if a, err := idna.Lookup.ToASCII(strings.TrimSuffix(rest, ".")); err == nil {
		return wild + a
	}
	return s
}

// normalizeDomain lowercases and validates a hostname. It needs at least one
// dot so a stray word in a list cannot block a whole TLD by accident.
func normalizeDomain(s string) (string, bool) {
	s = strings.TrimSuffix(strings.ToLower(ToASCII(s)), ".")
	if len(s) < 3 || len(s) > 253 || !strings.Contains(s, ".") {
		return "", false
	}
	if s[0] == '.' || s[0] == '-' || strings.Contains(s, "..") {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' {
			continue
		}
		return "", false
	}
	return s, true
}
