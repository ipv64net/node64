package model

import (
	"net/netip"
	"strings"
)

// URLHostV6 macht den Host-Teil einer Adresse URL-tauglich fuer IPv6: eine IPv6-Adresse ohne Klammern kommt in
// Klammern, eine Zone (Link-Local, "%eth0") wird als "%25" geschrieben. Gilt mit und ohne Schema, Benutzer, Port und
// Pfad: "fd00::1" -> "[fd00::1]", "https://fd00::1" -> "https://[fd00::1]", "ssh://u@fd00::1/x" -> "ssh://u@[fd00::1]/x",
// "[fe80::1%eth0]:8006" -> "[fe80::1%25eth0]:8006". Namen, IPv4 und alles Unklare bleiben, wie sie sind
// ("fd00::1:9100" ist eine Adresse, kein Port – ein Port braucht die Klammern).
func URLHostV6(s string) string {
	scheme, rest := "", s
	if i := strings.Index(s, "://"); i >= 0 {
		scheme, rest = s[:i+3], s[i+3:]
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	auth, tail := rest[:end], rest[end:]
	user := ""
	if i := strings.LastIndex(auth, "@"); i >= 0 {
		user, auth = auth[:i+1], auth[i+1:]
	}
	isV6 := func(a string) bool {
		ip, err := netip.ParseAddr(strings.Replace(a, "%25", "%", 1))
		return err == nil && ip.Is6()
	}
	zone := func(a string) string {
		if i := strings.Index(a, "%"); i >= 0 && !strings.HasPrefix(a[i:], "%25") {
			return a[:i] + "%25" + a[i+1:]
		}
		return a
	}
	switch {
	case strings.HasPrefix(auth, "["):
		i := strings.Index(auth, "]")
		if i < 0 || !isV6(auth[1:i]) {
			return s
		}
		auth = "[" + zone(auth[1:i]) + "]" + auth[i+1:]
	case isV6(auth):
		auth = "[" + zone(auth) + "]"
	default:
		return s
	}
	return scheme + user + auth + tail
}

// NoZone entfernt die Zone einer IPv6-Adresse ("fe80::1%eth0" -> "fe80::1"); fuer Namen im Zertifikat.
func NoZone(host string) string {
	if i := strings.Index(host, "%"); i >= 0 {
		return host[:i]
	}
	return host
}
