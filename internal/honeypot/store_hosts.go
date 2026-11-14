package honeypot

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
)

// Rangliste der angefragten Namen (#113): Host-Kopfzeile bzw. SNI der Anfragen an die Web-Falle und an den
// PROXY64-Koeder. Gezaehlt wird der Name ohne Port, klein geschrieben und ohne Punkt am Ende; reine IP-Adressen
// (Aufruf ohne Namen) zaehlen nicht mit.

// topHostsMin ist die Mindestlaenge der Rangliste (auch wenn die anderen Listen kuerzer sind).
const topHostsMin = 20

// hostName macht aus der Host-Kopfzeile den angefragten Namen ("" = kein Name, z. B. IP-Adresse).
func hostName(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		h = host
	}
	h = strings.TrimSuffix(strings.Trim(h, "[]"), ".")
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@") {
		return ""
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return ""
	}
	return h
}

// topHosts zaehlt die angefragten Namen ab from (hoechstens limit, nach Anzahl, dann Name).
func (s *Store) topHosts(ctx context.Context, from string, limit int) ([]Count, error) {
	raw, err := s.counts(ctx, `SELECT lower(host) AS k, COUNT(*) AS n, MAX(ts) FROM hp_events WHERE ts >= ? AND host <> '' GROUP BY k`, from)
	if err != nil {
		return nil, err
	}
	by := map[string]*Count{}
	for _, c := range raw {
		name := hostName(c.Key)
		if name == "" {
			continue
		}
		if x := by[name]; x != nil {
			x.Count += c.Count
			if c.Last.After(x.Last) {
				x.Last = c.Last
			}
			continue
		}
		by[name] = &Count{Key: name, Count: c.Count, Last: c.Last}
	}
	out := make([]Count, 0, len(by))
	for _, c := range by {
		out = append(out, *c)
	}
	slices.SortFunc(out, func(a, b Count) int {
		if a.Count != b.Count {
			if a.Count > b.Count {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Key, b.Key)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
