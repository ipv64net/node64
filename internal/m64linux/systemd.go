package m64linux

import (
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// ParseSystemdFailed liest "systemctl --failed --no-legend --plain" (erste Spalte = Unit).
func ParseSystemdFailed(b []byte) []string {
	out := []string{}
	for _, ln := range lines(b) {
		f := strings.Fields(ln)
		// aeltere systemd-Versionen setzen trotz --plain einen Punkt davor
		for len(f) > 0 && (f[0] == "●" || f[0] == "*" || f[0] == "x" || f[0] == "×") {
			f = f[1:]
		}
		if len(f) == 0 || !strings.Contains(f[0], ".") {
			continue
		}
		out = append(out, clip(f[0]))
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// ParseSystemdState liest "systemctl is-system-running" (running, degraded, starting, maintenance ...).
func ParseSystemdState(b []byte) string {
	l := lines(b)
	if len(l) == 0 {
		return ""
	}
	return clip(strings.TrimSpace(l[0]))
}

// newSystemd baut den Abschnitt aus beiden Ausgaben.
func newSystemd(failed, state []byte) *m64proto.Systemd {
	return &m64proto.Systemd{Failed: ParseSystemdFailed(failed), State: ParseSystemdState(state)}
}
