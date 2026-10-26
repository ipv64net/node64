// Package update prueft per Opt-in, ob eine neuere Version des Nodes
// verfuegbar ist. Es wird nur die Versionsdatei abgerufen, keine Telemetrie
// gesendet. Erwartetes Format unter der URL:
//
//	{"version": "1.2.3", "url": "https://...", "notes": "..."}
package update

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const DefaultURL = "https://ipv64.net/node64/latest.json"

// Info ist das Ergebnis einer Pruefung.
type Info struct {
	Version   string    `json:"version"`
	URL       string    `json:"url,omitempty"`
	Notes     string    `json:"notes,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
	Newer     bool      `json:"newer"`
}

// Checker ruft die Versionsdatei ab.
type Checker struct {
	URL     string
	Current string
	Client  *http.Client
}

func New(current string) *Checker {
	return &Checker{URL: DefaultURL, Current: current, Client: &http.Client{Timeout: 15 * time.Second}}
}

// Check holt die Versionsdatei und vergleicht mit der laufenden Version.
func (c *Checker) Check(ctx context.Context) (*Info, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "node64/"+c.Current)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var info Info
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info); err != nil {
		return nil, err
	}
	if info.Version == "" {
		return nil, errors.New("no version in response")
	}
	info.CheckedAt = time.Now().UTC()
	info.Newer = Newer(info.Version, c.Current)
	return &info, nil
}

// Newer sagt, ob a eine hoehere Version als b ist (1.2.3, v1.2.3, 0.12.0-alpha.16). Vorab-Kennungen zaehlen wie bei
// SemVer (0.12.0-alpha.15 < 0.12.0-alpha.16 < 0.12.0); Entwicklungsstaende (-dev) gelten als gleich mit ihrem Release.
func Newer(a, b string) bool {
	pa, pb := parse(a), parse(b)
	if pa == nil || pb == nil {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	ra, rb := pre(a), pre(b)
	if ra == "dev" || rb == "dev" || ra == rb {
		return false
	}
	if ra == "" || rb == "" { // ohne Vorab-Kennung ist neuer
		return ra == ""
	}
	return preLess(rb, ra)
}

// pre liefert die Vorab-Kennung ("alpha.16"; "dev" fuer Entwicklungsstaende, "" fuer Releases).
func pre(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	i := strings.IndexByte(v, '-')
	if i < 0 {
		return ""
	}
	p := v[i+1:]
	if p == "dev" || strings.HasPrefix(p, "dev.") || strings.HasSuffix(p, "-dev") {
		return "dev"
	}
	return p
}

// preLess vergleicht zwei Vorab-Kennungen nach SemVer: Teil fuer Teil, Zahlen numerisch und vor Text, kuerzer zuerst.
func preLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, ea := strconv.Atoi(pa[i])
		nb, eb := strconv.Atoi(pb[i])
		switch {
		case ea == nil && eb == nil:
			if na != nb {
				return na < nb
			}
		case ea == nil:
			return true
		case eb == nil:
			return false
		case pa[i] != pb[i]:
			return pa[i] < pb[i]
		}
	}
	return len(pa) < len(pb)
}

func parse(v string) []int {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || parts[0] == "" {
		return nil
	}
	out := []int{0, 0, 0}
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}
