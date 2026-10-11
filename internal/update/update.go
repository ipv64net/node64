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

// Newer sagt, ob a eine hoehere Version als b ist (1.2.3, v1.2.3, 1.2.3-dev).
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
	return false
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
