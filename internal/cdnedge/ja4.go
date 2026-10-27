package cdnedge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/fingerprint"
)

// JA4 (Abschnitt 3 und 8 von docs/PLAN-CDN64-SCHUTZ.md): Fingerabdruck des TLS-ClientHello auf Port 443, einmal je
// Verbindung aus den ohnehin gelesenen Bytes (handle443, alle Modi). Die Liste kommt aus der zentralen
// Honeypot64-Datenbank (ipv64_ja4.txt neben den Blocklisten). Je Name: off = nicht pruefen, count = nur zaehlen,
// block = Verbindung schliessen.

const (
	ja4Off   = "off"
	ja4Count = "count"
	ja4Block = "block"

	ja4File   = "ipv64_ja4.txt"
	ja4Max    = 1000 // Eintraege der Liste
	ja4TopMax = 20   // gemeldete JA4 je Name und Meldung
)

// ja4Set: JA4 der Liste (ohne Praefix "ja4:").
type ja4Set map[string]struct{}

// ja4Entry: ein Eintrag von ja4_top in edge/report.
type ja4Entry struct {
	JA4  string `json:"ja4"`
	Hits int64  `json:"hits"`
}

// ja4Mode: Wert aus edge/config (fehlt oder unbekannt = count).
func ja4Mode(v string) string {
	switch v {
	case ja4Off, ja4Block:
		return v
	}
	return ja4Count
}

// ja4Check prueft das ClientHello (data aus edge.PeekHello) gegen die Liste und zaehlt Treffer beim Namen.
// true = Verbindung schliessen (Wert block).
func (s *Server) ja4Check(re *route, st *hostStat, data []byte, ip netip.Addr) bool {
	l := s.ja4List.Load()
	if re.JA4 == ja4Off || l == nil || len(*l) == 0 {
		return false
	}
	hello, _ := fingerprint.TLSHello(data)
	if hello == nil {
		return false
	}
	j := fingerprint.JA4(hello)
	if _, hit := (*l)[j]; !hit || j == "" {
		return false
	}
	st.ja4Hit(j)
	if re.JA4 != ja4Block {
		return false
	}
	st.block(bJA4, ip)
	return true
}

// parseJA4List: je Zeile ein JA4, # = Kommentar, hoechstens ja4Max; ungueltige Zeilen fallen weg.
func parseJA4List(b []byte) ja4Set {
	m := ja4Set{}
	for _, line := range strings.Split(string(b), "\n") {
		v := strings.ToLower(strings.TrimSpace(line))
		v = strings.TrimPrefix(v, "ja4:")
		if v == "" || v[0] == '#' || len(v) > 64 || strings.Trim(v, "abcdefghijklmnopqrstuvwxyz0123456789_") != "" {
			continue
		}
		if len(m) >= ja4Max {
			break
		}
		m[v] = struct{}{}
	}
	return m
}

// ja4Top: die haeufigsten JA4 einer Meldung (hoechstens ja4TopMax).
func ja4Top(m map[string]int64) []ja4Entry {
	if len(m) == 0 {
		return nil
	}
	out := make([]ja4Entry, 0, len(m))
	for k, v := range m {
		out = append(out, ja4Entry{JA4: k, Hits: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hits != out[j].Hits {
			return out[i].Hits > out[j].Hits
		}
		return out[i].JA4 < out[j].JA4
	})
	return out[:min(len(out), ja4TopMax)]
}

// ja4Loop laedt die Liste von ipv64.net (alle 30 Minuten, ETag, Zwischenspeicher in data_dir) - nur mit api_url
// (die Werte je Name kommen von ipv64).
func (s *Server) ja4Loop(ctx context.Context) {
	if s.cfg.APIURL == "" {
		return
	}
	path := filepath.Join(s.cfg.DataDir, "blocklists", ja4File)
	if b, err := os.ReadFile(path); err == nil { // sofort aus dem Zwischenspeicher
		l := parseJA4List(b)
		s.ja4List.Store(&l)
	}
	client := &http.Client{Timeout: 60 * time.Second}
	etag := ""
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		tag, err := s.fetchJA4(ctx, client, blocklistBase(s.cfg)+ja4File, etag, path)
		if err != nil && ctx.Err() == nil {
			s.log.Warn("ja4 list not loaded", "err", err)
		} else if err == nil && tag != etag {
			etag = tag
			if l := s.ja4List.Load(); l != nil {
				s.log.Info("ja4 list ready", "entries", len(*l))
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// fetchJA4 holt die Liste (If-None-Match etag), uebernimmt sie und legt sie unter path ab. Rueckgabe: neuer ETag
// (unveraendert bei 304).
func (s *Server) fetchJA4(ctx context.Context, client *http.Client, url, etag, path string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return etag, err
	}
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := client.Do(req)
	if err != nil {
		return etag, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return etag, nil
	}
	if resp.StatusCode != http.StatusOK {
		return etag, fmt.Errorf("ja4: http %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return etag, err
	}
	if bytes.Contains(bytes.ToLower(raw[:min(len(raw), 512)]), []byte("<html")) {
		return etag, fmt.Errorf("ja4: html instead of list")
	}
	l := parseJA4List(raw) // leer ist erlaubt (alles in den Ausnahmen)
	s.ja4List.Store(&l)
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	tmp := path + ".tmp"
	if os.WriteFile(tmp, raw, 0o640) == nil {
		_ = os.Rename(tmp, path)
	}
	return resp.Header.Get("ETag"), nil
}
