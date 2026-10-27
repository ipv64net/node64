package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// index.json von ipv64.net: welche Listen es gibt (Name, Kategorie, Lizenz, Datei) und welche Laender. Neue Listen
// auf ipv64.net erscheinen so ohne Update von Node64. Geladen wie die Listen (nur bei Aenderung, zwischengespeichert);
// fehlt sie, gilt die feste Liste Blocklists.

const (
	blIndexFile = "index.json"
	blIndexMax  = 4 << 20
)

type blIndexEntry struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Source      string `json:"source"`
	License     string `json:"license"`
	Files       struct {
		All string `json:"all"`
	} `json:"files"`
}

type blIndex struct {
	Lists     []blIndexEntry `json:"lists"`
	Combined  []blIndexEntry `json:"combined"`
	Countries []struct {
		Country string `json:"country"`
		Name    string `json:"name"`
	} `json:"countries"`
}

// geoCountry ist ein Land zur Auswahl (Laendersperre).
type geoCountry struct {
	Code string `json:"code"`
	Name string `json:"name"`
}

var (
	blIDRe   = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	blFileRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}\.txt$`)
)

// parseBlIndex: Auswahl fuer CDN64, Gesamtlisten zuerst. DoH-Server fehlen: die Liste ist zum Sperren ausgehender
// Verbindungen im eigenen Netz, nicht fuer Besucher eines Proxys.
func parseBlIndex(raw []byte) ([]BlocklistInfo, []geoCountry, error) {
	var ix blIndex
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, nil, err
	}
	var out []BlocklistInfo
	seen := map[string]bool{}
	nComb := 0 // Gesamtlisten vorne
	for i, e := range append(append([]blIndexEntry{}, ix.Combined...), ix.Lists...) {
		if !blIDRe.MatchString(e.ID) || !blFileRe.MatchString(e.Files.All) || strings.HasPrefix(e.Files.All, ".") || seen[e.ID] || e.Category == "doh" {
			continue
		}
		seen[e.ID] = true
		info := BlocklistInfo{ID: e.ID, Name: trunc(e.Name, 60), File: e.Files.All, Category: trunc(e.Category, 20), Text: trunc(e.Description, 300),
			License: trunc(e.License, 100)}
		if strings.HasPrefix(e.Source, "https://") {
			info.Source = trunc(e.Source, 300)
		}
		if n, ok := blKnown[e.ID]; ok {
			info.Name, info.Desc = n, "cdn64.bl.desc."+e.ID
		}
		if info.Name == "" {
			info.Name = e.ID
		}
		out = append(out, info)
		if i < len(ix.Combined) {
			nComb = len(out)
		}
	}
	if len(out) == 0 {
		return nil, nil, errors.New("index without lists")
	}
	// v64 Blocklist (eigene Liste von ipv64.net) direkt hinter die Gesamtlisten, nicht ans Ende
	if i := slices.IndexFunc(out, func(b BlocklistInfo) bool { return b.ID == "v64" }); i > nComb {
		v := out[i]
		out = slices.Insert(slices.Delete(out, i, i+1), nComb, v)
	}
	var cc []geoCountry
	for _, c := range ix.Countries {
		if code := strings.ToUpper(c.Country); geoCodeRe.MatchString(code) {
			cc = append(cc, geoCountry{Code: code, Name: trunc(c.Name, 80)})
		}
	}
	return out, cc, nil
}

func (m *Module) blSetIndex(cat []BlocklistInfo, cc []geoCountry) {
	m.bl.mu.Lock()
	m.bl.catalog, m.bl.countries = cat, cc
	m.bl.mu.Unlock()
}

// blLoadIndexCache: zwischengespeicherte index.json (beim Start, vor den Listen).
func (m *Module) blLoadIndexCache() {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	raw, err := os.ReadFile(filepath.Join(dir, blIndexFile))
	if err != nil {
		return
	}
	if cat, cc, err := parseBlIndex(raw); err == nil {
		m.blSetIndex(cat, cc)
	}
}

// blGet laedt eine Datei von ipv64.net, nur bei Aenderung (ETag unter key). notModified = Stand ist aktuell.
func (m *Module) blGet(ctx context.Context, rel, key string, have bool, max int64) (raw []byte, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.bl.base+rel, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", "Node64/"+m.version)
	m.bl.mu.Lock()
	if e := m.bl.etag[key]; e != "" && have {
		req.Header.Set("If-None-Match", e)
	}
	m.bl.mu.Unlock()
	resp, err := m.bl.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		return nil, false, errors.New("no list (html answer)")
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(raw)) > max {
		return nil, false, errors.New("list too large")
	}
	m.bl.mu.Lock()
	m.bl.etag[key] = resp.Header.Get("ETag")
	m.bl.mu.Unlock()
	return raw, false, nil
}

// blCacheWrite legt eine Datei unter /data/cdn64/blocklists ab (rel z. B. "index.json", "countries/DE.txt").
func (m *Module) blCacheWrite(rel string, raw []byte) {
	dir := m.blCacheDir()
	if dir == "" {
		return
	}
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return
	}
	if os.WriteFile(p+".tmp", raw, 0o640) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// blFetchIndex laedt index.json; bei Fehler bleibt die bisherige Auswahl.
func (m *Module) blFetchIndex(ctx context.Context) error {
	m.bl.mu.Lock()
	have := len(m.bl.catalog) > 0
	m.bl.mu.Unlock()
	raw, same, err := m.blGet(ctx, blIndexFile, blIndexFile, have, blIndexMax)
	if err != nil || same {
		return err
	}
	cat, cc, err := parseBlIndex(raw)
	if err != nil {
		return err
	}
	m.blCacheWrite(blIndexFile, raw)
	m.blSetIndex(cat, cc)
	return nil
}
