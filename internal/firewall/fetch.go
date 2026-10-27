package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/shield"
)

// Laden der Listen von ipv64.net, wie PROXY64 (internal/cdn64/blindex.go, blocklist_live.go): index.json sagt, welche
// Datei zu einer Liste gehoert und welche Kategorie sie hat. Listen der Kategorie honeypot (v64 …) gibt es mit
// Listen-Token live unter live/<token>/<datei>; 401/403/404 -> Rueckfall auf den Tagesstand, Kopfzeile
// X-IPv64-List: daily = Token ohne Berechtigung (ipv64 liefert den Tagesstand). Geladen wird nur bei Aenderung
// (If-None-Match/If-Modified-Since, gilt nur fuer dieselbe Adresse); die letzte Fassung liegt im Cache-Ordner, damit
// der Schutz nach einem Neustart ohne Netz sofort steht.

const (
	indexFile   = "index.json"
	indexMax    = 4 << 20
	listMax     = 32 << 20 // je Liste
	catHoneypot = "honeypot"
	listHeader  = "X-IPv64-List" // "daily": Token ohne Berechtigung, Tagesstand
)

var (
	// IDRe: Kennung einer Liste in index.json (v64, ai_bots, …).
	IDRe   = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	fileRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\.txt$`)
	// TokenRe: Format der Listen-Token (32 Zeichen, docs/PLAN-NODE64-HONEYPOT64.md Abschnitt 8).
	TokenRe = regexp.MustCompile(`^[A-Za-z0-9]{32}$`)
)

// indexEntry: was der Helfer aus index.json braucht.
type indexEntry struct {
	File     string
	Category string
}

// parseIndex liest index.json (Listen und Gesamtlisten).
func parseIndex(raw []byte) (map[string]indexEntry, error) {
	type entry struct {
		ID       string `json:"id"`
		Category string `json:"category"`
		Files    struct {
			All string `json:"all"`
		} `json:"files"`
	}
	var ix struct {
		Lists    []entry `json:"lists"`
		Combined []entry `json:"combined"`
	}
	if err := json.Unmarshal(raw, &ix); err != nil {
		return nil, err
	}
	out := map[string]indexEntry{}
	for _, e := range append(ix.Combined, ix.Lists...) {
		if !IDRe.MatchString(e.ID) || !fileRe.MatchString(e.Files.All) {
			continue
		}
		if _, dup := out[e.ID]; !dup {
			out[e.ID] = indexEntry{File: e.Files.All, Category: e.Category}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("index without lists")
	}
	return out, nil
}

// fallbackEntry gilt, solange index.json nicht geladen ist: Dateiname nach dem Schema des Generators.
func fallbackEntry(id string) indexEntry {
	e := indexEntry{File: "ipv64_blocklist_" + id + ".txt"}
	if id == "v64" || strings.HasPrefix(id, "v64_") {
		e.Category = catHoneypot
	}
	return e
}

// httpError: Antwort von ipv64 ausser 200/304.
type httpError int

func (e httpError) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }

// mask entfernt das Token aus einer Fehlermeldung (die URL des Live-Abrufs steht in Fehlern des HTTP-Clients).
func mask(err error, tok string) error {
	if err == nil || tok == "" || !strings.Contains(err.Error(), tok) {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), tok, "***"))
}

// validator merkt sich ETag und Last-Modified einer Adresse.
type validator struct {
	rel, etag, modified string
}

// get laedt rel (relativ zur Basis-URL), nur bei Aenderung, wenn have (Daten fuer key vorhanden) und rel gleich
// der zuletzt geladenen Adresse ist. list = Kopfzeile X-IPv64-List.
func (h *Helper) get(ctx context.Context, rel, key string, have bool, maxLen int64) (raw []byte, list string, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.cfg.Base+rel, nil)
	if err != nil {
		return nil, "", false, err
	}
	req.Header.Set("User-Agent", "Node64/"+h.cfg.Version)
	h.mu.Lock()
	if v, ok := h.valid[key]; ok && have && v.rel == rel {
		if v.etag != "" {
			req.Header.Set("If-None-Match", v.etag)
		}
		if v.modified != "" {
			req.Header.Set("If-Modified-Since", v.modified)
		}
	}
	h.mu.Unlock()
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	list = resp.Header.Get(listHeader)
	if resp.StatusCode == http.StatusNotModified {
		return nil, list, true, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, list, false, httpError(resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "html") {
		return nil, list, false, errors.New("no list (html answer)")
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, maxLen+1))
	if err != nil {
		return nil, list, false, err
	}
	if int64(len(raw)) > maxLen {
		return nil, list, false, errors.New("list too large")
	}
	h.mu.Lock()
	h.valid[key] = validator{rel: rel, etag: resp.Header.Get("ETag"), modified: resp.Header.Get("Last-Modified")}
	h.mu.Unlock()
	return raw, list, false, nil
}

// fetchIndex laedt index.json; bei Fehler bleibt die bisherige Zuordnung.
func (h *Helper) fetchIndex(ctx context.Context) error {
	h.mu.Lock()
	have := h.index != nil
	h.mu.Unlock()
	raw, _, same, err := h.get(ctx, indexFile, indexFile, have, indexMax)
	if err != nil || same {
		return err
	}
	ix, err := parseIndex(raw)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.index = ix
	h.mu.Unlock()
	return nil
}

// entry: Datei und Kategorie einer Liste (ok = false: index.json geladen, Liste dort unbekannt).
func (h *Helper) entry(id string) (indexEntry, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.index == nil {
		return fallbackEntry(id), true
	}
	e, ok := h.index[id]
	return e, ok
}

// fetchList laedt eine Liste: Kategorie honeypot mit Token live (Rueckfall Tagesstand), sonst den Tagesstand.
func (h *Helper) fetchList(ctx context.Context, id string) error {
	e, ok := h.entry(id)
	if !ok {
		return errors.New("list not in index.json")
	}
	tok := h.cfg.Token
	if tok == "" || e.Category != catHoneypot {
		return h.load(ctx, id, e.File, "daily")
	}
	err := h.load(ctx, id, "live/"+tok+"/"+e.File, "live")
	var he httpError
	if errors.As(err, &he) && (he == 401 || he == 403 || he == 404) {
		h.log.Warn("firewall: live list not allowed, loading daily list", "list", id, "err", "live: "+he.Error())
		err = h.load(ctx, id, e.File, "daily")
		h.setLiveErr(id, "live: "+he.Error())
		return err
	}
	return mask(err, tok)
}

// load laedt rel als Liste id; edition = erwartete Fassung (daily/live), X-IPv64-List: daily setzt den Tagesstand.
func (h *Helper) load(ctx context.Context, id, rel, edition string) error {
	h.mu.Lock()
	_, have := h.nets[id]
	h.mu.Unlock()
	raw, list, same, err := h.get(ctx, rel, id, have, listMax)
	if err != nil {
		return err
	}
	denied := strings.EqualFold(list, "daily") && edition == "live"
	if denied {
		edition = "daily"
	}
	if same {
		h.setList(id, nil, edition, denied, false)
		return nil
	}
	nets, err := shield.ParseList(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	if len(nets) == 0 && len(bytes.TrimSpace(raw)) > 0 {
		return errors.New("no addresses in the list")
	}
	h.writeCache(id, raw)
	h.setList(id, nets, edition, denied, true)
	return nil
}

// setList vermerkt eine geladene (changed) bzw. bestaetigte Liste.
func (h *Helper) setList(id string, nets []netip.Prefix, edition string, denied, changed bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if changed {
		h.nets[id] = nets
	}
	ls := h.listState(id)
	ls.Edition, ls.LiveDenied, ls.LiveError, ls.Error = edition, denied, "", ""
	ls.Entries = len(h.nets[id])
	ls.Updated = h.now()
}

func (h *Helper) setLiveErr(id, msg string) {
	h.mu.Lock()
	h.listState(id).LiveError = msg
	h.mu.Unlock()
}

// writeCache legt die Liste unter CacheDir/<id>.txt ab (leer = kein Cache).
func (h *Helper) writeCache(id string, raw []byte) {
	dir := h.cfg.CacheDir
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	p := filepath.Join(dir, id+".txt")
	if os.WriteFile(p+".tmp", raw, 0o640) == nil {
		_ = os.Rename(p+".tmp", p)
	}
}

// loadCache liest die zwischengespeicherten Listen (beim Start, bevor etwas geladen ist).
func (h *Helper) loadCache() {
	dir := h.cfg.CacheDir
	if dir == "" {
		return
	}
	for _, id := range h.cfg.Lists {
		raw, err := os.ReadFile(filepath.Join(dir, id+".txt"))
		if err != nil {
			continue
		}
		nets, err := shield.ParseList(bytes.NewReader(raw))
		if err != nil || (len(nets) == 0 && len(bytes.TrimSpace(raw)) > 0) {
			continue
		}
		h.mu.Lock()
		h.nets[id] = nets
		ls := h.listState(id)
		ls.Edition, ls.Entries = "cache", len(nets)
		h.mu.Unlock()
	}
}
