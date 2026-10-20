package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultBase ist die Basis der Blocklisten auf ipv64.net (index.json und die Dateien daneben).
	DefaultBase = "https://ipv64.net/blocklists/"
	// EnvBase ueberschreibt die Basis (nur fuer Tests, http(s)-URL).
	EnvBase = "NODE64_IPV64_BLOCKLISTS"

	indexFile = "index.json"
	indexMax  = 4 << 20
	cacheFile = "country_ranges.txt.gz"
	metaFile  = "meta.json"

	refreshEvery = 24 * time.Hour // regulaer (auch nach 304)
	missingEvery = 6 * time.Hour  // Datei bei ipv64 (noch) nicht vorhanden
	errorEvery   = time.Hour      // sonstige Fehler
)

var geoFileRe = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,99}\.txt\.gz$`)

// errMissing: index.json ohne "geo" bzw. Datei mit 404 – kein Fehler, nur keine Laender.
var errMissing = errors.New("geoip: country file not available")

// Status ist der Stand der Laenderdaten (Oberflaeche, Info-Seite).
type Status struct {
	Loaded  bool      `json:"loaded"`
	Ranges4 int       `json:"ranges_v4"`
	Ranges6 int       `json:"ranges_v6"`
	Bytes   int       `json:"bytes"` // Speicherbedarf der Bereiche
	Updated time.Time `json:"updated,omitzero"`
	Error   string    `json:"error,omitempty"` // letzter Fehler (nicht bei fehlender Datei)
}

// meta ist der Stand des Zwischenspeichers (fuer bedingte Abrufe nach einem Neustart).
type meta struct {
	File         string    `json:"file"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched,omitzero"`
}

// DB haelt die Laenderdaten und laedt sie (eine Instanz je Prozess ueber Start; Tests legen eigene an).
type DB struct {
	dir    string // Zwischenspeicher ("" = keiner)
	base   string // mit "/" am Ende
	ua     string
	client *http.Client
	log    *slog.Logger

	tab atomic.Pointer[table]

	mu      sync.Mutex
	meta    meta
	lastErr string // zuletzt geloggter Fehler (kein Spam)
	missing bool   // Datei fehlte beim letzten Abruf (einmal geloggt)
}

// New legt eine DB an. dir = Zwischenspeicher (z. B. <data>/geoip, "" = keiner), base = Blocklisten-Basis
// ("" = DefaultBase), ua = User-Agent.
func New(dir, base, ua string, log *slog.Logger) *DB {
	if base == "" {
		base = DefaultBase
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	if log == nil {
		log = slog.Default()
	}
	return &DB{dir: dir, base: base, ua: ua, client: &http.Client{Timeout: 2 * time.Minute}, log: log.With("component", "geoip")}
}

// Lookup liefert den Laendercode (ISO 3166 alpha-2, gross) einer Adresse. ok = false fuer private, reservierte und
// unbekannte Adressen und solange keine Daten geladen sind.
func (d *DB) Lookup(a netip.Addr) (string, bool) {
	if d == nil {
		return "", false
	}
	c := d.tab.Load().lookup(a)
	if c == 0 {
		return "", false
	}
	return ccString(c), true
}

// Status liefert den Stand.
func (d *DB) Status() Status {
	if d == nil {
		return Status{}
	}
	var st Status
	if t := d.tab.Load(); t != nil {
		st = Status{Loaded: true, Ranges4: len(t.v4s), Ranges6: len(t.v6s), Bytes: t.bytes(), Updated: t.updated}
	}
	d.mu.Lock()
	st.Error = d.lastErr
	d.mu.Unlock()
	return st
}

// LoadCache laedt den Zwischenspeicher (beim Start; fehlt er, passiert nichts).
func (d *DB) LoadCache() error {
	if d.dir == "" {
		return nil
	}
	if raw, err := os.ReadFile(filepath.Join(d.dir, metaFile)); err == nil {
		var m meta
		if json.Unmarshal(raw, &m) == nil {
			d.mu.Lock()
			d.meta = m
			d.mu.Unlock()
		}
	}
	p := filepath.Join(d.dir, cacheFile)
	f, err := os.Open(p)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() > maxFile {
		return errTooLarge
	}
	t, _, err := parseGzip(io.LimitReader(f, maxFile))
	if err != nil {
		return err
	}
	t.updated = fi.ModTime()
	d.tab.Store(t)
	return nil
}

// get laedt base+rel. cond = bedingte Kopfzeilen (nil = keine). notModified = 304.
func (d *DB) get(ctx context.Context, rel string, cond *meta, max int64) (raw []byte, h http.Header, notModified bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.base+rel, nil)
	if err != nil {
		return nil, nil, false, err
	}
	if d.ua != "" {
		req.Header.Set("User-Agent", d.ua)
	}
	if cond != nil {
		if cond.ETag != "" {
			req.Header.Set("If-None-Match", cond.ETag)
		}
		if cond.LastModified != "" {
			req.Header.Set("If-Modified-Since", cond.LastModified)
		}
	}
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, nil, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotModified:
		return nil, resp.Header, true, nil
	case http.StatusNotFound, http.StatusGone:
		return nil, nil, false, errMissing
	default:
		return nil, nil, false, fmt.Errorf("geoip: %s: HTTP %d", rel, resp.StatusCode)
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "html") {
		return nil, nil, false, fmt.Errorf("geoip: %s: html answer", rel)
	}
	if resp.ContentLength > max {
		return nil, nil, false, errTooLarge
	}
	raw, err = io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, nil, false, err
	}
	if int64(len(raw)) > max {
		return nil, nil, false, errTooLarge
	}
	return raw, resp.Header, false, nil
}

// geoFile liest den Dateinamen aus index.json ("geo": {"file": …}).
func geoFile(raw []byte) (string, error) {
	var ix struct {
		Geo *struct {
			File string `json:"file"`
		} `json:"geo"`
	}
	if err := json.Unmarshal(raw, &ix); err != nil {
		return "", fmt.Errorf("geoip: index.json: %w", err)
	}
	if ix.Geo == nil || ix.Geo.File == "" {
		return "", errMissing
	}
	if !geoFileRe.MatchString(ix.Geo.File) || strings.Contains(ix.Geo.File, "..") {
		return "", fmt.Errorf("geoip: index.json: invalid file name %q", ix.Geo.File)
	}
	return ix.Geo.File, nil
}

// Refresh laedt index.json und die Laenderdatei (nur bei Aenderung). Bei Fehlern bleibt der bisherige Stand.
func (d *DB) Refresh(ctx context.Context) error {
	raw, _, _, err := d.get(ctx, indexFile, nil, indexMax)
	if err != nil {
		return err
	}
	file, err := geoFile(raw)
	if err != nil {
		return err
	}
	d.mu.Lock()
	m := d.meta
	d.mu.Unlock()
	var cond *meta
	if d.tab.Load() != nil && m.File == file {
		cond = &m
	}
	raw, h, same, err := d.get(ctx, file, cond, maxFile)
	if err != nil {
		return err
	}
	now := time.Now()
	if same {
		d.mu.Lock()
		d.meta.Fetched = now
		m = d.meta
		d.mu.Unlock()
		d.writeMeta(m)
		return nil
	}
	t, skipped, err := parseGzip(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	t.updated = now
	d.tab.Store(t)
	m = meta{File: file, ETag: h.Get("ETag"), LastModified: h.Get("Last-Modified"), Fetched: now}
	d.mu.Lock()
	d.meta = m
	d.mu.Unlock()
	d.writeCache(raw)
	d.writeMeta(m)
	d.log.Info("country data loaded", "ranges_v4", len(t.v4s), "ranges_v6", len(t.v6s), "bytes", t.bytes(), "skipped_lines", skipped)
	return nil
}

func (d *DB) writeFile(name string, raw []byte) {
	if d.dir == "" {
		return
	}
	if err := os.MkdirAll(d.dir, 0o750); err != nil {
		d.log.Debug("geoip cache dir", "err", err)
		return
	}
	p := filepath.Join(d.dir, name)
	if err := os.WriteFile(p+".tmp", raw, 0o640); err != nil {
		d.log.Debug("geoip cache write", "err", err)
		return
	}
	_ = os.Rename(p+".tmp", p)
}

func (d *DB) writeCache(raw []byte) { d.writeFile(cacheFile, raw) }

func (d *DB) writeMeta(m meta) {
	if raw, err := json.Marshal(m); err == nil {
		d.writeFile(metaFile, raw)
	}
}

// report loggt das Ergebnis eines Abrufs ohne Wiederholungen und liefert den Abstand bis zum naechsten.
func (d *DB) report(err error) time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case err == nil:
		if d.lastErr != "" || d.missing {
			d.log.Info("country data available again")
		}
		d.lastErr, d.missing = "", false
		return refreshEvery
	case errors.Is(err, errMissing):
		if !d.missing {
			d.log.Debug("country data not available on ipv64.net yet")
		}
		d.missing, d.lastErr = true, ""
		return missingEvery
	default:
		if msg := err.Error(); msg != d.lastErr {
			d.log.Warn("country data not loaded", "err", err)
			d.lastErr = msg
		}
		return errorEvery
	}
}

// run laedt den Zwischenspeicher, dann von ipv64.net und danach regelmaessig, bis ctx endet.
func (d *DB) run(ctx context.Context) {
	if err := d.LoadCache(); err != nil {
		d.log.Warn("country data cache not readable", "err", err)
	}
	for {
		err := d.Refresh(ctx)
		if ctx.Err() != nil {
			return
		}
		wait := d.report(err)
		wait += rand.N(wait / 24) // verteilt die Abrufe vieler Nodes
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// ---- eine Instanz je Prozess

var (
	cur   atomic.Pointer[DB]
	ctlMu sync.Mutex
	users int
	stop  context.CancelFunc
	done  chan struct{}
)

// baseFromEnv: Blocklisten-Basis aus der Umgebung (nur http/https), sonst DefaultBase.
func baseFromEnv() string {
	if v := strings.TrimSpace(os.Getenv(EnvBase)); strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "http://") {
		return v
	}
	return DefaultBase
}

// Start fordert die Laenderdaten an (z. B. Honeypot64 beim Modulstart). Der erste Aufruf laedt im Hintergrund
// (Zwischenspeicher unter <dataDir>/geoip, dann ipv64.net, danach taeglich); weitere Aufrufe zaehlen nur mit. Die
// gelieferte Funktion gibt die Anforderung zurueck (mehrfach aufrufbar); ohne Nutzer endet das Laden und die Daten
// werden freigegeben.
func Start(dataDir, userAgent string, log *slog.Logger) (release func()) {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	users++
	if users == 1 {
		dir := ""
		if dataDir != "" {
			dir = filepath.Join(dataDir, "geoip")
		}
		d := New(dir, baseFromEnv(), userAgent, log)
		ctx, cancel := context.WithCancel(context.Background())
		ch := make(chan struct{})
		stop, done = cancel, ch
		cur.Store(d)
		go func() { defer close(ch); d.run(ctx) }()
	}
	var once sync.Once
	return func() { once.Do(releaseOne) }
}

func releaseOne() {
	ctlMu.Lock()
	defer ctlMu.Unlock()
	if users == 0 {
		return
	}
	if users--; users > 0 {
		return
	}
	stop()
	<-done
	cur.Store(nil)
	stop, done = nil, nil
}

// Lookup liefert das Land einer Adresse aus den angeforderten Daten (siehe Start; ohne Start nie ein Land).
func Lookup(a netip.Addr) (string, bool) { return cur.Load().Lookup(a) }

// Current liefert den Stand der angeforderten Daten (ohne Start: leer).
func Current() Status { return cur.Load().Status() }
