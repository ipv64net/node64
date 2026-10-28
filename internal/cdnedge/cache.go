package cdnedge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/httpcompress"
)

// Cache fuer Modus 3 (wie proxy_cache im alten CDN): nur GET/HEAD ohne Anmeldung, nur Antworten 200, die das Ziel
// selbst als cachebar markiert (Cache-Control max-age/s-maxage oder Expires, nicht private/no-store/no-cache, kein
// Set-Cookie, Vary hoechstens Accept-Encoding). Eine Anfrage mit Cache-Control geht immer zum Ziel. Groesse je Name
// (cache_mb, Grenze der Klasse kommt von ipv64), ungenutzte Eintraege fallen nach cache_minutes weg. Ablage auf der
// Platte in data_dir/cache (beim Start geleert). Kopf X-Proxy-Cache: HIT bzw. MISS.

const cacheMaxObject = 8 << 20

type respCache struct {
	dir   string
	max   int64 // alle Namen zusammen (cache_total_mb)
	mu    sync.Mutex
	total int64
	hosts map[int]*hostCache
}

type hostCache struct {
	size  int64
	items map[string]*cacheItem
}

type cacheItem struct {
	file    string
	size    int64
	expires time.Time
	used    time.Time
	header  http.Header
}

func newRespCache(dir string, maxMB int) *respCache {
	if dir != "" {
		_ = os.RemoveAll(dir)
		_ = os.MkdirAll(dir, 0o700)
	}
	if maxMB <= 0 {
		maxMB = 4096
	}
	return &respCache{dir: dir, max: int64(maxMB) << 20, hosts: map[int]*hostCache{}}
}

// cacheKey: Name, Pfad und Abfrage, dazu das Verfahren, das der Server waehlen wuerde, und die Komprimierungen, die der
// Browser annimmt (fuer Ziele, die selbst komprimieren; httpcompress.CacheVariant) - statt der ganzen
// Accept-Encoding-Zeile (zu viele Fassungen).
func cacheKey(r *http.Request) string {
	h := sha256.Sum256([]byte(hostOnly(r.Host) + " " + r.URL.RequestURI() + " " + httpcompress.CacheVariant(r.Header.Get("Accept-Encoding"))))
	return hex.EncodeToString(h[:])
}

// cacheable: Antwort darf in den Cache; ttl aus den Koepfen des Ziels.
func cacheable(status int, h http.Header, now time.Time) (time.Duration, bool) {
	if status != http.StatusOK || h.Get("Set-Cookie") != "" {
		return 0, false
	}
	if v := strings.ToLower(h.Get("Vary")); v != "" && v != "accept-encoding" {
		return 0, false
	}
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") {
		return 0, false
	}
	for _, d := range []string{"s-maxage=", "max-age="} {
		if i := strings.Index(cc, d); i >= 0 {
			v := cc[i+len(d):]
			if j := strings.IndexAny(v, ", "); j >= 0 {
				v = v[:j]
			}
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				return time.Duration(n) * time.Second, true
			}
			return 0, false
		}
	}
	if e, err := http.ParseTime(h.Get("Expires")); err == nil && e.After(now) {
		return e.Sub(now), true
	}
	return 0, false
}

// serveCached: aus dem Cache oder ueber next (und dabei, wenn erlaubt, ablegen).
func (s *Server) serveCached(w http.ResponseWriter, r *http.Request, re *route, next http.Handler) {
	t := re.Target
	if s.cache == nil || t == nil || t.cacheMB <= 0 || (r.Method != http.MethodGet && r.Method != http.MethodHead) ||
		r.Header.Get("Cache-Control") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Upgrade") != "" || r.Header.Get("Range") != "" {
		next.ServeHTTP(w, r)
		return
	}
	key, ae := cacheKey(r), r.Header.Get("Accept-Encoding")
	now := time.Now()
	if it, f := s.cache.get(re.HostID, key, now); it != nil && !httpcompress.Acceptable(ae, it.header.Get("Content-Encoding")) {
		_ = f.Close() // Verfahren des Ziels, das dieser Browser nicht kann: zum Ziel
	} else if it != nil {
		defer f.Close()
		for k, v := range it.header {
			w.Header()[k] = v
		}
		w.Header().Set("X-Proxy-Cache", "HIT")
		w.Header().Set("Content-Length", strconv.FormatInt(it.size, 10))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = io.Copy(w, f) // Traffic zaehlt outCounter (terminate.go)
		}
		return
	}
	cw := &captureWriter{ResponseWriter: w, s: s, now: now, limit: min(int64(cacheMaxObject), int64(t.cacheMB)<<20/4), get: r.Method == http.MethodGet, ae: ae}
	r, cw.body = httpcompress.Track(r)
	ok := false
	defer func() { // auch bei panic(http.ErrAbortHandler) (Abbruch, Fehler des Ziels): Zwischendatei weg, panic laeuft weiter
		cw.failed = cw.failed || !ok
		cw.finish(re, key, t)
	}()
	next.ServeHTTP(cw, r.WithContext(context.WithValue(r.Context(), captureKey{}, cw)))
	ok = true
}

type captureKey struct{}

type captureWriter struct {
	http.ResponseWriter
	s       *Server
	now     time.Time
	limit   int64
	get     bool
	ae      string             // Accept-Encoding der Anfrage
	body    *httpcompress.Body // vollstaendig vom Ziel gelesen?
	wrote   bool
	ttl     time.Duration
	tmp     *os.File
	n       int64
	failed  bool
	header  http.Header
	flusher bool
}

// storable: Antwort mit Status und Koepfen kaeme in den Cache (auch fuer die staerkere Komprimierung, compress.go).
func (c *captureWriter) storable(code int, h http.Header) (time.Duration, bool) {
	ttl, ok := cacheable(code, h, c.now)
	if !ok || !c.get || c.s.cache.dir == "" {
		return 0, false
	}
	if cl, err := strconv.ParseInt(h.Get("Content-Length"), 10, 64); err == nil && cl > c.limit {
		return 0, false
	}
	return ttl, true
}

func (c *captureWriter) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols { // 103 Early Hints: nicht der Status
		c.ResponseWriter.WriteHeader(code)
		return
	}
	if c.wrote {
		return
	}
	c.wrote = true
	h := c.Header()
	if ttl, ok := c.storable(code, h); ok {
		if f, err := os.CreateTemp(c.s.cache.dir, "tmp-*"); err == nil {
			c.tmp, c.ttl, c.header = f, ttl, h.Clone()
		}
	}
	h.Set("X-Proxy-Cache", "MISS")
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	n, err := c.ResponseWriter.Write(p)
	if err != nil {
		c.failed = true
	}
	if c.tmp != nil && !c.failed {
		if c.n+int64(n) > c.limit {
			c.failed = true
		} else if _, werr := c.tmp.Write(p[:n]); werr != nil {
			c.failed = true
		}
		c.n += int64(n)
	}
	return n, err
}

func (c *captureWriter) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// finish: vollstaendige, cachebare Antwort uebernehmen - nur wenn der Body des Ziels ganz gelesen wurde (komprimiert
// fehlt die Content-Length) und das Verfahren zu dieser Anfrage passt.
func (c *captureWriter) finish(re *route, key string, t *target) {
	if c.tmp == nil {
		return
	}
	name := c.tmp.Name()
	_ = c.tmp.Close()
	if cl, err := strconv.ParseInt(c.header.Get("Content-Length"), 10, 64); c.failed || (err == nil && cl != c.n) || !c.body.Complete() ||
		!httpcompress.Acceptable(c.ae, c.header.Get("Content-Encoding")) {
		_ = os.Remove(name)
		return
	}
	for _, k := range []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Content-Length", "X-Proxy-Cache"} {
		c.header.Del(k)
	}
	c.s.cache.put(re.HostID, key, &cacheItem{file: name, size: c.n, expires: c.now.Add(c.ttl), used: c.now, header: c.header},
		int64(t.cacheMB)<<20)
}

func (rc *respCache) get(host int, key string, now time.Time) (*cacheItem, *os.File) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	hc := rc.hosts[host]
	if hc == nil {
		return nil, nil
	}
	it := hc.items[key]
	if it == nil {
		return nil, nil
	}
	if now.After(it.expires) {
		rc.dropLocked(hc, key)
		return nil, nil
	}
	f, err := os.Open(it.file)
	if err != nil {
		rc.dropLocked(hc, key)
		return nil, nil
	}
	it.used = now
	return it, f
}

func (rc *respCache) put(host int, key string, it *cacheItem, limit int64) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	hc := rc.hosts[host]
	if hc == nil {
		hc = &hostCache{items: map[string]*cacheItem{}}
		rc.hosts[host] = hc
	}
	if hc.items[key] != nil {
		rc.dropLocked(hc, key)
	}
	final := filepath.Join(rc.dir, strconv.Itoa(host)+"-"+key)
	if os.Rename(it.file, final) != nil {
		_ = os.Remove(it.file)
		return
	}
	it.file = final
	hc.items[key] = it
	hc.size += it.size
	rc.total += it.size
	for hc.size > limit && len(hc.items) > 0 { // zuletzt genutzte bleiben
		rc.dropOldestLocked(hc)
	}
	for rc.total > rc.max { // Grenze aller Namen: der am laengsten ungenutzte Eintrag gleich welchen Namens
		var oldest *hostCache
		var at time.Time
		for _, h := range rc.hosts {
			for _, x := range h.items {
				if oldest == nil || x.used.Before(at) {
					oldest, at = h, x.used
				}
			}
		}
		if oldest == nil {
			break
		}
		rc.dropOldestLocked(oldest)
	}
}

func (rc *respCache) dropOldestLocked(hc *hostCache) {
	var oldK string
	var old *cacheItem
	for k, x := range hc.items {
		if old == nil || x.used.Before(old.used) {
			oldK, old = k, x
		}
	}
	rc.dropLocked(hc, oldK)
}

func (rc *respCache) dropLocked(hc *hostCache, key string) {
	if it := hc.items[key]; it != nil {
		_ = os.Remove(it.file)
		hc.size -= it.size
		rc.total -= it.size
		delete(hc.items, key)
	}
}

// sweep: abgelaufene und lange ungenutzte Eintraege, Namen ohne Cache (oder nicht mehr da) ganz.
func (rc *respCache) sweep(now time.Time, inactive map[int]time.Duration) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for id, hc := range rc.hosts {
		d, ok := inactive[id]
		for k, it := range hc.items {
			if !ok || now.After(it.expires) || now.Sub(it.used) > d {
				rc.dropLocked(hc, k)
			}
		}
		if len(hc.items) == 0 {
			delete(rc.hosts, id)
		}
	}
}

// cacheLoop raeumt jede Minute auf.
func (s *Server) cacheSweep() {
	if s.cache == nil {
		return
	}
	in := map[int]time.Duration{}
	for _, e := range s.routes.Load().exact {
		if e.Target != nil && e.Target.cacheMB > 0 {
			in[e.HostID] = time.Duration(max(e.Target.cacheMinutes, 1)) * time.Minute
		}
	}
	s.cache.sweep(time.Now(), in)
}
