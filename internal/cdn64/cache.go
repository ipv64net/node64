package cdn64

import (
	"container/list"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Cache Assets: statische Dateien (Bilder, CSS, JS, Schriften) eines Hosts im Speicher halten, wie die
// Option im Nginx Proxy Manager. Gecacht wird nur, was oeffentlich ist: GET ohne Anmeldung und ohne Cookie in
// der Antwort, Status 200, hoechstens 2 MB, nicht "private"/"no-store". Gesamtgroesse begrenzt, aelteste
// Eintraege fallen zuerst heraus. Beim Abschalten des Moduls wird alles freigegeben.

const (
	cacheMaxObject = 2 << 20
	cacheTTL       = 30 * time.Minute // ohne max-age vom Ziel
	cacheMaxTTL    = 24 * time.Hour
	browserMaxAge  = 30 * 24 * 3600 // wie NPM: expires 30d, wenn das Ziel nichts sagt
)

var assetExt = map[string]bool{".css": true, ".js": true, ".mjs": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".ico": true,
	".webp": true, ".avif": true, ".svg": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true, ".map": true}

type cacheEntry struct {
	key     string
	host    int64
	status  int
	header  http.Header
	body    []byte
	expires time.Time
	stored  time.Time
}

type assetCache struct {
	mu    sync.Mutex
	limit int
	size  int
	lru   *list.List // vorne = zuletzt benutzt
	items map[string]*list.Element
	hits  int64
	miss  int64
}

func newAssetCache(limit int) *assetCache {
	return &assetCache{limit: limit, lru: list.New(), items: map[string]*list.Element{}}
}

// cacheable: Anfrage kommt fuer den Cache in Frage.
func cacheable(r *http.Request) bool {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || r.Header.Get("Authorization") != "" || r.Header.Get("Range") != "" ||
		r.Header.Get("Upgrade") != "" {
		return false
	}
	return assetExt[strings.ToLower(path.Ext(r.URL.Path))]
}

// cacheKey: Host, Pfad und Abfrage, dazu die Komprimierungen, die der Browser kann.
func cacheKey(id int64, r *http.Request) string {
	ae := strings.ToLower(r.Header.Get("Accept-Encoding"))
	enc := ""
	for _, e := range []string{"br", "gzip", "zstd"} {
		if strings.Contains(ae, e) {
			enc += e + ","
		}
	}
	return strconv.FormatInt(id, 10) + "|" + r.Host + "|" + r.URL.RequestURI() + "|" + enc
}

func (c *assetCache) get(key string) *cacheEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.items[key]
	if el == nil {
		c.miss++
		return nil
	}
	e := el.Value.(*cacheEntry)
	if time.Now().After(e.expires) {
		c.removeLocked(el)
		c.miss++
		return nil
	}
	c.lru.MoveToFront(el)
	c.hits++
	return e
}

func (c *assetCache) put(e *cacheEntry) {
	n := len(e.body)
	if n > cacheMaxObject || n > c.limit {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.items[e.key]; old != nil {
		c.removeLocked(old)
	}
	c.items[e.key] = c.lru.PushFront(e)
	c.size += n
	for c.size > c.limit {
		c.removeLocked(c.lru.Back())
	}
}

func (c *assetCache) removeLocked(el *list.Element) {
	e := c.lru.Remove(el).(*cacheEntry)
	delete(c.items, e.key)
	c.size -= len(e.body)
}

// dropHost entfernt alles eines Hosts (nach Aenderung oder Loeschen).
func (c *assetCache) dropHost(id int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.lru.Front(); el != nil; {
		next := el.Next()
		if el.Value.(*cacheEntry).host == id {
			c.removeLocked(el)
		}
		el = next
	}
}

func (c *assetCache) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Init()
	c.items = map[string]*list.Element{}
	c.size = 0
}

// Stats: Groesse und Trefferquote.
func (c *assetCache) stats() (entries, bytes int, hits, miss int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items), c.size, c.hits, c.miss
}

// ttlOf: Lebensdauer nach den Angaben des Ziels; ok = false, wenn nicht gecacht werden darf.
func ttlOf(h http.Header) (time.Duration, bool) {
	cc := strings.ToLower(h.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") || strings.Contains(cc, "no-cache") || h.Get("Set-Cookie") != "" {
		return 0, false
	}
	if v := h.Get("Vary"); v != "" && !strings.EqualFold(strings.TrimSpace(v), "Accept-Encoding") {
		return 0, false
	}
	for _, part := range strings.Split(cc, ",") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(part), "max-age="); ok {
			n, err := strconv.Atoi(v)
			if err != nil || n <= 0 {
				return 0, false
			}
			d := time.Duration(n) * time.Second
			if d > cacheMaxTTL {
				d = cacheMaxTTL
			}
			return d, true
		}
	}
	return cacheTTL, true
}

// recorder nimmt die Antwort fuer den Cache mit auf (bis zur Hoechstgroesse), waehrend sie zum Browser geht.
type recorder struct {
	http.ResponseWriter
	status int
	buf    []byte
	over   bool
	origCC string // Cache-Control des Ziels (vor der Ergaenzung fuer den Browser)
}

func (w *recorder) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
		w.origCC = w.Header().Get("Cache-Control")
		if code == http.StatusOK && w.origCC == "" {
			w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(browserMaxAge))
		}
		w.Header().Set("X-Cache-Status", "MISS")
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *recorder) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.over {
		if len(w.buf)+len(b) > cacheMaxObject {
			w.over, w.buf = true, nil
		} else {
			w.buf = append(w.buf, b...)
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *recorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *recorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// cached umhuellt den Proxy eines Hosts mit dem Cache.
func (c *assetCache) cached(id int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cacheable(r) {
			next.ServeHTTP(w, r)
			return
		}
		key := cacheKey(id, r)
		if e := c.get(key); e != nil {
			for k, v := range e.header {
				w.Header()[k] = v
			}
			w.Header().Set("X-Cache-Status", "HIT")
			w.Header().Set("Age", strconv.Itoa(int(time.Since(e.stored).Seconds())))
			w.WriteHeader(e.status)
			if r.Method != http.MethodHead {
				_, _ = w.Write(e.body)
			}
			return
		}
		rec := &recorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		if r.Method != http.MethodGet || rec.status != http.StatusOK || rec.over {
			return
		}
		orig := w.Header().Clone()
		if rec.origCC == "" {
			orig.Del("Cache-Control")
		}
		ttl, ok := ttlOf(orig)
		if !ok {
			return
		}
		if cl := w.Header().Get("Content-Length"); cl != "" && cl != strconv.Itoa(len(rec.buf)) {
			return // Antwort abgebrochen
		}
		hdr := w.Header().Clone()
		hdr.Del("X-Cache-Status")
		hdr.Del("Date")
		now := time.Now()
		c.put(&cacheEntry{key: key, host: id, status: rec.status, header: hdr, body: rec.buf, expires: now.Add(ttl), stored: now})
	})
}
