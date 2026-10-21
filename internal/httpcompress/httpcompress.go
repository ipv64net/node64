// Package httpcompress komprimiert HTTP-Antworten mit zstd, Brotli oder gzip - je nachdem, was der Browser anbietet
// (Accept-Encoding mit q-Werten). Genutzt von PROXY64 (Node) und den CDN64-Servern (Modus 3).
//
// Dynamische Antworten: zstd (schnell), sonst Brotli Stufe 4, sonst gzip Stufe 5. Statische Dateien, die danach im
// Cache liegen (Static): Brotli Stufe 6, sonst zstd "better", sonst gzip 9 - einmal teurer, dann oft ausgeliefert.
// Kleine Fenster (Brotli 256 KB, zstd 1 MB): je Encoder nur wenige MB Speicher (Raspberry Pi); hoechstens staticSlots
// staerkere Laeufe zugleich, sonst die dynamische Stufe.
// Komprimiert wird nur, was sich lohnt: Status 200, Text/JSON/JS/XML/SVG/WASM u. ae., ab 512 Byte, nicht schon
// komprimiert, nicht bei Range, HEAD, WebSocket oder Cache-Control: no-transform.
package httpcompress

import (
	"context"
	"io"
	"net/http"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

const (
	minSize   = 512
	brotliWin = 18      // 256 KB Fenster (Standard 4 MB: ~20 MB je Encoder)
	zstdWin   = 1 << 20 // 1 MB Fenster (Standard 8 MB: ~10 MB je Encoder)
)

// Verfahren (Content-Encoding).
const (
	Zstd   = "zstd"
	Brotli = "br"
	Gzip   = "gzip"
)

// Accepts liest Accept-Encoding: Verfahren (klein) -> q-Wert; x-gzip zaehlt als gzip.
func Accepts(acceptEncoding string) map[string]float64 {
	q := map[string]float64{}
	for _, part := range strings.Split(strings.ToLower(acceptEncoding), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if name == "x-gzip" {
			name = Gzip
		}
		v := 1.0
		for _, p := range strings.Split(params, ";") {
			if s, ok := strings.CutPrefix(strings.TrimSpace(p), "q="); ok {
				if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
					v = f
				}
			}
		}
		q[name] = v
	}
	return q
}

// accepted: Verfahren erlaubt? Nicht genannt gilt "*", ohne "*" nur identity.
func accepted(q map[string]float64, coding string) bool {
	if v, ok := q[coding]; ok {
		return v > 0
	}
	if v, ok := q["*"]; ok {
		return v > 0
	}
	return coding == "identity"
}

// Negotiate waehlt das Verfahren nach Accept-Encoding ("" = keins). static bevorzugt Brotli (kleiner), sonst zstd
// (schneller).
func Negotiate(acceptEncoding string, static bool) string {
	return negotiate(Accepts(acceptEncoding), static)
}

func negotiate(q map[string]float64, static bool) string {
	order := []string{Zstd, Brotli, Gzip}
	if static {
		order = []string{Brotli, Zstd, Gzip}
	}
	for _, e := range order {
		if accepted(q, e) {
			return e
		}
	}
	return ""
}

// CacheVariant: Teil des Cache-Schluessels - das Verfahren, das hier gewaehlt wuerde, und welche der ueblichen
// Verfahren der Browser annimmt (q=0 zaehlt nicht). Wenige Fassungen statt der ganzen Accept-Encoding-Zeile; was ein
// Ziel selbst komprimiert (z. B. deflate), bekommt so kein Browser, der es nicht kann.
func CacheVariant(acceptEncoding string) string {
	q := Accepts(acceptEncoding)
	v := negotiate(q, true) + "|"
	for _, c := range []string{Brotli, "deflate", Gzip, "identity", Zstd} {
		if accepted(q, c) {
			v += c + ","
		}
	}
	return v
}

// Acceptable: darf eine Antwort mit diesem Content-Encoding (z. B. aus dem Cache) an diesen Browser?
func Acceptable(acceptEncoding, contentEncoding string) bool {
	if strings.TrimSpace(contentEncoding) == "" {
		return true
	}
	q := Accepts(acceptEncoding)
	for _, c := range strings.Split(strings.ToLower(contentEncoding), ",") {
		if c = strings.TrimSpace(c); c != "" && c != "identity" && !accepted(q, c) {
			return false
		}
	}
	return true
}

// Compressible: Inhalt, der sich komprimieren laesst (Bilder, Videos, Archive, woff2 sind es schon).
func Compressible(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "javascript") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "svg") || strings.Contains(ct, "wasm") || strings.Contains(ct, "font/ttf") || strings.Contains(ct, "font/otf") ||
		strings.Contains(ct, "vnd.ms-fontobject") || strings.Contains(ct, "x-font-ttf")
}

var staticExt = map[string]bool{".css": true, ".js": true, ".mjs": true, ".svg": true, ".json": true, ".map": true, ".txt": true,
	".xml": true, ".wasm": true, ".ttf": true, ".otf": true, ".eot": true, ".ico": true}

// StaticExt: Datei mit komprimierbarer Endung, die sich fuer die staerkere Stufe eignet (nur, wenn die Antwort danach
// auch im Cache liegt - .json/.txt/.xml sind oft dynamisch).
func StaticExt(p string) bool { return staticExt[strings.ToLower(path.Ext(p))] }

// ---------------------------------------------------------------- Vollstaendigkeit (fuer Caches)

type bodyKey struct{}

// Body haelt fest, ob eine Antwort vollstaendig war: erst wenn der Body des Ziels bis EOF gelesen ist (TrackBody) und
// kein Lese-, Schreib- oder Encoder-Fehler auftrat. Ein Cache legt nur ab, was Complete ist - auch bei HTTP/3 und im
// Tunnel, wo httputil.ReverseProxy nach einem Abbruch still zurueckkehrt statt abzubrechen.
type Body struct{ done, failed atomic.Bool }

// Track haengt einen Body an die Anfrage (im Cache, vor Komprimierung und Proxy).
func Track(r *http.Request) (*http.Request, *Body) {
	b := &Body{}
	return r.WithContext(context.WithValue(r.Context(), bodyKey{}, b)), b
}

// BodyOf: der Body der Anfrage (nil = keiner).
func BodyOf(r *http.Request) *Body {
	b, _ := r.Context().Value(bodyKey{}).(*Body)
	return b
}

// Fail: Antwort nicht in den Cache.
func (b *Body) Fail() {
	if b != nil {
		b.failed.Store(true)
	}
}

// Complete: Body des Ziels ganz gelesen, kein Fehler.
func (b *Body) Complete() bool { return b != nil && b.done.Load() && !b.failed.Load() }

// TrackBody fuer ReverseProxy.ModifyResponse: liest der Proxy den Body bis EOF, ist er vollstaendig; ein anderer
// Lesefehler (Ziel bricht ab, Content-Length nicht erreicht) markiert ihn. Nicht bei 101 (WebSocket).
func TrackBody(resp *http.Response) {
	if resp.Request == nil || resp.StatusCode == http.StatusSwitchingProtocols {
		return
	}
	if b := BodyOf(resp.Request); b != nil {
		resp.Body = &trackedBody{ReadCloser: resp.Body, b: b}
	}
}

type trackedBody struct {
	io.ReadCloser
	b *Body
}

func (t *trackedBody) Read(p []byte) (int, error) {
	n, err := t.ReadCloser.Read(p)
	switch {
	case err == io.EOF:
		t.b.done.Store(true)
	case err != nil:
		t.b.failed.Store(true)
	}
	return n, err
}

// ---------------------------------------------------------------- Encoder

type encoder interface {
	io.Writer
	Flush() error
	Close() error
	Reset(io.Writer)
}

type zstdEnc struct{ *zstd.Encoder }

func (z zstdEnc) Reset(w io.Writer) { z.Encoder.Reset(w) }

var pools sync.Map // "verfahren/stufe" -> *sync.Pool

// staticSlots: so viele staerkere Laeufe zugleich (Speicher, CPU); sind alle belegt, gilt die dynamische Stufe.
var staticSlots = make(chan struct{}, max(2, min(runtime.NumCPU()/2, 4)))

func level(enc string, static bool) int {
	switch {
	case enc == Brotli && static:
		return 6
	case enc == Brotli:
		return 4
	case enc == Zstd && static:
		return int(zstd.SpeedBetterCompression)
	case enc == Zstd:
		return int(zstd.SpeedDefault)
	case static:
		return gzip.BestCompression
	default:
		return 5
	}
}

func getEncoder(enc string, lvl int, w io.Writer) encoder {
	key := enc + "/" + strconv.Itoa(lvl)
	p, _ := pools.LoadOrStore(key, &sync.Pool{New: func() any {
		switch enc {
		case Brotli:
			return brotli.NewWriterOptions(nil, brotli.WriterOptions{Quality: lvl, LGWin: brotliWin})
		case Zstd:
			e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(lvl)), zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true),
				zstd.WithWindowSize(zstdWin))
			return zstdEnc{e}
		default:
			g, _ := gzip.NewWriterLevel(nil, lvl)
			return g
		}
	}})
	e := p.(*sync.Pool).Get().(encoder)
	e.Reset(w)
	return e
}

func putEncoder(enc string, lvl int, e encoder) {
	e.Reset(io.Discard) // keine Verweise auf die Verbindung halten
	if p, ok := pools.Load(enc + "/" + strconv.Itoa(lvl)); ok {
		p.(*sync.Pool).Put(e)
	}
}

// ---------------------------------------------------------------- Handler

// Options steuern den Handler.
type Options struct {
	// Static: Antwort (Status 200, Koepfe h des Ziels) kommt danach in den Cache - staerkere Stufe; nil = immer dynamisch
	Static func(r *http.Request, h http.Header) bool
}

// Handler komprimiert die Antworten von next, wenn der Browser es kann und es sich lohnt.
func Handler(next http.Handler, opt Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || r.Header.Get("Upgrade") != "" {
			next.ServeHTTP(w, r)
			return
		}
		q := Accepts(r.Header.Get("Accept-Encoding"))
		if negotiate(q, false) == "" {
			next.ServeHTTP(w, r)
			return
		}
		cw := &writer{ResponseWriter: w, r: r, q: q, static: opt.Static, body: BodyOf(r), orig: -1}
		defer cw.close()
		next.ServeHTTP(cw, r)
	})
}

// writer entscheidet beim ersten endgueltigen WriteHeader (nicht 1xx), ob komprimiert wird.
type writer struct {
	http.ResponseWriter
	r       *http.Request
	q       map[string]float64
	static  func(*http.Request, http.Header) bool
	body    *Body
	enc     string
	lvl     int
	slot    bool // haelt einen der staticSlots
	e       encoder
	orig, n int64 // Content-Length des Ziels (-1 = keine), unkomprimiert geschrieben
	decided bool
}

func (w *writer) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols { // 103 Early Hints, 100 Continue: noch offen
		w.ResponseWriter.WriteHeader(code)
		return
	}
	if !w.decided {
		w.decided = true
		h := w.Header()
		cl, err := strconv.ParseInt(h.Get("Content-Length"), 10, 64)
		if err != nil {
			cl = -1
		}
		if code == http.StatusOK && h.Get("Content-Encoding") == "" && Compressible(h.Get("Content-Type")) && (cl < 0 || cl >= minSize) &&
			!strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform") {
			static := w.static != nil && w.static(w.r, h)
			w.enc = negotiate(w.q, static)
			w.lvl = level(w.enc, false)
			if static {
				select {
				case staticSlots <- struct{}{}:
					w.slot, w.lvl = true, level(w.enc, true)
				default: // alle belegt: dynamische Stufe statt warten
				}
			}
			w.orig = cl
			h.Del("Content-Length")
			h.Del("Accept-Ranges") // Bereiche gaelten fuer die unkomprimierte Fassung
			h.Set("Content-Encoding", w.enc)
			h.Add("Vary", "Accept-Encoding")
			if et := h.Get("ETag"); et != "" && !strings.HasPrefix(et, "W/") { // anderer Inhalt: nur noch schwach gleich
				h.Set("ETag", "W/"+et)
			}
			w.e = getEncoder(w.enc, w.lvl, w.ResponseWriter)
		} else if code == http.StatusOK || code == http.StatusNotModified {
			h.Add("Vary", "Accept-Encoding")
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *writer) Write(b []byte) (int, error) {
	if !w.decided {
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", http.DetectContentType(b))
		}
		w.WriteHeader(http.StatusOK)
	}
	if w.e == nil {
		return w.ResponseWriter.Write(b)
	}
	n, err := w.e.Write(b)
	w.n += int64(n)
	if err != nil {
		w.body.Fail()
	}
	return n, err
}

func (w *writer) Flush() {
	if w.e != nil && w.e.Flush() != nil {
		w.body.Fail()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *writer) close() {
	if w.e != nil {
		if err := w.e.Close(); err != nil || (w.orig >= 0 && w.n != w.orig) { // Schreibfehler oder Ziel abgebrochen
			w.body.Fail()
		}
		putEncoder(w.enc, w.lvl, w.e)
		w.e = nil
	}
	if w.slot {
		<-staticSlots
		w.slot = false
	}
}
