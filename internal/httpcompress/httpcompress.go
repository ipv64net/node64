// Package httpcompress komprimiert HTTP-Antworten mit zstd, Brotli oder gzip - je nachdem, was der Browser anbietet
// (Accept-Encoding mit q-Werten). Genutzt von PROXY64 (Node) und den CDN64-Servern (Modus 3).
//
// Dynamische Antworten: zstd (schnell), sonst Brotli Stufe 4, sonst gzip Stufe 5. Statische Dateien, die danach im
// Cache liegen (Static): Brotli Stufe 9, sonst zstd hoch, sonst gzip 9 - einmal teuer, dann oft ausgeliefert.
// Komprimiert wird nur, was sich lohnt: Status 200, Text/JSON/JS/XML/SVG/WASM u. ae., ab 512 Byte, nicht schon
// komprimiert, nicht bei Range, HEAD, WebSocket oder Cache-Control: no-transform.
package httpcompress

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/gzip"
	"github.com/klauspost/compress/zstd"
)

const minSize = 512

// Verfahren (Content-Encoding).
const (
	Zstd   = "zstd"
	Brotli = "br"
	Gzip   = "gzip"
)

// Negotiate waehlt das Verfahren nach Accept-Encoding ("" = keins). static bevorzugt Brotli (kleiner), sonst zstd
// (schneller).
func Negotiate(acceptEncoding string, static bool) string {
	q := map[string]float64{}
	for _, part := range strings.Split(strings.ToLower(acceptEncoding), ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		v := 1.0
		if p, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(p), 64); err == nil {
				v = f
			}
		}
		q[name] = v
	}
	order := []string{Zstd, Brotli, Gzip}
	if static {
		order = []string{Brotli, Zstd, Gzip}
	}
	for _, e := range order {
		if q[e] > 0 {
			return e
		}
	}
	return ""
}

// Compressible: Inhalt, der sich komprimieren laesst (Bilder, Videos, Archive, woff2 sind es schon).
func Compressible(contentType string) bool {
	ct := strings.ToLower(contentType)
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "javascript") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "svg") || strings.Contains(ct, "wasm") || strings.Contains(ct, "font/ttf") || strings.Contains(ct, "font/otf") ||
		strings.Contains(ct, "vnd.ms-fontobject") || strings.Contains(ct, "x-font-ttf")
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

func level(enc string, static bool) int {
	switch {
	case enc == Brotli && static:
		return 9
	case enc == Brotli:
		return 4
	case enc == Zstd && static:
		return int(zstd.SpeedBestCompression)
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
			return brotli.NewWriterLevel(nil, lvl)
		case Zstd:
			e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(lvl)), zstd.WithEncoderConcurrency(1), zstd.WithLowerEncoderMem(true))
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
	// Static: Anfrage auf eine Datei, die danach im Cache liegt (staerkere Stufe); nil = immer dynamisch
	Static func(r *http.Request) bool
}

// Handler komprimiert die Antworten von next, wenn der Browser es kann und es sich lohnt.
func Handler(next http.Handler, opt Options) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || r.Header.Get("Upgrade") != "" {
			next.ServeHTTP(w, r)
			return
		}
		static := opt.Static != nil && opt.Static(r)
		enc := Negotiate(r.Header.Get("Accept-Encoding"), static)
		if enc == "" {
			next.ServeHTTP(w, r)
			return
		}
		cw := &writer{ResponseWriter: w, enc: enc, lvl: level(enc, static)}
		defer cw.close()
		next.ServeHTTP(cw, r)
	})
}

// writer entscheidet beim ersten WriteHeader, ob komprimiert wird.
type writer struct {
	http.ResponseWriter
	enc     string
	lvl     int
	e       encoder
	decided bool
}

func (w *writer) WriteHeader(code int) {
	if !w.decided {
		w.decided = true
		h := w.Header()
		cl, _ := strconv.Atoi(h.Get("Content-Length"))
		if code == http.StatusOK && h.Get("Content-Encoding") == "" && Compressible(h.Get("Content-Type")) && (cl == 0 || cl >= minSize) &&
			!strings.Contains(strings.ToLower(h.Get("Cache-Control")), "no-transform") {
			h.Del("Content-Length")
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
	if w.e != nil {
		return w.e.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *writer) Flush() {
	if w.e != nil {
		_ = w.e.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *writer) close() {
	if w.e != nil {
		_ = w.e.Close()
		putEncoder(w.enc, w.lvl, w.e)
		w.e = nil
	}
}
