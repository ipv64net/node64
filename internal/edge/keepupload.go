package edge

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Upload nach einer fruehen Antwort: Antwortet das Ziel, bevor es den Upload gelesen hat (nginx bei OpenSpeedTest:
// POST auf eine Datei gibt sofort 200, den Rest verwirft nginx still), schloss der Transport von ReverseProxy den
// Body - unter HTTP/2 und HTTP/3 hiess das fuer den Besucher "nicht weiter senden" (Stream zu), unter HTTP/1.1
// Verbindung zu. Der Upload brach ab, im Speedtest fiel er bis fast auf null. Firefox hoert ausserdem schon auf zu
// senden, sobald die Antwort vollstaendig da ist (z. B. "ok" mit Content-Length 2), auch wenn der Server weiter liest.
//
// KeepUpload laesst den Transport deshalb nur eine Huelle schliessen und haelt eine fruehe, kleine Antwort
// (hoechstens keepHold Bytes) zurueck, bis der Upload ganz angekommen ist; die zurueckgegebene Funktion liest danach
// den Rest, verwirft ihn wie nginx (hoechstens KeepUploadMax bzw. KeepUploadTime; was darunter zaehlt oder bremst,
// gilt weiter) und schickt erst dann die Antwort. Fuer den Besucher sieht das aus wie ein Ziel, das erst liest und
// dann antwortet. Groessere oder laufend gestreamte Antworten gehen sofort durch.

const (
	KeepUploadMax  = 1 << 30
	KeepUploadTime = 30 * time.Second
	keepHold       = 64 << 10
)

// KeepUpload vor dem Weiterreichen aufrufen: den gelieferten ResponseWriter weiterreichen, die Funktion danach
// aufrufen (immer). Ohne Upload und bei "Expect: 100-continue" (der Client schickt den Body nach einer fruehen
// Antwort gar nicht erst) bleibt alles, wie es ist. Ohne Upload heisst auch Laenge 0: HTTP/2 liefert selbst einem GET
// ohne Inhalt einen Body (nur HTTP/1.1 http.NoBody) - den liest niemand, die Antwort blieb bis zum Ende bzw. 64 KB
// liegen und Live-Verbindungen (Server-Sent Events, Streams; Forum 5202, Dockhand) hingen (1.7.6).
func KeepUpload(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func()) {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 || strings.EqualFold(r.Header.Get("Expect"), "100-continue") {
		return w, func() {}
	}
	k := &keepBody{ReadCloser: r.Body}
	r.Body = k
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // HTTP/1.1: Body auch nach der Antwort lesen (sonst "Connection: close" ab 256 KB)
	hw := &holdWriter{ResponseWriter: w, k: k}
	return hw, func() {
		k.drain(rc, r)
		hw.release()
	}
}

type keepBody struct {
	io.ReadCloser
	mu     sync.Mutex  // ein Leser: der Transport bzw. danach drain
	closed atomic.Bool // vom Transport geschlossen
	eof    atomic.Bool // ganz gelesen
}

func (k *keepBody) Read(p []byte) (int, error) {
	if k.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	n, err := k.ReadCloser.Read(p)
	if err == io.EOF {
		k.eof.Store(true)
	}
	return n, err
}

func (k *keepBody) Close() error {
	k.closed.Store(true)
	return nil
}

// drain: nach der Antwort des Ziels den Rest des Uploads lesen und verwerfen, dann den Body schliessen.
func (k *keepBody) drain(rc *http.ResponseController, r *http.Request) {
	k.closed.Store(true)
	defer k.ReadCloser.Close()
	if k.eof.Load() || r.Context().Err() != nil {
		return
	}
	if rc.SetReadDeadline(time.Now().Add(KeepUploadTime)) != nil { // ohne Lesefrist: nach KeepUploadTime schliessen
		t := time.AfterFunc(KeepUploadTime, func() { _ = k.ReadCloser.Close() })
		defer t.Stop()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_, _ = io.CopyN(io.Discard, k.ReadCloser, KeepUploadMax)
}

// holdWriter haelt die Antwort zurueck, solange der Upload nicht ganz gelesen ist (hoechstens keepHold Bytes).
type holdWriter struct {
	http.ResponseWriter
	k    *keepBody
	mu   sync.Mutex
	code int    // zurueckgehaltener Status (0 = keiner)
	buf  []byte // zurueckgehaltener Inhalt
	open bool   // durchgeschaltet
}

func (h *holdWriter) holding() bool { return !h.open && !h.k.eof.Load() }

// stream: Event-Stream (Server-Sent Events) - nie zurueckhalten.
func (h *holdWriter) stream() bool {
	return strings.HasPrefix(strings.ToLower(h.Header().Get("Content-Type")), "text/event-stream")
}

func (h *holdWriter) WriteHeader(code int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// 1xx und Event-Streams (Antwort laeuft neben dem Upload weiter, z. B. Fortschritt) immer sofort
	if code < 200 || !h.holding() || h.stream() {
		h.releaseLocked()
		h.ResponseWriter.WriteHeader(code)
		return
	}
	if h.code == 0 {
		h.code = code
	}
}

func (h *holdWriter) Write(b []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.holding() && !h.stream() && len(h.buf)+len(b) <= keepHold {
		if h.code == 0 {
			h.code = http.StatusOK
		}
		h.buf = append(h.buf, b...)
		return len(b), nil
	}
	if err := h.releaseLocked(); err != nil {
		return 0, err
	}
	return h.ResponseWriter.Write(b)
}

// Flush: zurueckgehalten wird nicht geschickt; durchgeschaltet wie gewohnt.
func (h *holdWriter) Flush() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.holding() {
		return
	}
	_ = h.releaseLocked()
	_ = http.NewResponseController(h.ResponseWriter).Flush()
}

func (h *holdWriter) Unwrap() http.ResponseWriter { return h.ResponseWriter }

// release schickt die zurueckgehaltene Antwort (nach dem Upload bzw. am Ende).
func (h *holdWriter) release() {
	h.mu.Lock()
	defer h.mu.Unlock()
	_ = h.releaseLocked()
}

func (h *holdWriter) releaseLocked() error {
	if h.open {
		return nil
	}
	h.open = true
	if h.code != 0 {
		h.ResponseWriter.WriteHeader(h.code)
	}
	if len(h.buf) > 0 {
		_, err := h.ResponseWriter.Write(h.buf)
		h.buf = nil
		return err
	}
	return nil
}
