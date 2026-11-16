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
// Verbindung zu. Der Upload brach ab, im Speedtest fiel er bis fast auf null. KeepUpload laesst den Transport nur
// eine Huelle schliessen; nach der Antwort liest die zurueckgegebene Funktion den Rest und verwirft ihn wie nginx
// (hoechstens KeepUploadMax bzw. KeepUploadTime; was darunter zaehlt oder bremst, gilt weiter).

const (
	KeepUploadMax  = 1 << 30
	KeepUploadTime = 30 * time.Second
)

// KeepUpload vor dem Weiterreichen aufrufen, die Rueckgabe danach (immer, auch ohne Body). Ohne Body und bei
// "Expect: 100-continue" (der Client schickt den Body nach einer fruehen Antwort gar nicht erst) tut sie nichts.
func KeepUpload(w http.ResponseWriter, r *http.Request) func() {
	if r.Body == nil || r.Body == http.NoBody || strings.EqualFold(r.Header.Get("Expect"), "100-continue") {
		return func() {}
	}
	k := &keepBody{ReadCloser: r.Body}
	r.Body = k
	rc := http.NewResponseController(w)
	_ = rc.EnableFullDuplex() // HTTP/1.1: Body auch nach der Antwort lesen (sonst "Connection: close" ab 256 KB)
	return func() { k.drain(rc, r) }
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

// drain: nach der Antwort den Rest des Uploads lesen und verwerfen, dann den Body schliessen.
func (k *keepBody) drain(rc *http.ResponseController, r *http.Request) {
	k.closed.Store(true)
	defer k.ReadCloser.Close()
	if k.eof.Load() || r.Context().Err() != nil {
		return
	}
	_ = rc.Flush()                                                 // Antwort zuerst beim Besucher
	if rc.SetReadDeadline(time.Now().Add(KeepUploadTime)) != nil { // ohne Lesefrist: nach KeepUploadTime schliessen
		t := time.AfterFunc(KeepUploadTime, func() { _ = k.ReadCloser.Close() })
		defer t.Stop()
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	_, _ = io.CopyN(io.Discard, k.ReadCloser, KeepUploadMax)
}
