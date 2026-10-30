package edge

import (
	"context"
	"log"
	"net/http"
	"net/netip"
	"strings"
)

// Debug-Beobachter: was am Eingang an den Routen vorbeigeht oder sie nie erreicht, fuer ein vollstaendiges
// Zugriffs-Log (PROXY64 mit Log-Level Debug). Ohne Beobachter kostet es nichts.

// Arten fuer WatchFunc.
const (
	WatchUnknown     = "unknown"     // Anfrage ohne passenden Namen (status = Antwort)
	WatchTLS         = "tls"         // TLS-Handshake gescheitert (path = Fehler)
	WatchNoTLS       = "no_tls"      // auf Port 443 kein lesbares TLS-ClientHello (auch zu altes TLS)
	WatchPassthrough = "passthrough" // TLS roh ans Ziel durchgereicht (host = SNI)
)

// WatchFunc bekommt je Ereignis die Gegenstelle, Name, Methode, Pfad bzw. Fehler, Status (0 = keine Antwort) und Art.
type WatchFunc func(ip netip.Addr, host, method, path string, status int, kind string)

// SetWatch setzt den Beobachter (nil = keiner). Ob er etwas festhaelt, entscheidet er selbst.
func (e *Edge) SetWatch(f WatchFunc) {
	if f == nil {
		e.watch.Store(nil)
		return
	}
	e.watch.Store(&f)
}

func (e *Edge) watched(ip netip.Addr, host, method, path string, status int, kind string) {
	if f := e.watch.Load(); f != nil {
		(*f)(ip, host, method, path, status, kind)
	}
}

type watchedKey struct{}

// MarkWatched: der Abnehmer unbekannter Namen (SetUnknown) hat die Anfrage selbst festgehalten - der Beobachter
// meldet sie nicht noch einmal.
func MarkWatched(r *http.Request) {
	if p, ok := r.Context().Value(watchedKey{}).(*bool); ok {
		*p = true
	}
}

// watchWriter merkt sich den Status der Antwort; Unwrap fuer http.ResponseController (Flush, Hijack).
type watchWriter struct {
	http.ResponseWriter
	status int
}

func (w *watchWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *watchWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *watchWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// watchUnknown: unknown mit Beobachter (Status der Antwort, auch wenn die Verbindung ohne Antwort endet).
func (e *Edge) watchUnknown(w http.ResponseWriter, r *http.Request, serve func(http.ResponseWriter, *http.Request)) {
	done := new(bool)
	r = r.WithContext(context.WithValue(r.Context(), watchedKey{}, done))
	sw := &watchWriter{ResponseWriter: w}
	defer func() {
		if !*done {
			e.watched(peerIP(r), hostOf(r.Host), r.Method, r.URL.RequestURI(), sw.status, WatchUnknown)
		}
	}()
	serve(sw, r)
}

// errLog: Fehler der HTTP-Server (vor allem TLS-Handshakes von Scannern) gehen nur an den Beobachter, nie ins Log
// (Art WatchTLS, auch fuer die seltenen anderen Fehler vor der ersten Anfrage).
func (e *Edge) errLog() *log.Logger { return log.New(watchErrs{e}, "", 0) }

type watchErrs struct{ e *Edge }

// Write: "http: TLS handshake error from 203.0.113.5:51234: EOF" -> Gegenstelle und Fehler.
func (x watchErrs) Write(b []byte) (int, error) {
	if x.e.watch.Load() == nil {
		return len(b), nil
	}
	s := strings.TrimSpace(string(b))
	var ip netip.Addr
	if i := strings.Index(s, " from "); i >= 0 {
		rest := s[i+6:]
		if j := strings.Index(rest, ": "); j > 0 {
			if ap, err := netip.ParseAddrPort(rest[:j]); err == nil {
				ip, s = ap.Addr().Unmap(), rest[j+2:]
			}
		}
	}
	x.e.watched(ip, "", "-", s, 0, WatchTLS)
	return len(b), nil
}
