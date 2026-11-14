package edge

import (
	"io"
	"net/http"
	"time"
)

// h3ProbeWait: so lange wartet H3Body hoechstens auf das Ende einer HTTP/3-Anfrage ohne Laenge (wie net/http beim
// Senden solcher Anfragen).
var h3ProbeWait = 200 * time.Millisecond

// H3Body: HTTP/3 kennt eine Laenge nur ueber content-length. Fehlt sie, liefert quic-go ContentLength -1 und einen
// Body - auch bei einem GET ohne Inhalt (HTTP/1.1 und HTTP/2 liefern dort http.NoBody). Weitergereicht saehe das Ziel
// eine Anfrage mit Inhalt unbekannter Laenge (HTTP/2 ohne END_STREAM, HTTP/1.1 chunked); lighttpd (z. B. OPNsense)
// antwortet darauf mit 400 Bad Request (#157). Bei Methoden, die ueblicherweise keinen Inhalt haben, sieht H3Body
// deshalb kurz nach, ob der Inhalt leer ist, und macht daraus dann eine Anfrage ohne Inhalt.
func H3Body(r *http.Request) {
	if r.ContentLength >= 0 || r.Body == nil || r.Body == http.NoBody {
		return
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodDelete, http.MethodOptions, "PROPFIND", "SEARCH":
	default:
		return
	}
	p := &probeBody{body: r.Body, ch: make(chan probeRes, 1)}
	go func() {
		n, err := p.body.Read(p.b[:])
		p.ch <- probeRes{n, err}
	}()
	t := time.NewTimer(h3ProbeWait)
	defer t.Stop()
	select {
	case x := <-p.ch:
		if x.n == 0 && x.err == io.EOF {
			r.Body, r.ContentLength = http.NoBody, 0
			return
		}
		p.ch <- x // Ergebnis fuer den ersten Read von probeBody
	case <-t.C: // Ende noch nicht da: Inhalt bleibt unbekannt lang, der erste Read wartet auf das laufende Lesen
	}
	r.Body = p
}

type probeRes struct {
	n   int
	err error
}

// probeBody ist der Body nach dem Nachsehen: zuerst das schon gelesene Byte (bzw. der Fehler), dann der Rest.
type probeBody struct {
	body io.ReadCloser
	ch   chan probeRes // Ergebnis des ersten Lesens (hoechstens ein Byte in b)
	b    [1]byte
	done bool
}

func (p *probeBody) Read(q []byte) (int, error) {
	if len(q) == 0 {
		return 0, nil
	}
	if !p.done {
		p.done = true
		x := <-p.ch
		if x.n > 0 {
			q[0] = p.b[0]
			return 1, x.err
		}
		if x.err != nil {
			return 0, x.err
		}
	}
	return p.body.Read(q)
}

func (p *probeBody) Close() error { return p.body.Close() }
