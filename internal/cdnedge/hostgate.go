package cdnedge

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// Modus 1, Port 80: die Verbindung geht nach dem Host der ersten Anfrage in den Tunnel einer Node. Weitere Anfragen
// derselben Verbindung (Keep-Alive, absolute URL) koennten einen anderen Namen tragen und kaemen dann beim Tunnel des
// ersten Namens an. hostGate liest deshalb jede Anfrage mit (Kopf und Laenge des Bodys wie net/http) und reicht die
// Bytes unveraendert weiter, solange Host-Kopf und absolute URL der Name sind, nach dem geroutet wurde; sonst wird
// getrennt. Nach einem Upgrade (WebSocket) geht es roh weiter - die Antwort (101 oder nicht) sieht der Server nicht,
// dort prueft die Node selbst.

const hgHeaderMax = 64 << 10 // Kopf einer Anfrage hoechstens (dazu, was schon im Puffer liegt)

var errOtherHost = errors.New("request for another host on this connection")

// hostGate: Lesen liefert nur gepruefte Anfragen; Schreiben, Adressen und Schliessen gehen an den Besucher.
type hostGate struct {
	net.Conn
	pr *io.PipeReader
}

// newHostGate: data sind die schon gelesenen Bytes (Kopf der ersten Anfrage), host der geroutete Name.
func newHostGate(c net.Conn, data []byte, host string) *hostGate {
	pr, pw := io.Pipe()
	go func() {
		err := gateHTTP(io.MultiReader(bytes.NewReader(data), c), pw, hostOnly(host))
		if err != nil && !errors.Is(err, io.EOF) { // anderer Name oder kaputte Anfrage: ganz trennen
			_ = c.Close()
		}
		_ = pw.CloseWithError(err)
	}()
	return &hostGate{Conn: c, pr: pr}
}

func (g *hostGate) Read(p []byte) (int, error) { return g.pr.Read(p) }

func (g *hostGate) Close() error {
	_ = g.pr.Close()
	return g.Conn.Close()
}

func (g *hostGate) CloseWrite() error {
	if cw, ok := g.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return g.Close()
}

// rawTap merkt sich jedes gelesene Byte, bis es weitergereicht ist; left begrenzt das Lesen (Kopf, -1 = frei).
type rawTap struct {
	r    io.Reader
	buf  []byte
	left int64
}

func (t *rawTap) Read(p []byte) (int, error) {
	if t.left == 0 {
		return 0, errors.New("request header too large")
	}
	if t.left > 0 && int64(len(p)) > t.left {
		p = p[:t.left]
	}
	n, err := t.r.Read(p)
	t.buf = append(t.buf, p[:n]...)
	if t.left > 0 {
		t.left -= int64(n)
	}
	return n, err
}

// gateHTTP reicht Anfrage fuer Anfrage von src nach w (unveraendert), solange jede an want geht. Rueckgabe io.EOF:
// sauberes Ende zwischen zwei Anfragen.
func gateHTTP(src io.Reader, w io.Writer, want string) error {
	tap := &rawTap{r: src, left: -1}
	br := bufio.NewReaderSize(tap, 16<<10)
	flush := func() error { // was der Parser verbraucht hat, weiterreichen
		n := len(tap.buf) - br.Buffered()
		if n <= 0 {
			return nil
		}
		_, err := w.Write(tap.buf[:n])
		tap.buf = append(tap.buf[:0], tap.buf[n:]...)
		return err
	}
	buf := make([]byte, 32<<10)
	for {
		tap.left = hgHeaderMax
		req, err := http.ReadRequest(br)
		tap.left = -1
		if err != nil {
			return err
		}
		if !hostIs(req, want) {
			return errOtherHost
		}
		if err := flush(); err != nil {
			return err
		}
		if isUpgrade(req) { // ab hier roh (WebSocket); im Puffer liegt genau, was noch nicht weitergereicht ist
			if _, err := w.Write(tap.buf); err != nil {
				return err
			}
			tap.buf = nil
			_, err := io.Copy(w, src)
			return err
		}
		for { // Body nach Content-Length bzw. chunked (wie die Node ihn liest)
			_, rerr := req.Body.Read(buf)
			if err := flush(); err != nil {
				return err
			}
			if errors.Is(rerr, io.EOF) {
				break
			}
			if rerr != nil {
				return rerr
			}
		}
	}
}

// hostIs: Anfrage geht an want - Host-Kopf (hoechstens einer) und, bei absoluter URL, deren Host; kein CONNECT.
func hostIs(r *http.Request, want string) bool {
	hs := r.Header["Host"]
	switch {
	case r.Method == http.MethodConnect, len(hs) > 1, r.Host == "", hostOnly(r.Host) != want:
		return false
	case len(hs) == 1 && hostOnly(hs[0]) != want:
		return false
	case r.URL != nil && r.URL.Host != "" && hostOnly(r.URL.Host) != want:
		return false
	}
	return true
}

// isUpgrade: Upgrade-Anfrage (Connection: upgrade und ein Upgrade-Kopf).
func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}
	for _, v := range r.Header["Connection"] {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "upgrade") {
				return true
			}
		}
	}
	return false
}
