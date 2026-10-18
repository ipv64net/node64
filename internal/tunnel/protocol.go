// Package tunnel ist die Verbindung zwischen einer Node64 und den CDN64-Servern (srv07/srv08.cdn64.de):
// Die Node oeffnet ausgehend eine QUIC-Verbindung (Ausweichweg TCP+TLS mit yamux), meldet sich an und nimmt
// danach Streams an, die der Server je Besucher-Verbindung oeffnet. Planung: docs/CDN64-ONLINE.md, Abschnitt 4.
package tunnel

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// ALPN unterscheidet den Tunnel von HTTP/3 auf demselben Port.
const ALPN = "cdn64-tunnel/1"

// Version ist die Protokoll-Version dieser Seite; Server koennen Version und Version-1 (G8).
const Version = 1

// Arten von Streams.
const (
	KindTLS    = "tls"    // Port 443 roh (Modus 1)
	KindHTTP80 = "http80" // Port 80 roh (Modus 1)
	KindHTTP   = "http"   // HTTP vom Server, TLS dort beendet (Modus 2, ab T5)
	KindQUIC   = "quic"   // QUIC eines Besuchers roh (Modus 1, HTTP/3): Datagramme mit Laengenpraefix (WriteDatagram)
)

// CapQUIC: Faehigkeit "QUIC durchreichen" (Hello der Node, Welcome des Servers).
const CapQUIC = "quic"

// HasCap: steht die Faehigkeit in der Liste?
func HasCap(caps []string, c string) bool {
	for _, x := range caps {
		if x == c {
			return true
		}
	}
	return false
}

// Hello: erste Nachricht der Node auf dem Steuer-Stream.
type Hello struct {
	Version     int      `json:"v"`
	Tunnel      string   `json:"tunnel"`
	Token       string   `json:"token"`
	Node        string   `json:"node,omitempty"`         // Name der Node (Anzeige)
	NodeVersion string   `json:"node_version,omitempty"` // Version von Node64
	Caps        []string `json:"caps,omitempty"`         // Faehigkeiten (z. B. "http")
}

// Welcome: Antwort des Servers (Error gesetzt = abgelehnt, danach wird getrennt).
type Welcome struct {
	Version int      `json:"v"`
	Edge    string   `json:"edge"`
	Error   string   `json:"error,omitempty"`
	Caps    []string `json:"caps,omitempty"` // Faehigkeiten des Servers (z. B. "quic")
}

// Control: weitere Nachrichten auf dem Steuer-Stream.
type Control struct {
	Type string `json:"type"` // "goaway": Server startet neu, laufende Streams duerfen enden
}

// Header steht am Anfang jedes Daten-Streams (vom Server geschrieben).
type Header struct {
	Kind   string `json:"kind"`
	Client string `json:"client"`         // echte Besucher-Adresse ip:port
	Host   string `json:"host,omitempty"` // SNI bzw. Host-Kopf
	Port   int    `json:"port"`           // Port beim Server (443/80)
	Edge   string `json:"edge,omitempty"` // Name des Servers
	Ray    string `json:"ray,omitempty"`  // Anfrage-ID fuer Logs (G9)
}

// ClientAddr ist die Besucher-Adresse als net.Addr (nil, wenn ungueltig).
func (h Header) ClientAddr() net.Addr {
	ap, err := netip.ParseAddrPort(h.Client)
	if err != nil {
		return nil
	}
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()))
}

var magic = [3]byte{'C', '6', '4'}

const maxHeader = 4096

var errBadHeader = errors.New("tunnel: bad stream header")

// WriteHeader schreibt den Kopf: "C64", Version, Laenge (2 Byte), JSON.
func WriteHeader(w io.Writer, h Header) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(b) > maxHeader {
		return errBadHeader
	}
	buf := make([]byte, 0, 6+len(b))
	buf = append(buf, magic[:]...)
	buf = append(buf, Version)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(b)))
	buf = append(buf, b...)
	_, err = w.Write(buf)
	return err
}

// ReadHeader liest den Kopf eines Daten-Streams.
func ReadHeader(r io.Reader) (Header, error) {
	var pre [6]byte
	if _, err := io.ReadFull(r, pre[:]); err != nil {
		return Header{}, err
	}
	if pre[0] != magic[0] || pre[1] != magic[1] || pre[2] != magic[2] || pre[3] == 0 || pre[3] > Version {
		return Header{}, errBadHeader
	}
	n := int(binary.BigEndian.Uint16(pre[4:]))
	if n == 0 || n > maxHeader {
		return Header{}, errBadHeader
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return Header{}, err
	}
	var h Header
	if err := json.Unmarshal(b, &h); err != nil {
		return Header{}, errBadHeader
	}
	return h, nil
}

// writeMsg/readMsg: Steuer-Nachrichten als JSON je Zeile (hoechstens 64 KB).
func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func readMsg(r *bufio.Reader, v any) error {
	line, err := r.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return fmt.Errorf("tunnel: control message too long")
		}
		return err
	}
	return json.Unmarshal(line, v)
}

func hostPort(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// Join kopiert zwischen zwei Verbindungen in beide Richtungen (halbes Schliessen, wo moeglich) und schliesst danach
// beide. Rueckgabe: Bytes a->b und b->a.
func Join(a, b net.Conn) (ab, ba int64) {
	done := make(chan struct{})
	go func() {
		ba, _ = io.Copy(a, b)
		closeWrite(a)
		close(done)
	}()
	ab, _ = io.Copy(b, a)
	closeWrite(b)
	<-done
	_ = a.Close()
	_ = b.Close()
	return ab, ba
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

// ---------------------------------------------------------------- Datagramme (KindQUIC)

// MaxDatagram: groesstes UDP-Datagramm, das durch den Tunnel geht.
const MaxDatagram = 65535

// WriteDatagram schreibt ein Datagramm mit 2 Byte Laenge davor.
func WriteDatagram(w io.Writer, p []byte) error {
	if len(p) > MaxDatagram {
		return errors.New("datagram too large")
	}
	var hdr [2]byte
	hdr[0], hdr[1] = byte(len(p)>>8), byte(len(p))
	if _, err := w.Write(append(hdr[:], p...)); err != nil {
		return err
	}
	return nil
}

// ReadDatagram liest ein Datagramm (buf muss MaxDatagram Bytes fassen).
func ReadDatagram(r io.Reader, buf []byte) (int, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}
	n := int(hdr[0])<<8 | int(hdr[1])
	if n > len(buf) {
		return 0, errors.New("datagram too large")
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return n, nil
}
