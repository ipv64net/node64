// Package backup verschluesselt ein Node64-Backup mit einem Passwort (Archiv-Datei .n64backup).
//
// Aufbau: Kopf (Magic, Version, Salt, Nonce-Praefix), danach der Inhalt in Stuecken zu 64 KiB, je Stueck mit
// XChaCha20-Poly1305 verschluesselt (Nonce = Praefix | Zaehler | Ende-Merker). Abgeschnittene, vertauschte oder
// veraenderte Stuecke fallen beim Lesen auf. Der Schluessel kommt per Argon2id aus dem Passwort.
package backup

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Magic steht am Anfang jeder Archiv-Datei.
const Magic = "NODE64-BACKUP\n"

const (
	version   = 1
	chunkSize = 64 << 10
	saltLen   = 16
	prefixLen = 15 // + 8 Byte Zaehler + 1 Byte Ende-Merker = 24 Byte Nonce
)

var (
	ErrNotArchive = errors.New("not a node64 backup archive")
	ErrPassword   = errors.New("wrong password or damaged archive")
	ErrTruncated  = errors.New("backup archive is incomplete")
)

// IsArchive: beginnt die Datei mit dem Kopf eines Archivs?
func IsArchive(head []byte) bool {
	return len(head) >= len(Magic) && string(head[:len(Magic)]) == Magic
}

func deriveKey(password string, salt []byte) (cipher.AEAD, error) {
	return chacha20poly1305.NewX(argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, chacha20poly1305.KeySize))
}

func nonce(prefix []byte, n uint64, last bool) []byte {
	out := make([]byte, chacha20poly1305.NonceSizeX)
	copy(out, prefix)
	binary.BigEndian.PutUint64(out[prefixLen:], n)
	if last {
		out[len(out)-1] = 1
	}
	return out
}

type writer struct {
	w      io.Writer
	aead   cipher.AEAD
	prefix []byte
	n      uint64
	buf    []byte
	err    error
}

// NewWriter schreibt den Kopf und liefert einen Writer fuer den Inhalt; Close schreibt das letzte Stueck.
func NewWriter(w io.Writer, password string) (io.WriteCloser, error) {
	salt := make([]byte, saltLen)
	prefix := make([]byte, prefixLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(prefix); err != nil {
		return nil, err
	}
	aead, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	head := append([]byte(Magic), version)
	head = append(head, salt...)
	head = append(head, prefix...)
	if _, err := w.Write(head); err != nil {
		return nil, err
	}
	return &writer{w: w, aead: aead, prefix: prefix, buf: make([]byte, 0, chunkSize+1)}, nil
}

func (x *writer) seal(p []byte, last bool) error {
	_, err := x.w.Write(x.aead.Seal(nil, nonce(x.prefix, x.n, last), p, nil))
	x.n++
	return err
}

func (x *writer) Write(p []byte) (int, error) {
	if x.err != nil {
		return 0, x.err
	}
	n := len(p)
	for len(p) > 0 {
		k := min(chunkSize+1-len(x.buf), len(p))
		x.buf = append(x.buf, p[:k]...)
		p = p[k:]
		// ein volles Stueck erst schreiben, wenn danach noch etwas kommt (das letzte traegt den Ende-Merker)
		if len(x.buf) > chunkSize {
			if x.err = x.seal(x.buf[:chunkSize], false); x.err != nil {
				return 0, x.err
			}
			x.buf = append(x.buf[:0], x.buf[chunkSize:]...)
		}
	}
	return n, nil
}

func (x *writer) Close() error {
	if x.err != nil {
		return x.err
	}
	x.err = errors.New("closed")
	return x.seal(x.buf, true)
}

type reader struct {
	r      *bufio.Reader
	aead   cipher.AEAD
	prefix []byte
	n      uint64
	plain  []byte
	done   bool
	buf    []byte
}

// NewReader liest den Kopf; Fehler ErrNotArchive. Ein falsches Passwort faellt beim ersten Lesen auf (ErrPassword).
func NewReader(r io.Reader, password string) (io.Reader, error) {
	br := bufio.NewReaderSize(r, chunkSize+chacha20poly1305.Overhead+1)
	head := make([]byte, len(Magic)+1+saltLen+prefixLen)
	if _, err := io.ReadFull(br, head); err != nil || !IsArchive(head) || head[len(Magic)] != version {
		return nil, ErrNotArchive
	}
	salt := head[len(Magic)+1 : len(Magic)+1+saltLen]
	aead, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}
	return &reader{r: br, aead: aead, prefix: append([]byte(nil), head[len(Magic)+1+saltLen:]...), buf: make([]byte, chunkSize+chacha20poly1305.Overhead)}, nil
}

func (x *reader) Read(p []byte) (int, error) {
	for len(x.plain) == 0 {
		if x.done {
			return 0, io.EOF
		}
		k, err := io.ReadFull(x.r, x.buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			return 0, err
		}
		last := k < len(x.buf)
		if !last {
			if _, perr := x.r.Peek(1); perr == io.EOF {
				last = true
			}
		}
		out, oerr := x.aead.Open(x.buf[:0:0], nonce(x.prefix, x.n, last), x.buf[:k], nil)
		if oerr != nil {
			if x.n == 0 {
				return 0, ErrPassword
			}
			if last {
				return 0, ErrTruncated
			}
			return 0, ErrPassword
		}
		x.n++
		x.plain, x.done = out, last
	}
	n := copy(p, x.plain)
	x.plain = x.plain[n:]
	return n, nil
}
