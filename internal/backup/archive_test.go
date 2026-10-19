package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func seal(t *testing.T, data []byte, pw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewWriter(&buf, pw)
	if err != nil {
		t.Fatal(err)
	}
	// in ungleichen Stuecken schreiben
	for p := data; len(p) > 0; {
		k := min(len(p), 7777)
		if _, err := w.Write(p[:k]); err != nil {
			t.Fatal(err)
		}
		p = p[k:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func open(enc []byte, pw string) ([]byte, error) {
	r, err := NewReader(bytes.NewReader(enc), pw)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func TestRoundTrip(t *testing.T) {
	for _, size := range []int{0, 1, chunkSize - 1, chunkSize, chunkSize + 1, 3*chunkSize + 17} {
		data := make([]byte, size)
		rand.Read(data)
		enc := seal(t, data, "geheimes passwort")
		if !IsArchive(enc) {
			t.Fatal("magic missing")
		}
		got, err := open(enc, "geheimes passwort")
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("size %d: %v (len %d)", size, err, len(got))
		}
	}
}

func TestWrongPasswordAndTampering(t *testing.T) {
	data := make([]byte, 2*chunkSize+5)
	rand.Read(data)
	enc := seal(t, data, "richtig-123")
	if _, err := open(enc, "falsch-123"); !errors.Is(err, ErrPassword) {
		t.Fatalf("wrong password: %v", err)
	}
	// abgeschnitten an einer Stueckgrenze
	cut := enc[:len(enc)-(5+16)]
	if _, err := open(cut, "richtig-123"); !errors.Is(err, ErrTruncated) {
		t.Fatalf("truncated: %v", err)
	}
	// ein Byte veraendert
	bad := append([]byte(nil), enc...)
	bad[len(bad)/2] ^= 1
	if _, err := open(bad, "richtig-123"); err == nil {
		t.Fatal("tampering not detected")
	}
	if _, err := NewReader(bytes.NewReader([]byte("SQLite format 3\x00")), "x"); !errors.Is(err, ErrNotArchive) {
		t.Fatalf("not archive: %v", err)
	}
}

func TestPackUnpack(t *testing.T) {
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "a"), []byte("eins"), 0o600)
	os.WriteFile(filepath.Join(src, "b"), []byte("zwei"), 0o600)
	var buf bytes.Buffer
	if err := Pack(&buf, []File{{Name: "node64.db", Path: filepath.Join(src, "a")}, {Name: "dns64/allowlist.txt", Path: filepath.Join(src, "b")}}); err != nil {
		t.Fatal(err)
	}
	dst := t.TempDir()
	names, err := Unpack(bytes.NewReader(buf.Bytes()), dst, 1<<20)
	if err != nil || len(names) != 2 {
		t.Fatalf("unpack: %v %v", names, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dst, "dns64", "allowlist.txt")); string(b) != "zwei" {
		t.Fatalf("content: %q", b)
	}
	if _, err := Unpack(bytes.NewReader(buf.Bytes()), t.TempDir(), 5); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("limit: %v", err)
	}
	// Pfad nach oben wird abgelehnt
	var evil bytes.Buffer
	gz := gzip.NewWriter(&evil)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../x", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
	tw.Write([]byte("x"))
	tw.Close()
	gz.Close()
	if _, err := Unpack(&evil, t.TempDir(), 1<<20); err == nil {
		t.Fatal("path traversal accepted")
	}
}
