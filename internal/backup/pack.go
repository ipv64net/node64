package backup

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// File ist eine Datei im Archiv: Name (relativ zum Datenverzeichnis, mit /) und Quelle auf der Platte.
type File struct {
	Name string
	Path string
}

// Pack schreibt die Dateien als tar.gz.
func Pack(w io.Writer, files []File) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := addFile(tw, f); err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func addFile(tw *tar.Writer, f File) error {
	fh, err := os.Open(f.Path)
	if err != nil {
		return err
	}
	defer fh.Close()
	st, err := fh.Stat()
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: f.Name, Mode: 0o600, Size: st.Size(), ModTime: st.ModTime(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	_, err = io.CopyN(tw, fh, st.Size())
	return err
}

// ErrTooLarge: der Inhalt ist groesser als erlaubt.
var ErrTooLarge = errors.New("backup content too large")

// Unpack entpackt ein tar.gz nach dir (nur normale Dateien, keine Pfade nach oben, hoechstens maxBytes) und
// liefert die Namen.
func Unpack(r io.Reader, dir string, maxBytes int64) ([]string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	var names []string
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return names, nil
		}
		if err != nil {
			return names, err
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		name := path.Clean(h.Name)
		if name == "." || path.IsAbs(name) || name == ".." || strings.HasPrefix(name, "../") || strings.Contains(name, "\\") {
			return names, fmt.Errorf("invalid name in archive: %q", h.Name)
		}
		total += h.Size
		if h.Size < 0 || total > maxBytes {
			return names, ErrTooLarge
		}
		dest := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			return names, err
		}
		out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			return names, err
		}
		_, err = io.CopyN(out, tr, h.Size)
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return names, err
		}
		names = append(names, name)
	}
}
