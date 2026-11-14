package cdn64

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Zugriffs-Log zusaetzlich als Datei (#74): <data>/cdn64/access.log im nginx-Format "combined" mit dem Namen des Hosts
// vorn (wie nginx '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer"
// "$http_user_agent"'), damit CrowdSec (Parser crowdsecurity/nginx-logs) und andere Werkzeuge es lesen koennen. Eine
// Zeile je HTTP-Anfrage aller Hosts, auch abgewiesene (mit dem Status der Antwort) und ungebremst - unabhaengig vom
// Einzel-Log der Hosts. Verbindungen vor der ersten Anfrage und Streams fehlen (keine HTTP-Anfrage). Wird die Datei
// groesser als eingestellt, wird sie zu access.log.1 (eine alte Datei bleibt; CrowdSec folgt dem Umbenennen).
// Geschrieben wird vom Schreiber der Statistik (statslog.go), gepuffert, alle 2 Sekunden auf die Platte.

const (
	setAccessFile   = "cdn64.access_file"    // "1" = an
	setAccessFileMB = "cdn64.access_file_mb" // Groesse bis zum Wechsel in MB
	accessFileName  = "access.log"
	accessFileDefMB = 50
	accessFileMaxMB = 1000
)

// accessFileSettings: eingeschaltet und Groesse in MB (Standard 50).
func (m *Module) accessFileSettings(ctx context.Context) (bool, int) {
	mb, err := strconv.Atoi(m.core.SettingOr(ctx, setAccessFileMB, ""))
	if err != nil || mb < 1 || mb > accessFileMaxMB {
		mb = accessFileDefMB
	}
	return m.core.SettingOr(ctx, setAccessFile, "0") == "1", mb
}

// accessFileApply gibt die Einstellungen an den Schreiber weiter (Start und Speichern).
func (m *Module) accessFileApply(ctx context.Context) {
	if sdb := m.stats2.Load(); sdb != nil {
		on, mb := m.accessFileSettings(ctx)
		sdb.afMax.Store(int64(mb) << 20)
		sdb.afOn.Store(on)
	}
}

// accessFile ist die offene Datei (nur der Schreiber der Statistik benutzt sie).
type accessFile struct {
	path   string
	log    *slog.Logger
	f      *os.File
	w      *bufio.Writer
	size   int64
	failed time.Time // letzter Fehler beim Oeffnen (neuer Versuch nach einer Minute)
}

// accessLine: eine Anfrage fuer die Datei (false = keine HTTP-Anfrage: Verbindung, Stream).
func accessLine(h hit, anon bool) (string, bool) {
	if h.conn || h.status == 0 || !strings.HasPrefix(h.path, "/") && h.path != "*" {
		return "", false
	}
	client := h.client.String()
	if anon { // gekuerzt wie im Zugriffs-Log, als Adresse (Parser erwarten eine IP)
		bits := 48
		if h.client.Is4() {
			bits = 24
		}
		if p, err := h.client.Prefix(bits); err == nil {
			client = p.Addr().String()
		}
	}
	host := h.host
	if host == "" {
		host = "-"
	}
	proto := h.proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	var b strings.Builder
	b.Grow(160 + len(h.path) + len(h.ua) + len(h.ref))
	b.WriteString(logEsc(host, false))
	b.WriteByte(' ')
	b.WriteString(client)
	b.WriteString(" - - [")
	b.WriteString(h.time.Format("02/Jan/2006:15:04:05 -0700"))
	b.WriteString("] \"")
	b.WriteString(logEsc(h.method, false))
	b.WriteByte(' ')
	b.WriteString(logEsc(h.path, true))
	b.WriteByte(' ')
	b.WriteString(logEsc(proto, false))
	b.WriteString("\" ")
	b.WriteString(strconv.Itoa(h.status))
	b.WriteByte(' ')
	b.WriteString(strconv.FormatInt(h.bytes, 10))
	b.WriteString(" \"")
	b.WriteString(dash(logEsc(h.ref, true)))
	b.WriteString("\" \"")
	b.WriteString(dash(logEsc(h.ua, true)))
	b.WriteString("\"\n")
	return b.String(), true
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// logEsc schreibt Steuerzeichen, Anfuehrungszeichen und Backslash als \xHH (wie nginx); ohne quoted auch Leerzeichen
// (Felder ohne Anfuehrungszeichen bleiben so ein Feld).
func logEsc(s string, quoted bool) string {
	clean := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c == 0x7f || c == '"' || c == '\\' {
			if c == ' ' && quoted {
				continue
			}
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x21 && !(c == ' ' && quoted) || c == 0x7f || c == '"' || c == '\\' {
			b.WriteString(`\x`)
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// write haengt eine Zeile an; wird die Datei zu gross, wird sie vorher zu access.log.1.
func (a *accessFile) write(line string, max int64) {
	if a.f != nil && a.size+int64(len(line)) > max && a.size > 0 {
		a.rotate()
	}
	if a.f == nil && !a.open() {
		return
	}
	n, err := a.w.WriteString(line)
	a.size += int64(n)
	if err != nil {
		a.log.Warn("cdn64 access log file not written", "err", err)
		a.close()
	}
}

func (a *accessFile) open() bool {
	if !a.failed.IsZero() && time.Since(a.failed) < time.Minute {
		return false
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o750); err != nil {
		a.fail(err)
		return false
	}
	f, err := os.OpenFile(a.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		a.fail(err)
		return false
	}
	var size int64
	if fi, err := f.Stat(); err == nil {
		size = fi.Size()
	}
	a.f, a.w, a.size, a.failed = f, bufio.NewWriterSize(f, 64<<10), size, time.Time{}
	return true
}

func (a *accessFile) fail(err error) {
	if a.failed.IsZero() {
		a.log.Warn("cdn64 access log file not opened", "path", a.path, "err", err)
	}
	a.failed = time.Now()
}

func (a *accessFile) rotate() {
	a.close()
	if err := os.Rename(a.path, a.path+".1"); err != nil && !os.IsNotExist(err) {
		a.log.Warn("cdn64 access log file not rotated", "err", err)
	}
}

func (a *accessFile) flush() {
	if a.w != nil {
		if err := a.w.Flush(); err != nil {
			a.log.Warn("cdn64 access log file not written", "err", err)
			a.close()
		}
	}
}

func (a *accessFile) close() {
	if a.f == nil {
		return
	}
	_ = a.w.Flush()
	_ = a.f.Close()
	a.f, a.w, a.size = nil, nil, 0
}
