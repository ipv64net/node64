package honeypot

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// tailTest ist ein Dateileser ohne Hintergrund-Abfrage: der Test ruft poll selbst auf (kein Warten auf LogPoll).
type tailTest struct {
	*logTailer
	mu    sync.Mutex
	lines []LogLine
}

func newTailTest(t *testing.T) *tailTest {
	t.Helper()
	tt := &tailTest{}
	clock := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	tt.logTailer = newLogTailer(nil, func(l LogLine) {
		tt.mu.Lock()
		tt.lines = append(tt.lines, l)
		tt.mu.Unlock()
	}, func() time.Time { return clock })
	t.Cleanup(tt.stop)
	return tt
}

// take liefert die Nachrichten seit dem letzten Aufruf.
func (tt *tailTest) take() []string {
	tt.mu.Lock()
	defer tt.mu.Unlock()
	var out []string
	for _, l := range tt.lines {
		out = append(out, l.Message)
	}
	tt.lines = nil
	return out
}

func (tt *tailTest) expect(t *testing.T, want ...string) {
	t.Helper()
	tt.poll()
	if got := tt.take(); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// release gibt unter Windows den Griff des Lesers frei (dort laesst sich eine offene Datei nicht umbenennen); die
// Kennung der Datei bleibt, so wie nach einem Lesefehler.
func (tt *tailTest) release(p string) {
	if runtime.GOOS != "windows" {
		return
	}
	tt.logTailer.mu.Lock()
	defer tt.logTailer.mu.Unlock()
	if tf := tt.files[p]; tf != nil {
		tf.close()
	}
}

func TestLogTailStartsAtEnd(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "old 1\nold 2\n")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: p, Format: "nginx"}})
	if got := tt.take(); len(got) != 0 {
		t.Fatalf("old lines read: %q", got)
	}
	appendFile(t, p, "new 1\r\nnew 2\npart")
	tt.expect(t, "new 1", "new 2")
	tt.expect(t)
	appendFile(t, p, "ial\n\n")
	tt.expect(t, "partial")
	st := tt.status()
	if len(st) != 1 || !st[0].OK || st[0].Lines != 3 || st[0].Format != "nginx" || st[0].Last.IsZero() {
		t.Fatalf("status %+v", st)
	}
}

func TestLogTailLongLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: p}})
	appendFile(t, p, strings.Repeat("a", LogMaxLine+5000)+"\nshort\n")
	tt.poll()
	got := tt.take()
	if len(got) != 2 || len(got[0]) != LogMaxLine || got[1] != "short" {
		t.Fatalf("got %d lines, first %d bytes", len(got), len(got[0]))
	}
}

func TestLogTailTruncate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: p}})
	appendFile(t, p, "line one is long enough\n")
	tt.expect(t, "line one is long enough")
	if err := os.Truncate(p, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, p, "after\n")
	tt.expect(t, "after")
}

func TestLogTailRotate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "auth.log")
	appendFile(t, p, "old\n")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: p}})
	appendFile(t, p, "before\n")
	tt.expect(t, "before")
	tt.release(p)
	if err := os.Rename(p, p+".1"); err != nil {
		t.Fatal(err)
	}
	var want []string
	if runtime.GOOS != "windows" { // Schreiber hat die alte noch offen: der Rest wird gelesen, solange die neue fehlt
		appendFile(t, p+".1", "late\n")
		want = append(want, "late")
	}
	tt.expect(t, want...) // neue Datei fehlt noch: die alte bleibt
	appendFile(t, p, "fresh 1\nfresh 2\n")
	tt.expect(t, "fresh 1", "fresh 2")
	appendFile(t, p, "fresh 3\n")
	tt.expect(t, "fresh 3")
}

func TestLogTailMissingThenAppears(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "later.log")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: p}})
	st := tt.status()
	if len(st) != 1 || st[0].OK || st[0].Error != "file not found" {
		t.Fatalf("status %+v", st)
	}
	appendFile(t, p, "first\n") // neu erschienen: von vorn
	tt.expect(t, "first")
	if st := tt.status(); !st[0].OK || st[0].Error != "" {
		t.Fatalf("status %+v", st)
	}
	tt.release(p)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	tt.expect(t)
	appendFile(t, p, "again\n") // geloescht und neu angelegt: von vorn
	tt.expect(t, "again")
}

func TestLogTailGlob(t *testing.T) {
	dir := t.TempDir()
	appendFile(t, filepath.Join(dir, "a.log"), "old a\n")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: filepath.Join(dir, "*.log")}})
	if got := tt.take(); len(got) != 0 {
		t.Fatalf("old lines read: %q", got)
	}
	appendFile(t, filepath.Join(dir, "b.log"), "new b\n")
	appendFile(t, filepath.Join(dir, "c.log.gz"), "zipped\n")
	tt.expect(t, "new b")
	appendFile(t, filepath.Join(dir, "a.log"), "more a\n")
	tt.expect(t, "more a")
	if st := tt.status(); len(st) != 2 {
		t.Fatalf("status %+v", st)
	}

	// Muster ohne Treffer
	tt.setFiles([]LogFile{{Path: filepath.Join(dir, "none*.log")}})
	if st := tt.status(); len(st) != 1 || st[0].Error != "no matching file" {
		t.Fatalf("status %+v", st)
	}
}

func TestLogTailGlobRotatedNotReread(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "app.log")
	appendFile(t, p, "")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: filepath.Join(dir, "app*.log")}})
	appendFile(t, p, "one\n")
	tt.expect(t, "one")
	tt.release(p)
	if err := os.Rename(p, filepath.Join(dir, "app1.log")); err != nil { // passt weiter zum Muster
		t.Fatal(err)
	}
	appendFile(t, p, "two\n")
	tt.expect(t, "two")
}

func TestLogTailMaxFiles(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < LogMaxFiles+3; i++ {
		appendFile(t, filepath.Join(dir, "f"+itoa(100+i)+".log"), "")
	}
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: filepath.Join(dir, "*.log")}})
	st := tt.status()
	if len(st) != LogMaxFiles+1 || !strings.HasPrefix(st[LogMaxFiles].Error, "too many files") {
		t.Fatalf("%d status entries, last %+v", len(st), st[len(st)-1])
	}
}

func TestLogTailDirectory(t *testing.T) {
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: t.TempDir()}})
	if st := tt.status(); st[0].OK || st[0].Error != "is a directory" {
		t.Fatalf("status %+v", st)
	}
}

func TestLogTailDetectFormat(t *testing.T) {
	dir := t.TempDir()
	caddy := filepath.Join(dir, "caddy-access.log")
	auto := filepath.Join(dir, "other.log")
	appendFile(t, caddy, "")
	appendFile(t, auto, "")
	tt := newTailTest(t)
	tt.setFiles([]LogFile{{Path: caddy}, {Path: auto}})
	appendFile(t, caddy, `{"request":{"remote_ip":"203.0.113.1"},"status":200}`+"\n")
	appendFile(t, auto, "Oct 20 12:00:01 host sshd[1]: hello\n")
	tt.poll()
	st := tt.status()
	if st[0].Format != "caddy" || st[1].Format != "syslog" {
		t.Fatalf("formats %q %q", st[0].Format, st[1].Format)
	}
	tt.mu.Lock()
	defer tt.mu.Unlock()
	if len(tt.lines) != 2 || tt.lines[1].Program != "sshd" || tt.lines[1].Message != "hello" || tt.lines[1].Origin != SrcLog {
		t.Fatalf("lines %+v", tt.lines)
	}
}

func TestLogDetectName(t *testing.T) {
	for p, want := range map[string]string{
		"/host/log/auth.log":                        "syslog",
		"/host/log/secure":                          "syslog",
		"/host/log/mail.log":                        "syslog",
		"/host/log/messages":                        "syslog",
		"/host/log/nginx/access.log":                "nginx",
		"/host/log/apache2/other_vhosts_access.log": "nginx",
		"/host/log/caddy/access.log":                "caddy",
		"/data/logs/nextcloud.log":                  "nextcloud",
		"/data/logs/vaultwarden.log":                "vaultwarden",
		"/data/logs/gitea/gitea.log":                "gitea",
		"/data/logs/home-assistant.log":             "homeassistant",
		"/host/log/pve/tasks/active":                "proxmox",
		"/host/log/random.txt":                      "",
	} {
		if got := logDetectName(p); got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
}

func TestLogDetectContent(t *testing.T) {
	for s, want := range map[string]string{
		`{"level":"info","request":{"remote_ip":"1.2.3.4"}}`:                                 "caddy",
		`{"reqId":"x","remoteAddr":"1.2.3.4","message":"Login failed"}`:                      "nextcloud",
		"Oct  2 12:00:01 host sshd[1]: x":                                                    "syslog",
		"2026-10-20T12:00:01.5+02:00 host sshd[1]: x":                                        "syslog",
		`203.0.113.1 - - [20/Oct/2026:12:00:01 +0200] "GET / HTTP/1.1" 200 1 "-" "-"`:        "nginx",
		"[2026-10-20 12:00:01.123][vaultwarden::api::identity][ERROR] x":                     "vaultwarden",
		"2026/10/20 12:00:01 ...ers/web/auth/auth.go:231:SignInPost() [I] x":                 "gitea",
		"2026-10-20 12:00:01.123 WARNING (MainThread) [homeassistant.components.http.ban] x": "homeassistant",
		"2026/10/20 12:00:01 [error] 12#12: *1 open() failed":                                "",
		"just text": "",
	} {
		if got := logDetectContent(s); got != want {
			t.Errorf("%q: %q, want %q", s, got, want)
		}
	}
}

func TestLogParseSyslogFile(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		in, host, prog, msg string
		tm                  time.Time
	}{
		{"Oct 20 11:59:58 box sshd[123]: Failed password", "box", "sshd", "Failed password", now},
		{"Oct  2 11:59:58 box postfix/smtpd[9]: warning: x", "box", "postfix/smtpd", "warning: x", now},
		{"2026-10-20T13:59:58.123+02:00 box sshd-session[1]: hi", "box", "sshd-session", "hi", time.Date(2026, 10, 20, 11, 59, 58, 123e6, time.UTC)},
		{"2026-10-21T13:59:58+02:00 box kernel: future", "box", "kernel", "future", now},
		{"Oct 20 11:59:58 box no tag here", "box", "", "no tag here", now},
	}
	for _, c := range cases {
		tm, host, prog, msg, ok := logParseSyslogFile(c.in, now)
		if !ok || host != c.host || prog != c.prog || msg != c.msg || !tm.Equal(c.tm) {
			t.Errorf("%q: %v %q %q %q %v", c.in, ok, host, prog, msg, tm)
		}
	}
	if _, _, _, _, ok := logParseSyslogFile("garbage line", now); ok {
		t.Error("garbage parsed")
	}
	l := logFileLine("nginx", "f", `203.0.113.1 - - [20/Oct/2026:13:59:00 +0200] "GET / HTTP/1.1" 200 1 "-" "-"`, now)
	if !l.Time.Equal(time.Date(2026, 10, 20, 11, 59, 0, 0, time.UTC)) || l.Origin != SrcLog || l.File != "f" {
		t.Errorf("nginx line %+v", l)
	}
}
