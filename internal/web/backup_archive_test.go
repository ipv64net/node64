package web

import (
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/backup"
)

// Archiv mit Passwort: enthaelt Datenbank, secret.key und Moduldateien, aber keine Caches; Wiederherstellen
// auf einer anderen Node legt alles unter restore.new ab.
func TestBackupArchiveRoundTrip(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	dir := a.s.Cfg.DataDir
	os.WriteFile(filepath.Join(dir, "secret.key"), []byte("0123456789abcdef0123456789abcdef"), 0o600)
	os.MkdirAll(filepath.Join(dir, "dns64", "lists"), 0o750)
	os.WriteFile(filepath.Join(dir, "dns64", "allowlist.txt"), []byte("example.org\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "dns64", "lists", "big.txt"), []byte("cache"), 0o600)
	os.MkdirAll(filepath.Join(dir, "bin"), 0o750) // Selbst-Update: gehoert nicht ins Archiv
	os.WriteFile(filepath.Join(dir, "bin", "state.json"), []byte("{}"), 0o600)
	_ = a.store.SetSetting(ctx, SettingNodeName, "Keller")
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, page := a.get(t, "/settings")
	csrf := csrfOf(t, page)

	resp, _ := a.post(t, "/settings/backup", url.Values{"_csrf": {csrf}, "password": {"kurz"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("short password: %d", resp.StatusCode)
	}
	resp, body := a.post(t, "/settings/backup", url.Values{"_csrf": {csrf}, "password": {"backup-passwort"}})
	if resp.StatusCode != 200 || !backup.IsArchive([]byte(body)) || strings.Contains(body, "example.org") {
		t.Fatalf("archive: %d %q", resp.StatusCode, body[:min(len(body), 20)])
	}
	// Inhalt pruefen
	dec, err := backup.NewReader(strings.NewReader(body), "backup-passwort")
	if err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	names, err := backup.Unpack(dec, out, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(names, ",")
	for _, want := range []string{"node64.db", "secret.key", "dns64/allowlist.txt"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "lists/") || strings.Contains(got, ".backup-") || strings.Contains(got, "bin/") {
		t.Fatalf("cache or temp in archive: %s", got)
	}

	// Wiederherstellen auf einer anderen Node
	b := newTestApp(t)
	loginAs(t, b, "admin", "sehr geheimes passwort")
	_, page = b.get(t, "/settings")
	csrf2 := csrfOf(t, page)
	upload := func(pw string) {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		mw.WriteField("_csrf", csrf2)
		mw.WriteField("password", pw)
		fw, _ := mw.CreateFormFile("file", "x.n64backup")
		io.WriteString(fw, body)
		mw.Close()
		req, _ := http.NewRequest("POST", b.srv.URL+"/settings/restore", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := b.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	restored := filepath.Join(b.s.Cfg.DataDir, RestoreDirName)
	upload("falsches-passwort")
	if _, err := os.Stat(restored); err == nil {
		t.Fatal("restored with wrong password")
	}
	upload("backup-passwort")
	if k, _ := os.ReadFile(filepath.Join(restored, "secret.key")); string(k) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("secret.key not staged: %q", k)
	}
	if l, _ := os.ReadFile(filepath.Join(restored, "dns64", "allowlist.txt")); string(l) != "example.org\n" {
		t.Fatalf("allowlist not staged: %q", l)
	}
	if entries, _ := filepath.Glob(filepath.Join(b.s.Cfg.DataDir, "restore.tmp-*")); len(entries) > 0 {
		t.Fatalf("staging left over: %v", entries)
	}
}
