package privdrop

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestTarget(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		m        map[string]string
		uid, gid int
		bad      bool
	}{
		{m: nil, uid: 65532, gid: 65532},
		{m: map[string]string{"NODE64_UID": "1026"}, uid: 1026, gid: 1026},
		{m: map[string]string{"NODE64_UID": "1026", "NODE64_GID": "100"}, uid: 1026, gid: 100},
		{m: map[string]string{"NODE64_GID": " 100 "}, uid: 65532, gid: 100},
		{m: map[string]string{"NODE64_UID": "0"}, uid: 0, gid: 0},
		{m: map[string]string{"NODE64_UID": "admin"}, bad: true},
		{m: map[string]string{"NODE64_GID": "-1"}, bad: true},
	}
	for _, c := range cases {
		uid, gid, err := target(env(c.m))
		if c.bad {
			if err == nil {
				t.Errorf("%v: want error", c.m)
			}
			continue
		}
		if err != nil || uid != c.uid || gid != c.gid {
			t.Errorf("%v: got %d:%d %v, want %d:%d", c.m, uid, gid, err, c.uid, c.gid)
		}
	}
}

func TestOwn(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux only")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "backups")
	if err := os.Mkdir(sub, 0o500); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "node64.db")
	if err := os.WriteFile(file, []byte("x"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	var calls []string
	chown := func(p string, uid, gid int) error {
		calls = append(calls, filepath.Base(p))
		if filepath.Base(p) == "cert.pem" {
			return errors.New("read-only file system")
		}
		return nil
	}
	uid := os.Getuid() + 4242 // anderer Besitzer: alles muss uebergeben werden
	changed, failed, err := own(dir, uid, uid, chown)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 5 || failed != 1 || changed != 4 {
		t.Fatalf("calls %v changed %d failed %d", calls, changed, failed)
	}
	for p, want := range map[string]os.FileMode{sub: 0o700, file: 0o600} {
		info, _ := os.Stat(p)
		if info.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", p, info.Mode().Perm(), want)
		}
	}
	if info, _ := os.Stat("/etc/passwd"); info.Mode().Perm()&0o002 != 0 {
		t.Error("symlink target was changed")
	}

	// schon richtig: nichts zu tun
	os.Chmod(filepath.Join(dir, "cert.pem"), 0o600)
	calls = nil
	changed, failed, err = own(dir, os.Getuid(), os.Getgid(), chown)
	if err != nil || changed != 0 || failed != 0 || len(calls) != 0 {
		t.Fatalf("second run: calls %v changed %d failed %d err %v", calls, changed, failed, err)
	}

	// Fehler am Ordner selbst bricht ab
	if _, _, err := own(dir, uid, uid, func(string, int, int) error { return errors.New("denied") }); err == nil {
		t.Fatal("want error for the data dir itself")
	}
}

func TestWritable(t *testing.T) {
	dir := t.TempDir()
	if err := Writable(dir); err != nil {
		t.Fatal(err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatal("test file left behind")
	}
	err := Writable(filepath.Join(dir, "missing"))
	if err == nil || !strings.Contains(err.Error(), `user "0:0"`) {
		t.Fatalf("want hint, got %v", err)
	}
}
