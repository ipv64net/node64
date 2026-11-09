//go:build linux || windows

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// testKey liefert einen gueltigen oeffentlichen Schluessel im authorized_keys-Format.
func testKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp))) + " " + comment
}

// CL5: ein addKey fuer Linux und Windows - auch unter Linux bleibt aus einer unter Windows bearbeiteten Liste (CRLF)
// kein \r zurueck.
func TestAddKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "keys")
	k1, k2 := testKey(t, "node64@nas"), testKey(t, "node64@b")
	if added, err := addKey(p, k1); err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	// gleicher Schluessel mit anderem Kommentar bzw. CRLF in der Datei: nicht doppelt
	if err := os.WriteFile(p, []byte(k1+"\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if added, err := addKey(p, strings.TrimSuffix(k1, " node64@nas")+" anders"); err != nil || added {
		t.Fatalf("doppelt: %v %v", added, err)
	}
	if added, err := addKey(p, k2); err != nil || !added {
		t.Fatalf("%v %v", added, err)
	}
	b, _ := os.ReadFile(p)
	if strings.Count(string(b), "ssh-ed25519") != 2 || strings.Contains(string(b), "\r") {
		t.Fatalf("%q", b)
	}
}

func TestCheckInstallArgs(t *testing.T) {
	k := testKey(t, "node64@nas")
	if got, err := checkInstallArgs("  "+k+"\r\n", 6465); err != nil || got != k {
		t.Fatalf("%q %v", got, err)
	}
	for _, bad := range []struct {
		key  string
		port int
	}{{"", 6465}, {"kein schluessel", 6465}, {k + "\n" + k, 6465}, {k, 0}, {k, 70000}} {
		if _, err := checkInstallArgs(bad.key, bad.port); err == nil {
			t.Errorf("%q %d angenommen", bad.key, bad.port)
		}
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src, dst := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.WriteFile(src, []byte("neu"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("alt"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(src, dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "neu" {
		t.Fatalf("%q", b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("Reste: %v", ents)
	}
}

// WI5: der Einzeiler im Kopf von install.ps1 schaltet TLS 1.2 ein, bevor irm das Skript laedt (Server 2016).
func TestInstallPS1OneLiner(t *testing.T) {
	b, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "irm https://"); i >= 0 {
			if tls := strings.Index(line, "SecurityProtocol -bor 3072;"); tls < 0 || tls > i {
				t.Errorf("TLS 1.2 nicht vor irm: %s", line)
			}
			return
		}
	}
	t.Fatal("Einzeiler fehlt")
}
