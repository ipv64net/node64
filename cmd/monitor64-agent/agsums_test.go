package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AG-2 (Sicherheits-Review 2026-11-15): Programm und SHA256SUMS kamen aus derselben Quelle ohne Signatur - wer beide
// austauscht, kam durch. Jetzt sichert die Pruefsumme der Node (--sums-sha256) bzw. die Signatur SHA256SUMS.sig
// (ed25519, Release-Schluessel, OpenSSL ab 3.0) SHA256SUMS ab.

const agKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIETckeS39th4eGsSzZlxN5qpGWW+u7VErd1nfg8mRDnw node64@nas"

func agLinux(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	return runInstallSh(t, "Linux", "x86_64", "monitor64-agent-linux-amd64", map[string]string{"curl": "curl", "sha256sum": "sha256sum"},
		append([]string{"--key", agKey}, args...)...)
}

func agHook(t *testing.T, f func(dir string, sums []byte)) {
	t.Helper()
	installSumsHook = f
	t.Cleanup(func() { installSumsHook = nil })
}

func TestAG2SumsFromNode(t *testing.T) {
	installSumsArgs = func(sums []byte) []string {
		h := sha256.Sum256(sums)
		return []string{"--sums-sha256", hex.EncodeToString(h[:])}
	}
	out, called, err := agLinux(t)
	installSumsArgs = nil
	if err != nil || called == "" || !strings.Contains(out, "SHA256SUMS confirmed by the node") {
		t.Fatalf("passende Pruefsumme: %v %q\n%s", err, called, out)
	}
	if strings.Contains(out, "SHA256SUMS.sig") {
		t.Errorf("Signatur geladen, obwohl die Node die Pruefsumme nennt:\n%s", out)
	}
	// ausgetauschte SHA256SUMS (samt passendem Programm): abgelehnt, nichts gestartet
	out, called, err = agLinux(t, "--sums-sha256", strings.Repeat("ab", 32))
	if err == nil || called != "" || !strings.Contains(out, "does not match the checksum from the node") {
		t.Fatalf("falsche Pruefsumme: %v %q\n%s", err, called, out)
	}
	for _, bad := range []string{"xyz", strings.Repeat("A", 64), strings.Repeat("a", 63)} {
		if out, called, err := agLinux(t, "--sums-sha256="+bad); err == nil || called != "" || !strings.Contains(out, "invalid --sums-sha256") {
			t.Errorf("%q angenommen: %v\n%s", bad, err, out)
		}
	}
}

func TestAG2Signature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Skript mit dem Test-Schluessel statt des Release-Schluessels
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	testPEM := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	const rel = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEACKADRKNeeSdwpqmdt9saWJw1i92EQJdsxmQOs6m/iAw=\n-----END PUBLIC KEY-----"
	if !strings.Contains(string(b), rel) {
		t.Fatal("Release-Schluessel nicht im Skript")
	}
	script := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(script, []byte(strings.Replace(string(b), rel, testPEM, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	installScript, installExtraTools = script, []string{"openssl"}
	t.Cleanup(func() { installScript, installExtraTools = "install.sh", nil })

	sign := func(content []byte) func(string, []byte) {
		return func(dir string, sums []byte) {
			if content == nil {
				content = sums
			}
			sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, content)) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), []byte(sig), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	agHook(t, sign(nil))
	out, called, err := agLinux(t)
	if strings.Contains(out, "OpenSSL 3.0 or newer is required") {
		t.Skip("OpenSSL ohne ed25519 (pkeyutl -rawin)")
	}
	if err != nil || called == "" || !strings.Contains(out, "signature of SHA256SUMS ok") {
		t.Fatalf("gueltige Signatur: %v %q\n%s", err, called, out)
	}
	// Signatur passt nicht (SHA256SUMS ausgetauscht): abgelehnt, nichts gestartet
	agHook(t, sign([]byte("0000  monitor64-agent-linux-amd64\n")))
	out, called, err = agLinux(t)
	if err == nil || called != "" || !strings.Contains(out, "invalid signature of SHA256SUMS") {
		t.Fatalf("falsche Signatur: %v %q\n%s", err, called, out)
	}
	// keine Signatur (z. B. aelteres Release, eigene Node): Warnung, Installation laeuft
	installSumsHook = nil
	out, called, err = agLinux(t)
	if err != nil || called == "" || !strings.Contains(out, "WARNING: no signature") {
		t.Fatalf("ohne Signatur: %v %q\n%s", err, called, out)
	}
}

// Der Release-Schluessel im Skript ist derselbe wie im Agent (main.ReleaseKeys) - sonst passte keine Signatur.
func TestAG2ScriptKeyMatchesRelease(t *testing.T) {
	b, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	i, j := strings.Index(string(b), "-----BEGIN PUBLIC KEY-----"), strings.Index(string(b), "-----END PUBLIC KEY-----")
	if i < 0 || j < i {
		t.Fatal("kein Schluessel im Skript")
	}
	blk, _ := pem.Decode([]byte(string(b)[i:j+len("-----END PUBLIC KEY-----")] + "\n"))
	if blk == nil {
		t.Fatal("kein Schluessel im Skript")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(k.(ed25519.PublicKey)); !strings.Contains(ReleaseKeys, got) {
		t.Fatalf("Skript-Schluessel %s nicht in ReleaseKeys %s", got, ReleaseKeys)
	}
}
