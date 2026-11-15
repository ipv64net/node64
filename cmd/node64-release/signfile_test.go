package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AG-2: sign-file signiert SHA256SUMS (Format wie manifest.json.sig: base64 ed25519 ueber den Inhalt, Zeilenende),
// install.sh prueft die Signatur mit OpenSSL gegen den Release-Schluessel.
func TestSignFile(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte(base64.StdEncoding.EncodeToString(priv.Seed())), 0o600); err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(dir, "SHA256SUMS")
	content := []byte(strings.Repeat("a", 64) + "  monitor64-agent-linux-amd64\n")
	if err := os.WriteFile(sums, content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := signFile([]string{"-key", keyFile, sums}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(sums + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(b), "\n") {
		t.Error("ohne Zeilenende")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || !ed25519.Verify(pub, content, sig) {
		t.Fatalf("Signatur ungueltig: %v", err)
	}
	if err := signFile([]string{"-key", keyFile}); err == nil {
		t.Error("ohne Datei angenommen")
	}
}
