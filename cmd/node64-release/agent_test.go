package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Kopfzeile fuer ein Agent-Update: Groesse, Pruefsumme und Signatur ueber m64proto.SignedMessage.
func TestAgentHeader(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bin := filepath.Join(t.TempDir(), "monitor64-agent-linux-amd64")
	data := []byte("\x7fELF agent")
	if err := os.WriteFile(bin, data, 0o755); err != nil {
		t.Fatal(err)
	}
	h, err := agentHeader(bin, "0.2.0", "linux", "amd64", priv)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if h.Size != int64(len(data)) || h.SHA256 != hex.EncodeToString(sum[:]) || h.Version != "0.2.0" {
		t.Fatalf("header %+v", h)
	}
	sig, _ := base64.StdEncoding.DecodeString(h.Signature)
	if !ed25519.Verify(pub, m64proto.SignedMessage(h.Version, h.OS, h.Arch, h.SHA256), sig) {
		t.Fatal("signature does not verify")
	}
	if ed25519.Verify(pub, m64proto.SignedMessage(h.Version, "windows", h.Arch, h.SHA256), sig) {
		t.Fatal("signature valid for another platform")
	}
}
