package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/agentdist"
	"github.com/ipv64net/node64/internal/selfupdate"
)

// Ablauf des Releases: Ordner mit den gebauten Dateien -> agent-index -> agent-sign (Plattform aus dem Dateinamen)
// -> sign. Das Ergebnis prueft die Node mit agentdist.Verify und agentdist.CheckHeader.
func TestAgentIndexRelease(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := []ed25519.PublicKey{pub}
	root := t.TempDir()
	dir := filepath.Join(root, "0.2.0")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, p := range agentdist.Platforms {
		name := filepath.Join(dir, agentdist.FileName(p.OS, p.Arch))
		if err := os.WriteFile(name, []byte("agent "+p.OS+"/"+p.Arch), 0o755); err != nil {
			t.Fatal(err)
		}
		files = append(files, name)
	}
	for _, s := range []string{"install.sh", "install.ps1"} {
		if err := os.WriteFile(filepath.Join(dir, s), []byte("# "+s+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out := filepath.Join(root, agentdist.IndexFile)
	if err := writeAgentIndex("v0.2.0", dir, out); err != nil {
		t.Fatal(err)
	}
	if err := agentSignFiles(files, "0.2.0", "", "", priv); err != nil {
		t.Fatal(err)
	}
	// zweiter Lauf mit dem Muster monitor64-agent-* (enthaelt jetzt die Kopfzeilen): keine Kopfzeile der Kopfzeile
	all, _ := filepath.Glob(filepath.Join(dir, "monitor64-agent-*"))
	if err := agentSignFiles(all, "0.2.0", "", "", priv); err != nil {
		t.Fatal(err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.update.json.update.json")); len(left) > 0 {
		t.Fatalf("header of a header: %v", left)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := agentdist.Verify(raw, selfupdate.Sign(raw, priv), keys)
	if err != nil {
		t.Fatal(err)
	}
	if ix.Version != "0.2.0" || len(ix.Files) != len(agentdist.Platforms) || len(ix.Scripts) != 2 {
		t.Fatalf("index: %+v", ix)
	}
	if f := ix.Files["linux-armv7"]; f.Arch != "arm" || f.Name != "monitor64-agent-linux-armv7" {
		t.Fatalf("armv7: %+v", f)
	}
	for _, f := range ix.Files {
		b, err := os.ReadFile(filepath.Join(dir, f.Name+agentdist.HeaderSuffix))
		if err != nil {
			t.Fatal(err)
		}
		var h m64proto.UpdateHeader
		if err := json.Unmarshal(b, &h); err != nil {
			t.Fatal(err)
		}
		if err := agentdist.CheckHeader(h, ix.Version, f, keys); err != nil {
			t.Errorf("%s: %v", f.Name, err)
		}
	}
	sums, err := os.ReadFile(filepath.Join(dir, agentdist.SumsFile))
	if err != nil || strings.Count(string(sums), "\n") != len(agentdist.Platforms) || !strings.Contains(string(sums), "  monitor64-agent-windows-amd64.exe\n") {
		t.Fatalf("SHA256SUMS: %v\n%s", err, sums)
	}
	// "sign" prueft das Verzeichnis wie ein Manifest (Version und Dateien)
	if _, err := selfupdate.Verify(raw, selfupdate.Sign(raw, priv), keys); err != nil {
		t.Fatalf("sign would refuse the index: %v", err)
	}
	// unbekannter Dateiname ohne -os/-arch
	odd := filepath.Join(dir, "agent.bin")
	_ = os.WriteFile(odd, []byte("x"), 0o644)
	if err := agentSignFiles([]string{odd}, "0.2.0", "", "", priv); err == nil {
		t.Fatal("file without platform in its name accepted")
	}
	if err := agentSignFiles([]string{odd}, "0.2.0", "linux", "amd64", priv); err != nil {
		t.Fatal(err)
	}
}

// Die Version des Agents steht in cmd/monitor64-agent/VERSION (eigene Version, nicht die der Node); der Build setzt
// sie mit -X main.Version.
func TestAgentVersionFile(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "monitor64-agent", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if v := strings.TrimSpace(string(b)); !agentdist.ValidVersion(v) {
		t.Fatalf("cmd/monitor64-agent/VERSION: %q is not MAJOR.MINOR.PATCH[-pre]", v)
	}
}
