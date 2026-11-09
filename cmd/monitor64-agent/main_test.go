package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64agent"
)

func TestParseRunFlags(t *testing.T) {
	f, err := parseRunFlags([]string{"--port", "16465", "--dir", "/tmp/m64"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.port != 16465 || f.keys != filepath.Join("/tmp/m64", "keys") || f.hostKey != filepath.Join("/tmp/m64", "hostkey") ||
		f.localDir != filepath.Join("/tmp/m64", "local.d") {
		t.Fatalf("flags = %+v", f)
	}
	for _, bad := range [][]string{{"--port", "0"}, {"--port", "70000"}, {"extra"}, {"--unknown"}} {
		if _, err := parseRunFlags(bad, io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}

// S1-K4: der Start einer neuen Version wird gezaehlt, bevor Flags (oder Schluessel) ausgewertet werden - scheitert
// sie schon daran, faellt der naechste Start auf die alte Version zurueck.
func TestRunCountsUpdateStartFirst(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "monitor64-agent")
	for p, b := range map[string]string{exe: "new", exe + ".old": "old"} {
		if err := os.WriteFile(p, []byte(b), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	oldV, oldR := Version, restartFn
	defer func() { Version, restartFn = oldV, oldR }()
	Version = "1.3.0"
	restarted := 0
	restartFn = func(string) error { restarted++; return errors.New("test: no exec") }
	if err := m64agent.WriteUpdateMarker(exe, "1.2.0", "v1.3.0"); err != nil {
		t.Fatal(err)
	}
	if code := runAgent(exe, []string{"--unknown-flag"}); code != 2 {
		t.Fatalf("first start: code %d", code)
	}
	b, err := os.ReadFile(exe + ".update")
	if err != nil || !strings.Contains(string(b), `"starts":1`) {
		t.Fatalf("start not counted before the flags: %q %v", b, err)
	}
	if code := runAgent(exe, []string{"--unknown-flag"}); code != 1 || restarted != 1 {
		t.Fatalf("second start: code %d restarted %d", code, restarted)
	}
	if b, _ := os.ReadFile(exe); string(b) != "old" {
		t.Fatalf("exe after rollback = %q", b)
	}
}
