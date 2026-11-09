package main

import (
	"os"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Der eingebaute Release-Schluessel ist derselbe wie fuer die Selbst-Updates von Node64 (Entscheidung 2026-11-09).
func TestReleaseKeyMatchesSelfUpdate(t *testing.T) {
	keys, err := m64agent.ParseReleaseKeys(ReleaseKeys)
	if err != nil || len(keys) == 0 {
		t.Fatalf("release keys %v %v", keys, err)
	}
	src, err := os.ReadFile("../../internal/selfupdate/keys.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range strings.Split(ReleaseKeys, ",") {
		if !strings.Contains(string(src), strings.TrimSpace(k)) {
			t.Fatalf("agent key %s not in internal/selfupdate/keys.go", k)
		}
	}
}
