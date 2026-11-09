package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ipv64net/node64/internal/m64agent"
)

const tok = "abcdefghijklmnopqrstuvwxyz"

func TestRunFlagsPush(t *testing.T) {
	dir := t.TempDir()
	f, err := parseRunFlags([]string{"--dir", dir, "--connect", tok + "@node.example", "--connect", tok + "@[2001:db8::1]:7000",
		"--no-listen"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if !f.noListen || len(f.connect) != 2 || f.connect[0].Addr != "node.example:6466" || f.connect[1].Addr != "[2001:db8::1]:7000" {
		t.Fatalf("flags = %+v", f)
	}
	for _, bad := range [][]string{{"--connect", "node.example"}, {"--connect", "kurz@node"}, {"--connect", tok + "@node:0"}} {
		if _, err := parseRunFlags(bad, io.Discard); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}

	// Ziele aus <dir>/connect kommen dazu, doppelte einmal
	if err := m64agent.WritePushFile(filepath.Join(dir, m64agent.PushFile), []m64agent.PushTarget{
		{Token: tok, Addr: "node.example:6466"}, {Token: tok, Addr: "other.example:6466"}}); err != nil {
		t.Fatal(err)
	}
	targets, err := pushTargets(f)
	if err != nil || len(targets) != 3 || targets[2].Addr != "other.example:6466" {
		t.Fatalf("targets = %+v, %v", targets, err)
	}

	// --no-listen ohne Ziel: Fehler (Agent waere unerreichbar); kaputte Datei: Fehler
	empty := t.TempDir()
	f2, _ := parseRunFlags([]string{"--dir", empty, "--no-listen"}, io.Discard)
	if _, err := pushTargets(f2); err == nil {
		t.Fatal("--no-listen without a node accepted")
	}
	f2.noListen = false
	if got, err := pushTargets(f2); err != nil || len(got) != 0 {
		t.Fatalf("no push: %+v %v", got, err)
	}
	if err := os.WriteFile(filepath.Join(empty, m64agent.PushFile), []byte("kaputt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := pushTargets(f2); err == nil {
		t.Fatal("broken connect file accepted")
	}
}
