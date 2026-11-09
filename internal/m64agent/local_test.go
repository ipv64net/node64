package m64agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

func f(v float64) *float64 { return &v }

func TestParseLocal(t *testing.T) {
	out := strings.Join([]string{
		`<<<local:sep(0)>>>`,
		`0 myservice count=40;30;50 Everything fine`,
		`2 "My Service" - Something is broken`,
		`P temp temp=72.5;70;80;0;100 Temperature`,
		`P "Disk free" free=5;10:;5:|used=95 Low space`,
		`P nothresholds val=3`,
		`1 nometrics - `,
		`3 "unknown svc" - state unknown here`,
		`7 bad - wrong state`,
		`0 "unterminated - text`,
		`0 onlyname`,
		`0 badmetric x=abc oops`,
		`0 unit time=12ms;100ms;200ms Response`,
		``,
	}, "\n")
	checks, bad := ParseLocal([]byte(out), "test.sh")
	if bad != 4 {
		t.Errorf("bad = %d, want 4", bad)
	}
	type exp struct {
		state int
		text  string
		nm    int
	}
	want := map[string]exp{
		"myservice":    {0, "Everything fine", 1},
		"My Service":   {2, "Something is broken", 0},
		"temp":         {1, "Temperature", 1}, // 72.5 ab warn 70, unter crit 80
		"Disk free":    {1, "Low space", 2},   // 5 unter Warn-Untergrenze 10, nicht unter crit 5
		"nothresholds": {0, "", 1},
		"nometrics":    {1, "", 0},
		"unknown svc":  {3, "state unknown here", 0},
		"unit":         {0, "Response", 1},
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for _, c := range checks {
		w, ok := want[c.Name]
		if !ok {
			t.Errorf("unexpected check %q", c.Name)
			continue
		}
		if c.State != w.state || c.Text != w.text || len(c.Metrics) != w.nm || c.Script != "test.sh" {
			t.Errorf("%s: got state=%d text=%q metrics=%d script=%q, want %+v", c.Name, c.State, c.Text, len(c.Metrics), c.Script, w)
		}
	}
	m := checks[0].Metrics[0]
	if m.Name != "count" || m.Value != 40 || *m.Warn != 30 || *m.Crit != 50 || m.Min != nil {
		t.Errorf("metric = %+v", m)
	}
	m = checks[2].Metrics[0]
	if *m.Min != 0 || *m.Max != 100 {
		t.Errorf("min/max = %+v", m)
	}
	if u := checks[len(checks)-1].Metrics[0]; u.Value != 12 || *u.Warn != 100 {
		t.Errorf("unit metric = %+v", u)
	}
}

func TestEvalPRanges(t *testing.T) {
	cases := []struct {
		line  string
		state int
	}{
		{"P a v=4;10:;5:", 2},      // unter der kritischen Untergrenze
		{"P a v=7;10:;5:", 1},      // unter der Warn-Untergrenze
		{"P a v=12;10:;5:", 0},     //
		{"P a v=50;10:40;5:60", 1}, // ueber Warn-Obergrenze
		{"P a v=60;10:40;5:60", 2}, // ab crit
		{"P a v=1|w=31;30;50", 1},  // zweite Metrik entscheidet
	}
	for _, c := range cases {
		got, bad := ParseLocal([]byte(c.line), "")
		if bad != 0 || len(got) != 1 || got[0].State != c.state {
			t.Errorf("%q: got %+v (bad %d), want state %d", c.line, got, bad, c.state)
		}
	}
}

func TestParseLocalLimits(t *testing.T) {
	long := "0 " + strings.Repeat("n", 500) + " - " + strings.Repeat("t", 5000) + "\x07"
	got, _ := ParseLocal([]byte(long), "")
	if len(got) != 1 || len(got[0].Name) != localMaxNameLen || len(got[0].Text) != localMaxTextLen {
		t.Fatalf("limits not applied: name %d text %d", len(got[0].Name), len(got[0].Text))
	}
	var b strings.Builder
	for range localMaxLines + 10 {
		b.WriteString("0 x - y\n")
	}
	got, bad := ParseLocal([]byte(b.String()), "")
	if len(got) != localMaxLines || bad != 1 {
		t.Fatalf("lines: got %d bad %d", len(got), bad)
	}
}

// TestLocalRunner braucht root (Eigentuemer-Pruefung) und Unix.
func TestLocalRunner(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on unix")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string, mode os.FileMode) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	write("ok.sh", "#!/bin/sh\necho '0 svc_ok - fine'\necho \"P temp t=$((70+5));70;80\"\n", 0o755)
	write("groupwrite.sh", "#!/bin/sh\necho '0 never - x'\n", 0o775)
	write("noexec.sh", "#!/bin/sh\necho '0 never2 - x'\n", 0o644)
	write("big.sh", "#!/bin/sh\ni=0; while [ $i -lt 20000 ]; do echo \"0 big$i - xxxxxxxxxx\"; i=$((i+1)); done\n", 0o755)
	write("300/cached.sh", "#!/bin/sh\necho \"0 cached - $$\"\n", 0o755)
	write(".hidden.sh", "#!/bin/sh\necho '0 hidden - x'\n", 0o755)

	r := &localRunner{dir: dir}
	rep := &m64proto.Report{}
	r.run(context.Background(), rep)
	names := map[string]m64proto.LocalCheck{}
	for _, c := range rep.Local {
		names[c.Name] = c
	}
	if names["svc_ok"].Script != "ok.sh" || names["temp"].State != 1 {
		t.Errorf("ok.sh: %+v %+v", names["svc_ok"], names["temp"])
	}
	if _, ok := names["never"]; ok {
		t.Error("group-writable script ran")
	}
	if _, ok := names["never2"]; ok {
		t.Error("non-executable script ran")
	}
	if _, ok := names["hidden"]; ok {
		t.Error("hidden script ran")
	}
	cached := names["cached"].Text
	if cached == "" {
		t.Error("cached script did not run")
	}
	notes := ""
	for _, n := range rep.Notes {
		notes += n.Note + "\n"
	}
	for _, w := range []string{"groupwrite.sh ignored: writable by group or others", "noexec.sh ignored: not executable", "big.sh: output larger than"} {
		if !strings.Contains(notes, w) {
			t.Errorf("note %q missing in:\n%s", w, notes)
		}
	}
	// Ausgabe begrenzt: big.sh hoechstens 64 KB
	bigs := 0
	for _, c := range rep.Local {
		if strings.HasPrefix(c.Name, "big") {
			bigs++
		}
	}
	if bigs == 0 || bigs*len("0 big1234 - xxxxxxxxxx\n") > m64proto.LocalMaxBytes+1000 {
		t.Errorf("big.sh produced %d checks", bigs)
	}

	// zweite Runde: Skript im Intervall-Ordner liefert den gepufferten Stand
	rep2 := &m64proto.Report{}
	r.run(context.Background(), rep2)
	for _, c := range rep2.Local {
		if c.Name == "cached" && c.Text != cached {
			t.Errorf("cached script ran again: %q vs %q", c.Text, cached)
		}
	}

	// Ordner fuer andere schreibbar: alles ignoriert
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	rep3 := &m64proto.Report{}
	r.run(context.Background(), rep3)
	if len(rep3.Local) != 0 || len(rep3.Notes) != 1 || !strings.Contains(rep3.Notes[0].Note, "local.d ignored") {
		t.Errorf("writable dir: %+v %+v", rep3.Local, rep3.Notes)
	}
}

func TestLocalRunnerTimeout(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on unix")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	p := filepath.Join(dir, "slow.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho '0 early - x'\nsleep 60 &\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := &localRunner{dir: dir}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*1e6)
	defer cancel()
	checks, notes := r.runOne(ctx, localScript{path: p, name: "slow.sh"})
	if len(checks) != 1 || len(notes) == 0 {
		t.Fatalf("checks %+v notes %v", checks, notes)
	}
}
