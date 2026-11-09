package m64agent

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
	write("ok.sh", "#!/bin/sh\necho '0 svc_ok - fine'\necho \"P temp t=$((70+5));70;80\"\necho \"0 home - $HOME\"\n", 0o755)
	write("groupwrite.sh", "#!/bin/sh\necho '0 never - x'\n", 0o775)
	write("noexec.sh", "#!/bin/sh\necho '0 never2 - x'\n", 0o644)
	write("big.sh", "#!/bin/sh\ni=0; while [ $i -lt 20000 ]; do echo \"0 big$i - xxxxxxxxxx\"; i=$((i+1)); done\n", 0o755)
	write("300/cached.sh", "#!/bin/sh\necho \"0 cached - $$\"\n", 0o755)
	write(".hidden.sh", "#!/bin/sh\necho '0 hidden - x'\n", 0o755)

	r := newLocalRunner(dir)
	defer r.close()
	rep := &m64proto.Report{}
	r.run(context.Background(), rep)
	names := map[string]m64proto.LocalCheck{}
	for _, c := range rep.Local {
		names[c.Name] = c
	}
	if names["svc_ok"].Script != "ok.sh" || names["temp"].State != 1 {
		t.Errorf("ok.sh: %+v %+v", names["svc_ok"], names["temp"])
	}
	if names["home"].Text != localHome {
		t.Errorf("HOME = %q, want %q", names["home"].Text, localHome)
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
	r := newLocalRunner(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*1e6)
	defer cancel()
	checks, notes := r.runOne(ctx, localScript{path: p, name: "slow.sh"})
	if len(checks) != 1 || len(notes) == 0 {
		t.Fatalf("checks %+v notes %v", checks, notes)
	}
}

// F1-K3: Skripte laufen im Hintergrund; collect wartet nur kurz und liefert langsame Skripte aus dem letzten Lauf.
func TestLocalRunnerAsync(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on unix")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	for name, body := range map[string]string{
		"fast.sh": "#!/bin/sh\necho '0 fast - quick'\n",
		"slow.sh": "#!/bin/sh\nsleep 2\necho \"0 slow - $$\"\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	r := newLocalRunner(dir)
	defer r.close()
	round := func() map[string]string {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		start := time.Now()
		rep := &m64proto.Report{}
		r.run(ctx, rep)
		if d := time.Since(start); d > 1500*time.Millisecond {
			t.Fatalf("round took %v", d)
		}
		out := map[string]string{}
		for _, c := range rep.Local {
			out[c.Name] = c.Text
		}
		for _, n := range rep.Notes {
			out["note"] += n.Note + "\n"
		}
		return out
	}
	r1 := round()
	if r1["fast"] != "quick" || r1["slow"] != "" || !strings.Contains(r1["note"], "slow.sh: running for the first time") {
		t.Fatalf("round 1: %v", r1)
	}
	time.Sleep(2500 * time.Millisecond)
	r2 := round() // Ergebnis des ersten Laufs, zweiter Lauf startet
	if r2["slow"] == "" || r2["fast"] != "quick" {
		t.Fatalf("round 2: %v", r2)
	}
	r3 := round() // zweiter Lauf noch nicht fertig: kein weiterer Start, gleicher Stand
	if r3["slow"] != r2["slow"] {
		t.Fatalf("round 3: %q vs %q", r3["slow"], r2["slow"])
	}
}

// F1-K3: Server.Collect antwortet innerhalb von CollectTimeout, auch wenn ein Skript haengt; Close beendet es.
func TestCollectWithHangingScript(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root on unix")
	}
	dir := t.TempDir()
	_ = os.Chmod(dir, 0o755)
	if err := os.WriteFile(filepath.Join(dir, "hang.sh"), []byte("#!/bin/sh\nsleep 60\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	hk, _ := testSigner(t)
	s, err := New(Config{HostKey: hk, KeysFile: "x", LocalDir: dir, CollectTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	rep, err := s.Collect(context.Background(), []string{m64proto.SecLocal})
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("collect took %v", d)
	}
	if len(rep.Notes) == 0 || !strings.Contains(rep.Notes[0].Note, "hang.sh: running") {
		t.Fatalf("notes %+v", rep.Notes)
	}
	start = time.Now()
	_ = s.Close()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("close took %v", d)
	}
}

// F1-K2: Symlinks und Elternordner werden geprueft; ausgefuehrt wird die geoeffnete Datei, nicht erneut der Pfad.
func TestLocalSecurity(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on linux")
	}
	base := t.TempDir()
	_ = os.Chmod(base, 0o755)
	mk := func(dir string, mode os.FileMode, uid int) string {
		p := filepath.Join(base, dir)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(p, uid, uid); err != nil {
			t.Fatal(err)
		}
		return p
	}
	script := func(p, body string) {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	local := mk("local.d", 0o755, 0)
	evil := mk("evil", 0o777, 0)    // fuer alle schreibbar (ohne Sticky-Bit)
	user := mk("user", 0o755, 1000) // gehoert nicht root
	inner := mk("user/inner", 0o755, 0)
	good := mk("good", 0o755, 0)
	script(filepath.Join(evil, "x.sh"), "echo '0 evil - x'")
	script(filepath.Join(user, "y.sh"), "echo '0 user - y'")
	script(filepath.Join(inner, "w.sh"), "echo '0 inner - w'")
	script(filepath.Join(good, "z.sh"), "echo '0 good - z'")
	script(filepath.Join(local, "fdpath.sh"), "echo \"0 path - $0\"")
	for link, target := range map[string]string{
		"link1.sh": filepath.Join(evil, "x.sh"),
		"link2.sh": filepath.Join(user, "y.sh"),
		"link3.sh": filepath.Join(inner, "w.sh"),
		"link4.sh": filepath.Join(good, "z.sh"),
	} {
		if err := os.Symlink(target, filepath.Join(local, link)); err != nil {
			t.Fatal(err)
		}
	}
	r := newLocalRunner(local)
	defer r.close()
	rep := &m64proto.Report{}
	r.run(context.Background(), rep)
	got := map[string]string{}
	for _, c := range rep.Local {
		got[c.Name] = c.Text
	}
	notes := ""
	for _, n := range rep.Notes {
		notes += n.Note + "\n"
	}
	for _, bad := range []string{"evil", "user", "inner"} {
		if _, ok := got[bad]; ok {
			t.Errorf("%s ran (unsafe path)", bad)
		}
	}
	for _, w := range []string{"link1.sh ignored: " + evil + " writable by group or others",
		"link2.sh ignored: " + user + " not owned by root", "link3.sh ignored: " + user + " not owned by root"} {
		if !strings.Contains(notes, w) {
			t.Errorf("note %q missing in:\n%s", w, notes)
		}
	}
	if got["good"] != "z" {
		t.Errorf("safe symlink did not run: %v\n%s", got, notes)
	}
	if got["path"] != "/proc/self/fd/3" {
		t.Errorf("script not run from the opened descriptor: $0 = %q", got["path"])
	}

	// local.d selbst als Symlink in einen unsicheren Ordner
	ld := mk("user/ld", 0o755, 0)
	script(filepath.Join(ld, "a.sh"), "echo '0 a - a'")
	if err := os.Symlink(ld, filepath.Join(base, "ld-link")); err != nil {
		t.Fatal(err)
	}
	r2 := newLocalRunner(filepath.Join(base, "ld-link"))
	defer r2.close()
	rep2 := &m64proto.Report{}
	r2.run(context.Background(), rep2)
	if len(rep2.Local) != 0 || len(rep2.Notes) != 1 || !strings.Contains(rep2.Notes[0].Note, "local.d ignored: "+user+" not owned by root") {
		t.Errorf("unsafe local.d: %+v %+v", rep2.Local, rep2.Notes)
	}

	// Datei nach der Pruefung ausgetauscht: es laeuft die gepruefte
	p := filepath.Join(good, "z.sh")
	f, err := openScript(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	script(filepath.Join(good, "z.new"), "echo swapped")
	if err := os.Rename(filepath.Join(good, "z.new"), p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := scriptCmd(ctx, f, p).Output()
	if err != nil || strings.TrimSpace(string(out)) != "0 good - z" {
		t.Fatalf("ran %q (err %v), want the checked file", out, err)
	}
}
