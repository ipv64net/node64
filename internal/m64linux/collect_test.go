package m64linux

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// fakeHost baut aus einer aufgezeichneten Skript-Ausgabe einen Dateibaum (/proc, /sys) und eine Exec-Funktion,
// die die Programmausgaben aus denselben Abschnitten liefert.
type fakeHost struct {
	root     string
	symlinks bool
	cmds     map[string][]byte
	smart    []string
	df       []DFRow
	inodes   map[string][2]uint64
	calls    sync.Map // Befehl -> *int64
}

func newFakeHost(t *testing.T, file string) *fakeHost {
	t.Helper()
	h := &fakeHost{root: t.TempDir(), symlinks: true, cmds: map[string][]byte{}}
	files := map[string][]byte{}
	for _, s := range splitSections(readTestdata(t, file)) {
		switch {
		case strings.HasPrefix(s.name, "file:"):
			files[s.name[5:]] = s.body
		case s.name == "attr":
			for _, ln := range lines(s.body) {
				p, v, _ := strings.Cut(ln, "\t")
				if hp, ok := strings.CutSuffix(p, ".hex"); ok {
					b, _ := hex.DecodeString(v)
					files[hp] = b
					continue
				}
				files[p] = []byte(v)
			}
		case strings.HasPrefix(s.name, "smart:"):
			dev := s.name[6:]
			h.smart = append(h.smart, dev)
			h.cmds["smartctl -j -a -n standby "+dev] = s.body
		case s.name == "df":
			h.df = ParseDF(s.body)
		case s.name == "df_i":
			h.inodes = ParseDFInodes(s.body)
		default:
			h.cmds[s.name] = s.body
		}
	}
	for p, v := range files {
		full := filepath.Join(h.root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		base := path.Base(p)
		switch {
		case string(v) == "1" && (base == "bonding" || base == "bridge" || base == "device" || base == "system"):
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatal(err)
			}
		case base == "master" || base == "device" || strings.HasPrefix(p, "/dev/disk/by-id/"):
			if err := os.Symlink(filepath.FromSlash(string(v)), full); err != nil {
				h.symlinks = false // Windows ohne Recht fuer Symlinks
			}
		default:
			if err := os.WriteFile(full, v, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	return h
}

func (h *fakeHost) count(cmd string) int64 {
	if v, ok := h.calls.Load(cmd); ok {
		return atomic.LoadInt64(v.(*int64))
	}
	return 0
}

func (h *fakeHost) has(name string) bool {
	switch name {
	case "zpool":
		_, ok := h.cmds["zpool_list"]
		return ok
	case "systemctl":
		_, ok := h.cmds["systemd_failed"]
		return ok
	case "apt-get":
		_, ok := h.cmds["updates:apt"]
		return ok
	case "smartctl":
		return len(h.smart) > 0
	}
	return false
}

func (h *fakeHost) exec(_ context.Context, name string, args ...string) (ExecResult, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	v, _ := h.calls.LoadOrStore(cmd, new(int64))
	atomic.AddInt64(v.(*int64), 1)
	if !h.has(name) {
		return ExecResult{}, ErrNotFound
	}
	key := map[string]string{
		"zpool " + strings.Join(zpoolListArgs, " "): "zpool_list",
		"zpool status":                             "zpool_status",
		"systemctl --failed --no-legend --plain":   "systemd_failed",
		"systemctl is-system-running":              "systemd_state",
		"apt-get " + strings.Join(aptSimArgs, " "): "updates:apt",
	}[cmd]
	if cmd == "smartctl --scan-open -j" {
		var devs []map[string]string
		for _, d := range h.smart {
			devs = append(devs, map[string]string{"name": d})
		}
		b, _ := json.Marshal(map[string]any{"devices": devs})
		return ExecResult{Stdout: b}, nil
	}
	if key == "" {
		key = cmd
	}
	out, ok := h.cmds[key]
	if !ok {
		return ExecResult{Code: 1, Stderr: []byte("unbekannt: " + cmd)}, nil
	}
	return ExecResult{Stdout: out}, nil
}

func (h *fakeHost) statfs(p string) (StatFS, error) {
	for _, r := range h.df {
		if r.Mount == p {
			in := h.inodes[p]
			return StatFS{Total: r.Total, Free: r.Total - r.Used, Avail: r.Avail, InodesTotal: in[0], InodesFree: in[1]}, nil
		}
	}
	return StatFS{}, errors.New("statfs " + p + ": nicht gefunden")
}

func (h *fakeHost) options(now func() time.Time) Options {
	return Options{Root: h.root, Exec: h.exec, Has: h.has, Statfs: h.statfs, Now: now, Cache: NewCache()}
}

// Collect (Agent) und ParseScriptOutput (SSH) muessen fuer denselben Host dasselbe liefern.
func TestCollectMatchesScript(t *testing.T) {
	for _, file := range []string{"script_proxmox8.txt", "script_unraid612.txt", "script_debian12_vm.txt", "script_raspios12.txt"} {
		t.Run(file, func(t *testing.T) {
			h := newFakeHost(t, file)
			now := func() time.Time { return testNow }
			opt := h.options(now)
			Collect(context.Background(), opt) // SMART/Updates laufen im Hintergrund an
			opt.Cache.Wait()
			got := Collect(context.Background(), opt)
			want, err := ParseScriptOutput(readTestdata(t, file), testNow)
			if err != nil {
				t.Fatal(err)
			}
			if !h.symlinks {
				t.Log("keine Symlinks: Master und hwmon-Geraete werden nicht verglichen")
				for _, r := range []*m64proto.Report{got, want} {
					for i := range r.Net {
						r.Net[i].Master = ""
					}
					r.Temps = nil
				}
			}
			// Updates nur, wenn der Paketverwalter im Fake bekannt ist
			if _, ok := h.cmds["updates:apt"]; !ok {
				want.Updates, got.Updates = nil, nil
			}
			cmp := func(name string, a, b any) {
				ja, _ := json.Marshal(a)
				jb, _ := json.Marshal(b)
				if string(ja) != string(jb) {
					t.Errorf("%s:\nCollect: %s\nSkript:  %s", name, ja, jb)
				}
			}
			cmp("uptime", got.Uptime, want.Uptime)
			cmp("cpu", got.CPU, want.CPU)
			cmp("mem", got.Mem, want.Mem)
			cmp("load", got.Load, want.Load)
			cmp("disk", got.Disks, want.Disks)
			cmp("net", got.Net, want.Net)
			cmp("bond", got.Bonds, want.Bonds)
			cmp("raid", got.RAID, want.RAID)
			cmp("zfs", got.ZFS, want.ZFS)
			cmp("temp", got.Temps, want.Temps)
			cmp("systemd", got.Systemd, want.Systemd)
			cmp("reboot", got.Reboot, want.Reboot)
			cmp("smart", got.SMART, want.SMART)
			cmp("updates", got.Updates, want.Updates)
			// FS: Geraet kommt beim Agent aus /proc/mounts, beim Skript aus df (Pi: /dev/root)
			for i := range got.FS {
				got.FS[i].Device = ""
			}
			for i := range want.FS {
				want.FS[i].Device = ""
			}
			cmp("fs", got.FS, want.FS)
			if len(got.Errors) != 0 {
				t.Errorf("Fehler: %+v", got.Errors)
			}
		})
	}
}

func TestCollectSections(t *testing.T) {
	h := newFakeHost(t, "script_proxmox8.txt")
	opt := h.options(nil)
	opt.Sections = []string{m64proto.SecCPU, m64proto.SecZFS}
	r := Collect(context.Background(), opt)
	if r.CPU == nil || len(r.ZFS) != 2 || r.Mem != nil || r.FS != nil || r.Net != nil || r.SMART != nil || r.Updates != nil {
		t.Fatalf("%+v", r)
	}
	if h.count("smartctl --scan-open -j") != 0 || h.count("systemctl is-system-running") != 0 {
		t.Fatal("nicht gewuenschte Abschnitte gelesen")
	}
	if r.Uptime == 0 || r.V != m64proto.Version {
		t.Fatalf("%+v", r)
	}
}

// Ohne /proc und ohne Programme: Errors je Abschnitt bzw. Notes, kein Abbruch.
func TestCollectEmptyHost(t *testing.T) {
	opt := Options{Root: t.TempDir(), Cache: NewCache(),
		Has:    func(string) bool { return false },
		Exec:   func(context.Context, string, ...string) (ExecResult, error) { return ExecResult{}, ErrNotFound },
		Statfs: func(string) (StatFS, error) { return StatFS{}, errors.New("nein") }}
	r := Collect(context.Background(), opt)
	errSecs := map[string]bool{}
	for _, e := range r.Errors {
		errSecs[e.Section] = true
		if strings.Contains(e.Error, opt.Root) {
			t.Errorf("Fehlertext enthaelt Wurzel: %q", e.Error)
		}
	}
	for _, s := range []string{"cpu", "mem", "load", "fs", "disk", "net"} {
		if !errSecs[s] {
			t.Errorf("Fehler fuer %s fehlt: %+v", s, r.Errors)
		}
	}
	for _, s := range []string{"smart", "updates", "systemd", "zfs", "raid", "bond", "temp"} {
		if errSecs[s] {
			t.Errorf("unerwarteter Fehler fuer %s", s)
		}
	}
	if !hasNote(r, "smart", m64proto.Hint(m64proto.HintMissing, "smartctl")) || !hasNote(r, "updates", m64proto.HintNoPkgManager) ||
		!hasNote(r, "systemd", m64proto.HintNoSystemd) {
		t.Fatalf("Notes %+v", r.Notes)
	}
	if r.Reboot == nil || r.Reboot.Required {
		t.Fatalf("%+v", r.Reboot)
	}
}

// SMART wird 30 min gepuffert; danach kommt sofort der alte Stand, erneuert wird im Hintergrund.
func TestCollectSlowCache(t *testing.T) {
	h := newFakeHost(t, "script_proxmox8.txt")
	var mu sync.Mutex
	now := testNow
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	opt := h.options(clock)
	opt.Sections = []string{m64proto.SecSmart, m64proto.SecUpdates}
	scan := "smartctl --scan-open -j"

	Collect(context.Background(), opt)
	opt.Cache.Wait()
	r := Collect(context.Background(), opt)
	if len(r.SMART) != 3 || h.count(scan) != 1 || r.Updates == nil || r.Updates.Checked != testNow.Unix() {
		t.Fatalf("erster Lauf: %d SMART, %d Scans, %+v", len(r.SMART), h.count(scan), r.Updates)
	}
	advance(29 * time.Minute)
	r = Collect(context.Background(), opt)
	opt.Cache.Wait()
	if h.count(scan) != 1 || len(r.SMART) != 3 {
		t.Fatalf("Puffer nicht genutzt: %d Scans", h.count(scan))
	}
	// Platte faellt aus: neuer Stand erst nach Ablauf
	h.cmds["smartctl -j -a -n standby /dev/nvme0"] = []byte(`{"device":{"name":"/dev/nvme0","protocol":"NVMe"},"smart_status":{"passed":false}}`)
	advance(2 * time.Minute)
	r = Collect(context.Background(), opt)
	if !*r.SMART[0].Passed {
		t.Fatal("veralteter Stand sollte sofort kommen")
	}
	opt.Cache.Wait()
	if h.count(scan) != 2 {
		t.Fatalf("keine Erneuerung: %d Scans", h.count(scan))
	}
	r = Collect(context.Background(), opt)
	if *r.SMART[0].Passed {
		t.Fatal("neuer Stand fehlt")
	}
	if h.count("apt-get "+strings.Join(aptSimArgs, " ")) != 1 {
		t.Fatal("Updates zu oft gelesen")
	}
	// Uhr rueckwaerts: Stand gilt als veraltet
	advance(-24 * time.Hour)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	if h.count(scan) != 3 {
		t.Fatalf("Uhr rueckwaerts: %d Scans", h.count(scan))
	}
}

func TestCollectConcurrent(t *testing.T) {
	h := newFakeHost(t, "script_proxmox8.txt")
	opt := h.options(nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := Collect(context.Background(), opt); r.CPU == nil {
				t.Error("cpu fehlt")
			}
		}()
	}
	wg.Wait()
	opt.Cache.Wait()
}

func TestCaps(t *testing.T) {
	h := newFakeHost(t, "script_proxmox8.txt")
	caps := strings.Join(Caps(h.options(nil)), ",")
	for _, c := range []string{"cpu", "bond", "zfs", "smart", "systemd", "updates"} {
		if !strings.Contains(caps, c) {
			t.Errorf("%s fehlt in %s", c, caps)
		}
	}
	if strings.Contains(caps, "raid") {
		t.Errorf("raid ohne mdstat: %s", caps)
	}
}

// Haengender Mount (F3-K3): statfs laeuft je Mount hoechstens einmal; solange er haengt, wird er ohne neuen Versuch
// als Fehler gemeldet. Gleichzeitige Aufrufe teilen sich einen Aufruf.
func TestStatfsTimeout(t *testing.T) {
	old := statfsLimit
	statfsLimit = 100 * time.Millisecond
	defer func() { statfsLimit = old }()
	block := make(chan struct{})
	var calls int64
	st := func(p string) (StatFS, error) {
		atomic.AddInt64(&calls, 1)
		if p == "/mnt/nfs" {
			<-block
		}
		return StatFS{Total: 1}, nil
	}
	c := newCollector(Options{Cache: NewCache()})
	start := time.Now()
	if _, err := c.statfsTimeout(context.Background(), st, "/mnt/nfs"); err == nil || !strings.Contains(err.Error(), m64proto.HintTimeout) {
		t.Fatalf("%v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Zeitlimit greift nicht")
	}
	for i := 0; i < 5; i++ {
		start = time.Now()
		_, err := c.statfsTimeout(context.Background(), st, "/mnt/nfs")
		if err == nil || !strings.Contains(err.Error(), "{m64:hung=") || time.Since(start) > 50*time.Millisecond {
			t.Fatalf("Runde %d: %v", i, err)
		}
	}
	if n := atomic.LoadInt64(&calls); n != 1 {
		t.Fatalf("%d statfs-Aufrufe fuer den haengenden Mount", n)
	}
	// andere Mounts laufen weiter
	if s, err := c.statfsTimeout(context.Background(), st, "/"); err != nil || s.Total != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	// Mount kommt zurueck: naechster Aufruf liest neu
	close(block)
	for i := 0; i < 200; i++ {
		c.cache.mu.Lock()
		n := len(c.cache.statfs)
		c.cache.mu.Unlock()
		if n == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if s, err := c.statfsTimeout(context.Background(), st, "/mnt/nfs"); err != nil || s.Total != 1 {
		t.Fatalf("%+v %v", s, err)
	}
	// gleichzeitig: ein Aufruf
	slow := make(chan struct{})
	var n2 int64
	st2 := func(string) (StatFS, error) { atomic.AddInt64(&n2, 1); <-slow; return StatFS{Total: 2}, nil }
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s, err := c.statfsTimeout(context.Background(), st2, "/data"); err != nil || s.Total != 2 {
				t.Errorf("%+v %v", s, err)
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(slow)
	wg.Wait()
	if n := atomic.LoadInt64(&n2); n != 1 {
		t.Fatalf("%d gleichzeitige Aufrufe", n)
	}
}

// Erster Lauf blockiert nicht (F1-K3): SMART/Updates laufen im Hintergrund, Collect kommt mit Hinweis zurueck.
func TestCollectSlowFirstRunNonBlocking(t *testing.T) {
	h := newFakeHost(t, "script_proxmox8.txt")
	block := make(chan struct{})
	opt := h.options(func() time.Time { return testNow })
	inner := opt.Exec
	opt.Exec = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		if name == "smartctl" || name == "apt-get" {
			select {
			case <-block:
			case <-ctx.Done():
				return ExecResult{}, errors.New(name + ": Zeitlimit")
			}
		}
		return inner(ctx, name, args...)
	}
	opt.Sections = []string{m64proto.SecCPU, m64proto.SecSmart, m64proto.SecUpdates}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := Collect(ctx, opt)
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("Collect blockiert %v", d)
	}
	if r.CPU == nil || r.SMART != nil || r.Updates != nil || !hasNote(r, "smart", NoteReading) || !hasNote(r, "updates", NoteReading) {
		t.Fatalf("%+v %+v", r.SMART, r.Notes)
	}
	close(block)
	opt.Cache.Wait()
	r = Collect(context.Background(), opt)
	if len(r.SMART) != 3 || r.Updates == nil || hasNote(r, "smart", NoteReading) {
		t.Fatalf("%+v %+v", r.SMART, r.Notes)
	}
	// Collect mit langer Deadline endet vor ihr (Rand fuer die Antwort)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel2()
	opt.Sections = []string{m64proto.SecZFS}
	opt.Exec = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		<-ctx.Done()
		return ExecResult{}, errors.New(name + ": Zeitlimit")
	}
	dl, _ := ctx2.Deadline()
	r = Collect(ctx2, opt)
	if time.Until(dl) < deadlineMargin/2 || len(r.Errors) == 0 {
		t.Fatalf("Rand %v, Fehler %+v", time.Until(dl), r.Errors)
	}
}

// Abgebrochener Lauf (Zeitlimit im Hintergrund) gilt nur kurz und ersetzt keinen guten Stand.
func TestCollectSlowAbortRetry(t *testing.T) {
	old := refreshTimeout
	refreshTimeout = 100 * time.Millisecond
	defer func() { refreshTimeout = old }()
	h := newFakeHost(t, "script_proxmox8.txt")
	var mu sync.Mutex
	now := testNow
	hang := false
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	setHang := func(v bool) { mu.Lock(); hang = v; mu.Unlock() }
	opt := h.options(clock)
	inner := opt.Exec
	opt.Exec = func(ctx context.Context, name string, args ...string) (ExecResult, error) {
		mu.Lock()
		hg := hang
		mu.Unlock()
		if hg {
			<-ctx.Done()
			return ExecResult{}, errors.New(name + ": Zeitlimit")
		}
		return inner(ctx, name, args...)
	}
	opt.Sections = []string{m64proto.SecSmart}
	scan := "smartctl --scan-open -j"

	// erster Lauf bricht ab: Fehler, nach 5 min neuer Versuch (nicht erst nach 30 min)
	setHang(true)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	r := Collect(context.Background(), opt)
	if len(r.Errors) == 0 || r.Errors[0].Section != "smart" {
		t.Fatalf("%+v", r.Errors)
	}
	setHang(false)
	advance(4 * time.Minute)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	if h.count(scan) != 0 {
		t.Fatalf("zu frueh neu gelesen: %d", h.count(scan))
	}
	advance(2 * time.Minute)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	r = Collect(context.Background(), opt)
	if h.count(scan) != 1 || len(r.SMART) != 3 || len(r.Errors) != 0 {
		t.Fatalf("%d Scans, %+v", h.count(scan), r.Errors)
	}
	// guter Stand, dann haengt smartctl: alter Stand bleibt, Versuch nach 5 min
	setHang(true)
	advance(31 * time.Minute)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	r = Collect(context.Background(), opt)
	if len(r.SMART) != 3 || len(r.Errors) != 0 {
		t.Fatalf("guter Stand ersetzt: %+v %+v", r.SMART, r.Errors)
	}
	setHang(false)
	advance(6 * time.Minute)
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	if h.count(scan) != 2 {
		t.Fatalf("kein neuer Versuch: %d", h.count(scan))
	}
}

func TestDefaultExec(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("nur Unix")
	}
	res, err := DefaultExec(context.Background(), "sh", "-c", "echo out; echo err >&2; echo LC=$LC_ALL; exit 3")
	if err != nil || res.Code != 3 || string(res.Stdout) != "out\nLC=C\n" || string(res.Stderr) != "err\n" {
		t.Fatalf("%+v %v", res, err)
	}
	if _, err := DefaultExec(context.Background(), "gibt-es-nicht-m64"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := DefaultExec(context.Background(), "../sh"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("relativer Pfad: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := DefaultExec(ctx, "sleep", "10"); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("Zeitlimit: %v", err)
	}
	// Ausgabe begrenzt
	res, err = DefaultExec(context.Background(), "sh", "-c", "head -c 5000000 /dev/zero")
	if err != nil || len(res.Stdout) != m64proto.MaxReportBytes {
		t.Fatalf("%d %v", len(res.Stdout), err)
	}
}

func TestStatfsLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nur Linux")
	}
	st, err := statfsPath("/")
	if err != nil || st.Total == 0 || st.Avail > st.Total {
		t.Fatalf("%+v %v", st, err)
	}
	if _, err := statfsPath("/gibt/es/nicht"); err == nil {
		t.Fatal("Fehler erwartet")
	}
}

// TestCollectLocal liest den echten Host (nur Linux): Grundwerte muessen da sein.
func TestCollectLocal(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("nur Linux")
	}
	r := Collect(context.Background(), Options{Sections: []string{"cpu", "mem", "load", "fs", "disk", "net", "temp", "reboot", "raid", "bond"}, Cache: NewCache()})
	if r.CPU == nil || r.Mem == nil || r.Load == nil || len(r.FS) == 0 {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(r)
	t.Logf("%d Bytes: %s", len(b), b[:min(len(b), 400)])
}

// RHEL: needs-restarting -r (Exit-Code 1 = Neustart noetig), 10 min gepuffert.
func TestCollectNeedsRestarting(t *testing.T) {
	var calls int64
	opt := Options{Root: t.TempDir(), Cache: NewCache(), Sections: []string{m64proto.SecReboot},
		Has: func(n string) bool { return n == "needs-restarting" },
		Exec: func(_ context.Context, name string, args ...string) (ExecResult, error) {
			atomic.AddInt64(&calls, 1)
			if name != "needs-restarting" || len(args) != 1 || args[0] != "-r" {
				t.Errorf("unerwartet: %s %v", name, args)
			}
			return ExecResult{Code: 1}, nil
		}}
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	for i := 0; i < 3; i++ {
		if r := Collect(context.Background(), opt); r.Reboot == nil || !r.Reboot.Required {
			t.Fatalf("%+v", r.Reboot)
		}
	}
	opt.Cache.Wait()
	if calls != 1 {
		t.Fatalf("%d Aufrufe", calls)
	}
}
