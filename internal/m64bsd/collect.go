package m64bsd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Zeitlimits je Programm.
const (
	timeoutShort   = 10 * time.Second // netstat, ifconfig, iostat, geom, zpool, gmirror, graid, swapinfo
	timeoutSmart   = 20 * time.Second // smartctl je Platte bzw. --scan-open
	timeoutUpdates = 90 * time.Second // pkg version
	timeoutAudit   = 60 * time.Second // pkg audit
	timeoutVersion = 30 * time.Second // freebsd-version (liest den Kernel mit what)
	timeoutStatfs  = 5 * time.Second  // statfs je Mount (z. B. ZFS-Pool im Zustand SUSPENDED)
	timeoutRefresh = 10 * time.Minute // Erneuern im Hintergrund insgesamt

	slowReboot     = 10 * time.Minute // Puffer fuer freebsd-version
	slowRetry      = 5 * time.Minute  // gescheiterter langsamer Abschnitt: so bald neu versuchen
	slowFirstWait  = 2 * time.Second  // erster Lauf: so lange auf das Ergebnis warten, dann Hinweis
	deadlineMargin = 3 * time.Second  // Collect endet so viel vor der ctx-Deadline (Antwort muss noch raus)
)

// In Tests veraenderbar.
var (
	refreshTimeout = timeoutRefresh
	statfsLimit    = timeoutStatfs
)

// Typen und Programmstart wie beim Linux-Sammler.
type (
	ExecResult = m64linux.ExecResult
	ExecFunc   = m64linux.ExecFunc
)

// ErrNotFound: Programm nicht vorhanden.
var ErrNotFound = m64linux.ErrNotFound

// NoteReading steht in Notes (SMART, Updates, Neustart), solange der erste Lauf im Hintergrund noch laeuft.
const NoteReading = m64linux.NoteReading

// Options steuern Collect.
type Options struct {
	Sections []string                          // gewuenschte Abschnitte (m64proto.Sec*), leer = alle
	Exec     ExecFunc                          // nil = Programme direkt starten (m64linux.DefaultExec)
	Has      func(name string) bool            // Programm vorhanden? nil = Suche in PATH und sbin-Ordnern
	Sysctl   SysctlFunc                        // nil = unix.SysctlRaw (nur FreeBSD)
	Mounts   func() ([]Mount, error)           // nil = getfsstat (nur FreeBSD)
	Statfs   func(path string) (StatFS, error) // nil = statfs (nur FreeBSD)
	Now      func() time.Time                  // nil = time.Now
	Cache    *Cache                            // Puffer fuer langsame Abschnitte und haengende statfs; nil = Paket-Puffer
}

// Cache puffert langsame Abschnitte (SMART 30 min, Updates 60 min, Neustart 10 min) und merkt sich haengende
// statfs-Aufrufe. Verhalten wie m64linux.Cache: langsame Abschnitte laufen immer im Hintergrund; ist ein Stand
// veraltet, liefert Collect ihn sofort und erneuert ihn; beim ersten Mal wartet Collect hoechstens slowFirstWait
// und meldet sonst NoteReading. Ein Lauf mit Fehlern oder Abbruch gilt nur slowRetry lang; ein abgebrochener Lauf
// ersetzt keinen vorhandenen guten Stand.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*slowEntry
	statfs  map[string]*statfsCall
	wg      sync.WaitGroup
}

type slowEntry struct {
	res  slowResult
	have bool          // res stammt aus einem fertigen Lauf
	at   time.Time     // Ende des letzten Laufs (Uhr rueckwaerts = veraltet)
	next time.Time     // ab dann erneuern
	run  chan struct{} // laufende Erneuerung (wird beim Ende geschlossen), nil = keine
}

// slowResult ist das Ergebnis eines langsamen Abschnitts.
type slowResult struct {
	smart   []m64proto.SMART
	updates *m64proto.Updates
	reboot  *m64proto.Reboot
	errs    []m64proto.SectionErr
	notes   []m64proto.SectionNote
}

// statfsCall ist ein laufender statfs-Aufruf; haengt er, bleibt er hier stehen, bis er zurueckkommt.
type statfsCall struct {
	done  chan struct{}
	start time.Time
	res   StatFS
	err   error
}

// NewCache legt einen leeren Puffer an.
func NewCache() *Cache {
	return &Cache{entries: map[string]*slowEntry{}, statfs: map[string]*statfsCall{}}
}

// Wait wartet auf laufende Erneuerungen im Hintergrund (Tests, Beenden). Haengende statfs-Aufrufe zaehlen nicht.
func (c *Cache) Wait() { c.wg.Wait() }

var defaultCache = NewCache()

// Ordner, in denen Programme auch ohne passenden PATH gesucht werden (rc.d-Start, smartctl/pkg in /usr/local/sbin).
var extraPath = []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// lookPath sucht ein Programm in PATH und den sbin-Ordnern; "" = nicht gefunden. Absolute Pfade werden direkt
// geprueft.
func lookPath(name string) string {
	isExe := func(p string) bool {
		st, err := os.Stat(p)
		return err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0
	}
	if strings.HasPrefix(name, "/") {
		if isExe(name) {
			return name
		}
		return ""
	}
	if strings.ContainsAny(name, `/\`) || name == "" {
		return ""
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, d := range extraPath {
		if p := filepath.Join(d, name); isExe(p) {
			return p
		}
	}
	return ""
}

type collector struct {
	opt    Options
	exec   ExecFunc
	has    func(string) bool
	sc     SysctlFunc
	mounts func() ([]Mount, error)
	now    func() time.Time
	cache  *Cache
}

func newCollector(opt Options) *collector {
	c := &collector{opt: opt, exec: opt.Exec, has: opt.Has, sc: opt.Sysctl, mounts: opt.Mounts, now: opt.Now, cache: opt.Cache}
	if c.exec == nil {
		c.exec = m64linux.DefaultExec
	}
	if c.has == nil {
		c.has = func(n string) bool { return lookPath(n) != "" }
	}
	if c.sc == nil {
		c.sc = defaultSysctl
	}
	if c.mounts == nil {
		c.mounts = getMounts
	}
	if c.now == nil {
		c.now = time.Now
	}
	if c.cache == nil {
		c.cache = defaultCache
	}
	return c
}

// wantFunc liefert die Abschnittsauswahl (leer = alle).
func wantFunc(secs []string) func(string) bool {
	if len(secs) == 0 {
		return func(string) bool { return true }
	}
	m := map[string]bool{}
	for _, s := range secs {
		m[s] = true
	}
	return func(s string) bool { return m[s] }
}

// Collect liest die gewuenschten Abschnitte des lokalen Hosts. Fehlende Programme ergeben Notes, Fehler eines
// Abschnitts Errors; die uebrigen Abschnitte laufen weiter. Collect ist fuer gleichzeitige Aufrufe geeignet. Mit
// ctx-Deadline endet Collect rechtzeitig davor (langsame Abschnitte laufen im Hintergrund, Programme und statfs
// haben Zeitlimits innerhalb der Deadline).
func Collect(ctx context.Context, opt Options) *m64proto.Report {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) > 2*deadlineMargin {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl.Add(-deadlineMargin))
		defer cancel()
	}
	c := newCollector(opt)
	now := c.now()
	r := &m64proto.Report{V: m64proto.Version, Time: now.UnixMilli()}
	want := wantFunc(opt.Sections)

	r.Uptime = uptimeFrom(readBoottime(c.sc), now)
	cores := 0
	if want(m64proto.SecCPU) || want(m64proto.SecTemp) {
		cpu, err := readCPU(c.sc)
		if cpu != nil {
			cores = cpu.Cores
		}
		if want(m64proto.SecCPU) {
			r.CPU = cpu
			addErr(r, m64proto.SecCPU, err)
		}
	}
	if want(m64proto.SecMem) {
		c.collectMem(ctx, r)
	}
	if want(m64proto.SecLoad) {
		b, err := c.sc("vm.loadavg")
		if err == nil {
			r.Load, err = ParseLoadavg(b, longSize)
		}
		if err != nil {
			addErr(r, m64proto.SecLoad, fmt.Errorf("sysctl vm.loadavg: %w", err))
		}
	}
	if want(m64proto.SecFS) {
		c.collectFS(ctx, r)
	}
	if want(m64proto.SecDisk) {
		c.collectDisks(ctx, r)
	}
	if want(m64proto.SecNet) || want(m64proto.SecBond) {
		c.collectNet(ctx, r, want(m64proto.SecNet), want(m64proto.SecBond))
	}
	if want(m64proto.SecRAID) {
		c.collectRAID(ctx, r)
	}
	if want(m64proto.SecTemp) {
		r.Temps = readTemps(c.sc, cores)
	}
	if want(m64proto.SecZFS) {
		c.collectZFS(ctx, r)
	}
	if want(m64proto.SecReboot) && c.has("freebsd-version") {
		res := c.slow(ctx, m64proto.SecReboot, slowReboot, c.collectReboot)
		r.Reboot = res.reboot
		r.Errors = append(r.Errors, res.errs...)
		r.Notes = append(r.Notes, res.notes...)
	}
	if want(m64proto.SecSmart) {
		res := c.slow(ctx, m64proto.SecSmart, m64proto.SlowSmartSec*time.Second, c.collectSmart)
		r.SMART = res.smart
		r.Errors = append(r.Errors, res.errs...)
		r.Notes = append(r.Notes, res.notes...)
	}
	if want(m64proto.SecUpdates) {
		res := c.slow(ctx, m64proto.SecUpdates, m64proto.SlowUpdatesSec*time.Second, c.collectUpdates)
		r.Updates = res.updates
		r.Errors = append(r.Errors, res.errs...)
		r.Notes = append(r.Notes, res.notes...)
	}
	return r
}

// slow liefert einen gepufferten Abschnitt. Gelesen wird immer im Hintergrund (hoechstens ein Lauf je Schluessel);
// ohne fertigen Stand wartet slow kurz und liefert sonst den Hinweis NoteReading (Abschnitt key).
func (c *collector) slow(ctx context.Context, key string, maxAge time.Duration, fn func(context.Context) slowResult) slowResult {
	ca := c.cache
	ca.mu.Lock()
	if ca.entries == nil {
		ca.entries = map[string]*slowEntry{}
	}
	e := ca.entries[key]
	if e == nil {
		e = &slowEntry{}
		ca.entries[key] = e
	}
	now := c.now()
	stale := !e.have || now.Before(e.at) || !now.Before(e.next)
	if stale && e.run == nil {
		done := make(chan struct{})
		e.run = done
		ca.wg.Add(1)
		go func() {
			defer ca.wg.Done()
			bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
			defer cancel()
			nr := fn(bg)
			aborted := bg.Err() != nil
			ca.mu.Lock()
			defer ca.mu.Unlock()
			t := c.now()
			if !aborted || !e.have { // abgebrochen: guter alter Stand bleibt
				e.res, e.have = nr, true
			}
			e.at = t
			if aborted || len(nr.errs) > 0 {
				e.next = t.Add(slowRetry)
			} else {
				e.next = t.Add(maxAge)
			}
			e.run = nil
			close(done)
		}()
	}
	if e.have {
		res := e.res
		ca.mu.Unlock()
		return res
	}
	done := e.run
	ca.mu.Unlock()
	t := time.NewTimer(slowFirstWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	case <-ctx.Done():
	}
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if e.have {
		return e.res
	}
	return slowResult{notes: []m64proto.SectionNote{{Section: key, Note: NoteReading}}}
}

// run startet ein Programm mit Zeitlimit.
func (c *collector) run(ctx context.Context, timeout time.Duration, name string, args ...string) (ExecResult, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.exec(ctx, name, args...)
}

// runOK startet ein Programm und verlangt Exit-Code 0.
func (c *collector) runOK(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	res, err := c.run(ctx, timeout, name, args...)
	if err != nil {
		return nil, err
	}
	if res.Code != 0 {
		return nil, execErr(name, res)
	}
	return res.Stdout, nil
}

// execErr beschreibt einen fehlgeschlagenen Aufruf (Exit-Code und erste stderr-Zeile).
func execErr(name string, res ExecResult) error {
	msg := name + ": " + m64proto.Hint(m64proto.HintExitCode, fmt.Sprint(res.Code))
	if l := lines(res.Stderr); len(l) > 0 {
		msg += ": " + l[0]
	}
	return errors.New(clip(msg))
}

func (c *collector) collectMem(ctx context.Context, r *m64proto.Report) {
	m, pageSize, err := readMem(c.sc)
	if err != nil {
		addErr(r, m64proto.SecMem, err)
		return
	}
	if total, free, ok := readSwap(c.sc, pageSize); ok {
		m.SwapTotal, m.SwapFree = total, free
	} else if c.has("swapinfo") { // unbekanntes xswdev-Format
		out, err := c.runOK(ctx, timeoutShort, "swapinfo", "-k")
		if err == nil {
			m.SwapTotal, m.SwapFree, err = ParseSwapinfo(out)
		}
		addErr(r, m64proto.SecMem, err)
	}
	r.Mem = m
}

func (c *collector) collectFS(ctx context.Context, r *m64proto.Report) {
	mounts, err := c.mounts()
	if err != nil {
		addErr(r, m64proto.SecFS, fmt.Errorf("getfsstat: %w", err))
		return
	}
	st := c.opt.Statfs
	if st == nil {
		st = statfsPath
	}
	fsl, errs := FSFromStatfs(mounts, func(p string) (StatFS, error) { return c.statfsTimeout(ctx, st, p) })
	r.FS = fsl
	for i, e := range errs {
		if i >= 5 {
			break
		}
		addErr(r, m64proto.SecFS, e)
	}
}

// statfsTimeout ruft statfs mit Zeitlimit auf (wie m64linux): je Mount laeuft hoechstens ein Aufruf; haengt er
// laenger als statfsLimit, wird der Mount ohne neuen Versuch als Fehler gemeldet (kein Goroutinen-Leck).
func (c *collector) statfsTimeout(ctx context.Context, st func(string) (StatFS, error), p string) (StatFS, error) {
	ca := c.cache
	ca.mu.Lock()
	if ca.statfs == nil {
		ca.statfs = map[string]*statfsCall{}
	}
	call := ca.statfs[p]
	if call == nil {
		call = &statfsCall{done: make(chan struct{}), start: time.Now()}
		ca.statfs[p] = call
		go func() {
			s, err := st(p)
			ca.mu.Lock()
			call.res, call.err = s, err
			if ca.statfs[p] == call {
				delete(ca.statfs, p)
			}
			ca.mu.Unlock()
			close(call.done)
		}()
	} else if since := time.Since(call.start); since >= statfsLimit {
		ca.mu.Unlock()
		return StatFS{}, fmt.Errorf("statfs %s: %s", p, m64proto.Hint(m64proto.HintHung, since.Round(time.Second).String()))
	}
	ca.mu.Unlock()
	t := time.NewTimer(statfsLimit - time.Since(call.start))
	defer t.Stop()
	select {
	case <-call.done:
		return call.res, call.err
	case <-t.C:
		return StatFS{}, fmt.Errorf("statfs %s: %s", p, m64proto.HintTimeout)
	case <-ctx.Done():
		return StatFS{}, ctx.Err()
	}
}

func (c *collector) collectDisks(ctx context.Context, r *m64proto.Report) {
	if !c.has("iostat") {
		addNote(r, m64proto.SecDisk, m64proto.Hint(m64proto.HintMissing, "iostat"))
		return
	}
	out, err := c.runOK(ctx, timeoutShort, "iostat", iostatArgs...)
	if err == nil {
		var ds []m64proto.DiskIO
		if ds, err = ParseIostat(out); err == nil {
			if c.has("geom") { // Seriennummern (Zusatz; Fehler unwichtig)
				if g, gerr := c.runOK(ctx, timeoutShort, "geom", "disk", "list"); gerr == nil {
					mergeGeom(ds, ParseGeomDisks(g))
				}
			}
			r.Disks = ds
			return
		}
		err = fmt.Errorf("iostat: %w", err)
	}
	addErr(r, m64proto.SecDisk, err)
}

func (c *collector) collectNet(ctx context.Context, r *m64proto.Report, net, bond bool) {
	var cfgs []IfConfig
	if out, err := c.runOK(ctx, timeoutShort, "ifconfig", "-a"); err == nil {
		cfgs = ParseIfconfig(out)
	} else {
		sec := m64proto.SecNet
		if !net {
			sec = m64proto.SecBond
		}
		addErr(r, sec, err)
		if !net {
			return
		}
	}
	var counters []m64proto.NetIf
	var down map[string]bool
	if net {
		out, err := c.runOK(ctx, timeoutShort, "netstat", netstatArgs...)
		if err == nil {
			counters, down, err = ParseNetstatJSON(out)
			if err != nil {
				err = fmt.Errorf("netstat: %w", err)
			}
		}
		if err != nil {
			addErr(r, m64proto.SecNet, err)
		}
	}
	ifs, bonds := BuildNet(counters, down, cfgs)
	if net {
		r.Net = ifs
	}
	if bond {
		r.Bonds = bonds
	}
}

func (c *collector) collectRAID(ctx context.Context, r *m64proto.Report) {
	for _, class := range []string{geomMirror, geomRAID} {
		if !sysExists(c.sc, geomSysctl[class]) || !c.has(class) { // Modul nicht geladen: nichts aufrufen
			continue
		}
		out, err := c.runOK(ctx, timeoutShort, class, "status")
		if err != nil {
			addErr(r, m64proto.SecRAID, err)
			continue
		}
		r.RAID = append(r.RAID, ParseGeomStatus(class, out)...)
	}
}

// zfsLoaded: zpool laedt das Kernel-Modul zfs.ko nach, wenn es fehlt (libzfs). Deshalb nur aufrufen, wenn ZFS
// schon laeuft (arcstats gibt es dann immer).
func (c *collector) zfsLoaded() bool { return sysExists(c.sc, "kstat.zfs.misc.arcstats.size") }

func (c *collector) collectZFS(ctx context.Context, r *m64proto.Report) {
	if !c.zfsLoaded() || !c.has("zpool") {
		return
	}
	res, err := c.run(ctx, timeoutShort, "zpool", "list", "-Hp", "-o", "name,size,alloc,free,frag,health")
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			addErr(r, m64proto.SecZFS, err)
		}
		return
	}
	pools := m64linux.ParseZpoolList(res.Stdout)
	if len(pools) == 0 {
		if res.Code != 0 && len(lines(res.Stdout)) > 0 {
			addErr(r, m64proto.SecZFS, execErr("zpool list", res))
		}
		return
	}
	if st, err := c.run(ctx, timeoutShort, "zpool", "status"); err == nil {
		m64linux.MergeZpoolStatus(pools, m64linux.ParseZpoolStatus(st.Stdout))
	} else {
		addErr(r, m64proto.SecZFS, err)
	}
	r.ZFS = pools
}

func (c *collector) collectReboot(ctx context.Context) slowResult {
	var out slowResult
	res, err := c.runOK(ctx, timeoutVersion, "freebsd-version", "-k", "-r")
	if err == nil {
		if rb, ok := ParseFreeBSDVersion(res); ok {
			out.reboot = rb
			return out
		}
		err = errors.New("freebsd-version: " + errFormat.Error())
	}
	out.errs = append(out.errs, m64proto.SectionErr{Section: m64proto.SecReboot, Error: errText(err)})
	return out
}

func (c *collector) collectSmart(ctx context.Context) slowResult {
	var out slowResult
	note := func(s string) {
		out.notes = append(out.notes, m64proto.SectionNote{Section: m64proto.SecSmart, Note: s})
	}
	fail := func(err error) {
		out.errs = append(out.errs, m64proto.SectionErr{Section: m64proto.SecSmart, Error: errText(err)})
	}
	if !c.has("smartctl") {
		note(m64proto.Hint(m64proto.HintMissing, "smartctl"))
		return out
	}
	res, err := c.run(ctx, timeoutSmart, "smartctl", "--scan-open", "-j")
	if errors.Is(err, ErrNotFound) {
		note(m64proto.Hint(m64proto.HintMissing, "smartctl"))
		return out
	}
	if err != nil {
		fail(err)
		return out
	}
	devs, err := m64linux.ParseSmartScan(res.Stdout)
	if err != nil {
		fail(fmt.Errorf("smartctl --scan-open: %w", err))
		return out
	}
	devs = smartDisks(devs)
	if len(devs) == 0 {
		note(m64proto.HintNoSmartDisks)
		return out
	}
	out.smart = []m64proto.SMART{}
	for _, d := range devs {
		if ctx.Err() != nil {
			break
		}
		args := []string{"-j", "-a", "-n", "standby"}
		if d.Type != "" {
			args = append(args, "-d", d.Type)
		}
		args = append(args, d.Name)
		res, err := c.run(ctx, timeoutSmart, "smartctl", args...)
		if err != nil {
			out.smart = append(out.smart, m64proto.SMART{Device: d.Name, Error: errText(err)})
			continue
		}
		out.smart = append(out.smart, m64linux.ParseSmartctl(d.Name, res.Stdout))
	}
	return out
}

// smartSkipRE: Eintraege aus "smartctl --scan-open", die keine Platte mit SMART sind. Optische Laufwerke (cd0)
// melden nur "standby"; NVMe-Platten fuehrt FreeBSD ab 14 zusaetzlich ueber CAM als nda0, smartctl scheitert dort
// ("INQUIRY failed") und liest dieselbe Platte ueber /dev/nvme0.
var smartSkipRE = regexp.MustCompile(`^/dev/(cd|nda)[0-9]+$`)

// smartDisks laesst diese Eintraege weg (sonst stuende je NVMe-Platte ein unlesbares Geraet im Bericht).
func smartDisks(devs []m64linux.SmartDevice) []m64linux.SmartDevice {
	out := devs[:0:0]
	for _, d := range devs {
		if !smartSkipRE.MatchString(d.Name) {
			out = append(out, d)
		}
	}
	return out
}

// pkgPath liefert das echte pkg ("" = nicht installiert).
func (c *collector) pkgPath() string {
	for _, p := range pkgPaths {
		if c.has(p) {
			return p
		}
	}
	return ""
}

// pkgNoRepoRE: keine Paketquelle eingeschaltet (TrueNAS CORE: Updates nur ueber die Oberflaeche).
var pkgNoRepoRE = regexp.MustCompile(`(?i)no active remote repositor`)

func (c *collector) collectUpdates(ctx context.Context) slowResult {
	var out slowResult
	note := func(s string) {
		out.notes = append(out.notes, m64proto.SectionNote{Section: m64proto.SecUpdates, Note: clip(s)})
	}
	pkg := c.pkgPath()
	if pkg == "" {
		note(m64proto.HintPkgMissing)
		return out
	}
	res, err := c.run(ctx, timeoutUpdates, pkg, pkgVersionArgs...)
	if err == nil && res.Code != 0 {
		if pkgNoRepoRE.Match(res.Stderr) || pkgNoRepoRE.Match(res.Stdout) {
			note(m64proto.HintNoRepo)
			return out
		}
		err = execErr("pkg version", res)
	}
	if err != nil {
		out.errs = append(out.errs, m64proto.SectionErr{Section: m64proto.SecUpdates, Error: errText(err)})
		return out
	}
	u := &m64proto.Updates{Manager: mgrPkg, Pending: ParsePkgVersion(res.Stdout), Checked: c.now().Unix()}
	if ares, err := c.run(ctx, timeoutAudit, pkg, pkgAuditArgs...); err != nil {
		note(m64proto.HintSecUnknown + ": " + errText(err))
	} else if n, noDB, ok := ParsePkgAudit(ares.Stdout, ares.Stderr, ares.Code); ok {
		u.Security = n
	} else if noDB {
		note("pkg audit: " + m64proto.HintNoVulnDB)
	} else {
		note(m64proto.HintSecUnknown + ": " + errText(execErr("pkg audit", ares)))
	}
	out.updates = u
	return out
}

// Caps liefert die Abschnitte, die auf diesem Host Werte liefern koennen (fuer m64proto.Info.Caps).
func Caps(opt Options) []string {
	c := newCollector(opt)
	caps := []string{m64proto.SecCPU, m64proto.SecMem, m64proto.SecLoad, m64proto.SecFS, m64proto.SecNet, m64proto.SecTemp}
	if c.has("iostat") {
		caps = append(caps, m64proto.SecDisk)
	}
	if sysExists(c.sc, "net.link.lagg.default_use_flowid") {
		caps = append(caps, m64proto.SecBond)
	}
	for _, class := range []string{geomMirror, geomRAID} {
		if sysExists(c.sc, geomSysctl[class]) && c.has(class) {
			caps = append(caps, m64proto.SecRAID)
			break
		}
	}
	if c.zfsLoaded() && c.has("zpool") {
		caps = append(caps, m64proto.SecZFS)
	}
	if c.has("smartctl") {
		caps = append(caps, m64proto.SecSmart)
	}
	if c.pkgPath() != "" {
		caps = append(caps, m64proto.SecUpdates)
	}
	if c.has("freebsd-version") {
		caps = append(caps, m64proto.SecReboot)
	}
	return caps
}
