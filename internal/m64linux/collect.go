package m64linux

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Zeitlimits je Programm (wie im Skript).
const (
	timeoutShort    = 10 * time.Second // systemctl, zpool
	timeoutSmart    = 20 * time.Second // smartctl je Platte bzw. --scan-open
	timeoutUpdates  = 90 * time.Second // Paketverwalter
	timeoutNeeds    = 30 * time.Second // needs-restarting (Python)
	timeoutStatfs   = 5 * time.Second  // statfs je Mount (haengende Mounts)
	timeoutVcgencmd = 3 * time.Second  // vcgencmd get_throttled (Raspberry Pi)
	timeoutRefresh  = 10 * time.Minute // Erneuern im Hintergrund insgesamt

	timeoutNeedsRestart = 10 * time.Minute // Puffer fuer needs-restarting
	slowRetry           = 5 * time.Minute  // gescheiterter langsamer Abschnitt: so bald neu versuchen
	slowFirstWait       = 2 * time.Second  // erster Lauf: so lange auf das Ergebnis warten, dann Hinweis
	deadlineMargin      = 3 * time.Second  // Collect endet so viel vor der ctx-Deadline (Antwort muss noch raus)
)

// In Tests veraenderbar.
var (
	refreshTimeout = timeoutRefresh
	statfsLimit    = timeoutStatfs
)

// NoteReading steht in Notes (SMART, Updates), solange der erste Lauf im Hintergrund noch nicht fertig ist. Hinweise
// und Fehlerteile, die der Sammler selbst formuliert, sind Codes (m64proto.Hint): die Node zeigt sie in der Sprache
// des Betrachters.
const NoteReading = m64proto.HintReading

// ExecResult ist das Ergebnis eines Programmaufrufs.
type ExecResult struct {
	Stdout []byte
	Stderr []byte
	Code   int // Exit-Code
}

// ExecFunc startet ein Programm (ohne Shell) und liefert Ausgabe und Exit-Code. Ein Fehler kommt nur, wenn das
// Programm nicht lief (fehlt: ErrNotFound, Zeitlimit, ...); Exit-Code != 0 ist kein Fehler.
type ExecFunc func(ctx context.Context, name string, args ...string) (ExecResult, error)

// ErrNotFound: Programm nicht vorhanden.
var ErrNotFound = errors.New(m64proto.HintNotFound)

// Options steuern Collect.
type Options struct {
	Sections []string                          // gewuenschte Abschnitte (m64proto.Sec*), leer = alle
	Root     string                            // Wurzel fuer /proc, /sys, /var (Tests, Agent im Container); "" = "/"
	Exec     ExecFunc                          // nil = Programme direkt starten (DefaultExec)
	Has      func(name string) bool            // Programm vorhanden? nil = Suche in PATH und sbin-Ordnern
	Statfs   func(path string) (StatFS, error) // nil = statfs (nur Linux)
	Now      func() time.Time                  // nil = time.Now
	Cache    *Cache                            // Puffer fuer SMART/Updates und haengende Mounts; nil = Paket-Puffer
}

// Cache puffert langsame Abschnitte (SMART 30 min, Updates 60 min) und merkt sich haengende statfs-Aufrufe.
//
// Langsame Abschnitte laufen immer im Hintergrund: ist ein Stand veraltet, liefert Collect ihn sofort und erneuert
// ihn; beim ersten Mal wartet Collect hoechstens slowFirstWait (bzw. bis ctx endet) und meldet sonst NoteReading.
// Ein Lauf, der am Zeitlimit abbrach oder Fehler brachte, gilt nur slowRetry lang; ein abgebrochener Lauf ersetzt
// keinen vorhandenen guten Stand.
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
	smart    []m64proto.SMART
	updates  *m64proto.Updates
	required *bool // needs-restarting
	errs     []m64proto.SectionErr
	notes    []m64proto.SectionNote
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

type collector struct {
	opt   Options
	src   source
	exec  ExecFunc
	has   func(string) bool
	now   func() time.Time
	cache *Cache
}

func newCollector(opt Options) *collector {
	c := &collector{opt: opt, src: osSource{root: opt.Root}, exec: opt.Exec, has: opt.Has, now: opt.Now, cache: opt.Cache}
	if c.exec == nil {
		c.exec = DefaultExec
	}
	if c.has == nil {
		c.has = func(n string) bool { return lookPath(n) != "" }
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
// Abschnitts Errors; die uebrigen Abschnitte laufen weiter. Collect ist fuer gleichzeitige Aufrufe geeignet.
// Mit ctx-Deadline endet Collect rechtzeitig davor (langsame Abschnitte laufen im Hintergrund, Programme und statfs
// haben Zeitlimits innerhalb der Deadline).
func Collect(ctx context.Context, opt Options) *m64proto.Report {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) > 2*deadlineMargin {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl.Add(-deadlineMargin))
		defer cancel()
	}
	c := newCollector(opt)
	r := &m64proto.Report{V: m64proto.Version, Time: c.now().UnixMilli()}
	want := wantFunc(opt.Sections)

	readProcBasics(c.src, r, want)
	if want(m64proto.SecFS) {
		c.collectFS(ctx, r)
	}
	if want(m64proto.SecDisk) {
		ds, err := readDisks(c.src)
		r.Disks = ds
		addErr(r, m64proto.SecDisk, err)
	}
	if want(m64proto.SecNet) {
		ns, err := readNet(c.src)
		r.Net = ns
		addErr(r, m64proto.SecNet, err)
	}
	if want(m64proto.SecBond) {
		bs, errs := readBonds(c.src)
		r.Bonds = bs
		for _, e := range errs {
			addErr(r, m64proto.SecBond, e)
		}
	}
	if want(m64proto.SecRAID) && c.src.Exists("/proc/mdstat") {
		b, err := c.src.ReadFile("/proc/mdstat")
		if err == nil {
			r.RAID = ParseMdstat(b)
		}
		addErr(r, m64proto.SecRAID, err)
	}
	if want(m64proto.SecRAID) {
		r.Btrfs = readBtrfs(c.src)
	}
	if want(m64proto.SecTemp) {
		r.Temps = readTemps(c.src)
		r.Power = c.collectPower(ctx)
	}
	if want(m64proto.SecZFS) {
		c.collectZFS(ctx, r)
	}
	if want(m64proto.SecSystemd) {
		c.collectSystemd(ctx, r)
	}
	if want(m64proto.SecReboot) {
		c.collectReboot(ctx, r)
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

// execErr beschreibt einen fehlgeschlagenen Aufruf (Exit-Code und erste stderr-Zeile).
func execErr(name string, res ExecResult) error {
	msg := name + ": " + m64proto.Hint(m64proto.HintExitCode, strconv.Itoa(res.Code))
	if l := lines(res.Stderr); len(l) > 0 {
		msg += ": " + l[0]
	}
	return errors.New(clip(msg))
}

func (c *collector) collectFS(ctx context.Context, r *m64proto.Report) {
	b, err := c.src.ReadFile("/proc/mounts")
	if err != nil {
		addErr(r, m64proto.SecFS, err)
		return
	}
	st := c.opt.Statfs
	if st == nil {
		root := c.opt.Root
		st = func(p string) (StatFS, error) { return statfsPath(joinRoot(root, p)) }
	}
	fsl, errs := FSFromStatfs(ParseMounts(b), func(p string) (StatFS, error) { return c.statfsTimeout(ctx, st, p) })
	r.FS = fsl
	for i, e := range errs {
		if i >= 5 {
			break
		}
		addErr(r, m64proto.SecFS, e)
	}
}

// statfsTimeout ruft statfs mit Zeitlimit auf (haengende Mounts blockieren sonst den ganzen Bericht). statfs laesst
// sich nicht abbrechen: der Aufruf bleibt im Cache stehen, bis er zurueckkommt. Je Mount laeuft hoechstens einer;
// gleichzeitige Aufrufe warten auf denselben, und haengt er schon laenger als statfsLimit, wird der Mount ohne
// neuen Versuch als Fehler gemeldet (kein Goroutinen-/Thread-Leck bei dauerhaft haengendem NFS).
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

func (c *collector) collectZFS(ctx context.Context, r *m64proto.Report) {
	if !c.has("zpool") {
		return
	}
	res, err := c.run(ctx, timeoutShort, "zpool", zpoolListArgs...)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			addErr(r, m64proto.SecZFS, err)
		}
		return
	}
	pools := ParseZpoolList(res.Stdout)
	if len(pools) == 0 {
		if res.Code != 0 && len(lines(res.Stdout)) > 0 {
			addErr(r, m64proto.SecZFS, execErr("zpool list", res))
		}
		return
	}
	if st, err := c.run(ctx, timeoutShort, "zpool", "status"); err == nil {
		MergeZpoolStatus(pools, ParseZpoolStatus(st.Stdout))
	} else {
		addErr(r, m64proto.SecZFS, err)
	}
	r.ZFS = pools
}

func (c *collector) collectSystemd(ctx context.Context, r *m64proto.Report) {
	if !c.src.Exists("/run/systemd/system") || !c.has("systemctl") {
		addNote(r, m64proto.SecSystemd, m64proto.HintNoSystemd)
		return
	}
	failed, err := c.run(ctx, timeoutShort, "systemctl", "--failed", "--no-legend", "--plain")
	if err != nil {
		addErr(r, m64proto.SecSystemd, err)
		return
	}
	if failed.Code != 0 {
		addErr(r, m64proto.SecSystemd, execErr("systemctl --failed", failed))
		return
	}
	state, err := c.run(ctx, timeoutShort, "systemctl", "is-system-running")
	if err != nil { // Zustand ist Zusatz; Liste gilt trotzdem
		state = ExecResult{}
	}
	r.Systemd = newSystemd(failed.Stdout, state.Stdout)
}

// collectPower: Stromversorgung eines Raspberry Pi (vcgencmd, sonst nur der Alarm des Kernels).
func (c *collector) collectPower(ctx context.Context) *m64proto.Power {
	var out []byte
	if c.has("vcgencmd") {
		if res, err := c.run(ctx, timeoutVcgencmd, "vcgencmd", "get_throttled"); err == nil && res.Code == 0 {
			out = res.Stdout
		}
	}
	return powerFrom(out, c.src)
}

func (c *collector) collectReboot(ctx context.Context, r *m64proto.Report) {
	rb := readReboot(c.src)
	if !rb.Required && c.has("needs-restarting") { // RHEL: Python-Aufruf, daher 10 min gepuffert
		res := c.slow(ctx, "needs-restarting", timeoutNeedsRestart, func(ctx context.Context) slowResult {
			var out slowResult
			if res, err := c.run(ctx, timeoutNeeds, "needs-restarting", "-r"); err == nil {
				if req, ok := ParseNeedsRestarting(res.Code); ok {
					out.required = &req
				}
			}
			return out
		})
		if res.required != nil {
			rb.Required = *res.required
		}
	}
	r.Reboot = rb
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
	devs, err := ParseSmartScan(res.Stdout)
	if err != nil {
		fail(fmt.Errorf("smartctl --scan-open: %w", err))
		return out
	}
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
		out.smart = append(out.smart, ParseSmartctl(d.Name, res.Stdout))
	}
	if ds, err := readDisks(c.src); err == nil { // Seriennummer schlafender Platten aus /sys
		fillSmartSerials(out.smart, ds)
	}
	return out
}

// detectMgr sucht den Paketverwalter.
func detectMgr(has func(string) bool) string {
	switch {
	case has(aptCheckPath):
		return mgrAptCheck
	case has("apt-get"):
		return mgrApt
	case has("dnf"):
		return mgrDnf
	case has("yum"):
		return mgrYum
	case has("zypper"):
		return mgrZypper
	case has("checkupdates"), has("pacman"):
		return mgrPacman
	case has("apk"):
		return mgrApk
	case has("opkg"):
		return mgrOpkg
	}
	return ""
}

func (c *collector) collectUpdates(ctx context.Context) slowResult {
	var out slowResult
	fail := func(err error) {
		out.errs = append(out.errs, m64proto.SectionErr{Section: m64proto.SecUpdates, Error: errText(err)})
	}
	mgr := detectMgr(c.has)
	if mgr == "" {
		out.notes = append(out.notes, m64proto.SectionNote{Section: m64proto.SecUpdates, Note: m64proto.HintNoPkgManager})
		return out
	}
	// ok sagt, welche Exit-Codes eine gueltige Liste bedeuten
	type call struct {
		name string
		args []string
		ok   func(int) bool
	}
	zero := func(code int) bool { return code == 0 }
	var list, sec *call
	aptCall := &call{"apt-get", aptSimArgs, zero}
	switch mgr {
	case mgrAptCheck:
		list = &call{aptCheckPath, nil, zero}
	case mgrApt:
		list = aptCall
	case mgrDnf, mgrYum:
		list = &call{mgr, []string{"-q", "check-update"}, func(c int) bool { return c == 0 || c == 100 }}
		sec = &call{mgr, []string{"-q", "updateinfo", "list", "--security"}, zero}
	case mgrZypper:
		list = &call{"zypper", []string{"-n", "-q", "list-updates"}, zero}
		sec = &call{"zypper", []string{"-n", "-q", "list-patches", "--category", "security"}, func(c int) bool { return c == 0 || c == 100 || c == 101 }}
	case mgrPacman:
		if c.has("checkupdates") {
			list = &call{"checkupdates", nil, func(c int) bool { return c == 0 || c == 2 }}
		} else {
			list = &call{"pacman", []string{"-Qu"}, func(c int) bool { return c == 0 || c == 1 }}
		}
	case mgrApk:
		list = &call{"apk", []string{"list", "-u"}, zero}
	case mgrOpkg:
		list = &call{"opkg", []string{"list-upgradable"}, zero}
	}
	runCall := func(k *call) ([]byte, error) {
		res, err := c.run(ctx, timeoutUpdates, k.name, k.args...)
		if err != nil {
			return nil, err
		}
		if !k.ok(res.Code) {
			return nil, execErr(k.name, res)
		}
		if mgr == mgrAptCheck {
			return res.Stderr, nil // apt-check schreibt auf stderr
		}
		return res.Stdout, nil
	}
	if mgr == mgrAptCheck {
		if b, err := runCall(list); err == nil {
			if u, err := ParseUpdates(mgrAptCheck, b, nil); err == nil {
				u.Checked = c.now().Unix()
				out.updates = u
				return out
			}
		}
		if !c.has("apt-get") {
			fail(errors.New("apt-check: " + m64proto.HintNotParsable))
			return out
		}
		mgr, list = mgrApt, aptCall // apt-check kaputt: apt-get
	}
	lb, err := runCall(list)
	if err != nil {
		fail(err)
		return out
	}
	var sb []byte
	if sec != nil {
		if b, err := runCall(sec); err == nil {
			sb = b
		} else {
			out.notes = append(out.notes, m64proto.SectionNote{Section: m64proto.SecUpdates, Note: clip(m64proto.HintSecUnknown + ": " + errText(err))})
		}
	}
	u, err := ParseUpdates(mgr, lb, sb)
	if err != nil {
		fail(fmt.Errorf("%s: %w", mgr, err))
		return out
	}
	u.Checked = c.now().Unix()
	out.updates = u
	return out
}

// Caps liefert die Abschnitte, die auf diesem Host Werte liefern koennen (fuer m64proto.Info.Caps).
func Caps(opt Options) []string {
	c := newCollector(opt)
	caps := []string{m64proto.SecCPU, m64proto.SecMem, m64proto.SecLoad, m64proto.SecFS, m64proto.SecDisk,
		m64proto.SecNet, m64proto.SecTemp, m64proto.SecReboot}
	if c.src.Exists("/proc/net/bonding") {
		caps = append(caps, m64proto.SecBond)
	}
	if c.src.Exists("/proc/mdstat") {
		caps = append(caps, m64proto.SecRAID)
	}
	if c.has("zpool") {
		caps = append(caps, m64proto.SecZFS)
	}
	if c.has("smartctl") {
		caps = append(caps, m64proto.SecSmart)
	}
	if c.src.Exists("/run/systemd/system") && c.has("systemctl") {
		caps = append(caps, m64proto.SecSystemd)
	}
	if detectMgr(c.has) != "" {
		caps = append(caps, m64proto.SecUpdates)
	}
	return caps
}
