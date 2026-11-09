//go:build windows

package m64win

import (
	"context"
	"errors"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

type collector struct {
	opt   Options
	now   func() time.Time
	cache *Cache
	ps    PSFunc
}

func newCollector(opt Options) *collector {
	c := &collector{opt: opt, now: opt.Now, cache: opt.Cache, ps: opt.PS}
	if c.now == nil {
		c.now = time.Now
	}
	if c.cache == nil {
		c.cache = defaultCache
	}
	if c.ps == nil {
		c.ps = runPS
	}
	return c
}

// Collect liest die gewuenschten Abschnitte des lokalen Windows-Hosts. Fehler eines Abschnitts stehen in Errors,
// fehlende Rechte bzw. Programme in Notes; die uebrigen Abschnitte laufen weiter. Die schnellen Werte kommen direkt
// aus der Windows-API, SMART/Storage Spaces/Updates aus dem Cache (PowerShell im Hintergrund).
func Collect(ctx context.Context, opt Options) *m64proto.Report {
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) > 2*deadlineMargin {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, dl.Add(-deadlineMargin))
		defer cancel()
	}
	c := newCollector(opt)
	r := &m64proto.Report{V: m64proto.Version, Time: c.now().UnixMilli(), Uptime: uptime().Seconds()}
	want := wantFunc(opt.Sections)

	if want(m64proto.SecCPU) {
		cpu, err := readCPU()
		r.CPU = cpu
		addErr(r, m64proto.SecCPU, err)
	}
	if want(m64proto.SecMem) {
		m, err := readMem()
		r.Mem = m
		addErr(r, m64proto.SecMem, err)
	}
	if want(m64proto.SecFS) {
		fs, errs := readFS(ctx, c.cache)
		r.FS = fs
		for i, e := range errs {
			if i >= 5 {
				break
			}
			addErr(r, m64proto.SecFS, e)
		}
	}
	var disks []m64proto.DiskIO
	if want(m64proto.SecDisk) || want(m64proto.SecSmart) {
		var err error
		var hung []error
		disks, hung, err = readDisks(ctx, c.cache)
		if want(m64proto.SecDisk) {
			r.Disks = disks
			addErr(r, m64proto.SecDisk, err)
			for i, h := range hung {
				if i >= 5 {
					break
				}
				addNote(r, m64proto.SecDisk, h.Error())
			}
		}
	}
	if want(m64proto.SecNet) {
		n, err := readNet()
		r.Net = n
		addErr(r, m64proto.SecNet, err)
	}
	if want(m64proto.SecWinSvc) {
		s, err := readServices()
		r.WinSvc = s
		addErr(r, m64proto.SecWinSvc, err)
	}
	ps := hasPowerShell()
	if want(m64proto.SecSmart) || want(m64proto.SecRAID) {
		c.collectStorage(ctx, r, want, disks, ps)
	}
	wuReboot := false
	if want(m64proto.SecUpdates) || want(m64proto.SecReboot) {
		if !ps {
			if want(m64proto.SecUpdates) {
				addNote(r, m64proto.SecUpdates, "PowerShell fehlt")
			}
		} else if want(m64proto.SecUpdates) {
			res := c.cache.slow(ctx, c.now, keyUpdates, m64proto.SecUpdates, m64proto.SlowUpdatesSec*time.Second, c.collectUpdates)
			r.Updates = res.updates
			wuReboot = res.reboot
			r.Errors = append(r.Errors, res.errs...)
			r.Notes = append(r.Notes, res.notes...)
		} else if res, ok := c.cache.peek(keyUpdates); ok {
			wuReboot = res.reboot // nur reboot gewuenscht: letzten Stand von Windows Update mitnehmen
		}
	}
	if want(m64proto.SecReboot) {
		wu, cbs, ren := readReboot()
		r.Reboot = rebootFrom(wu, cbs, ren, wuReboot)
	}
	return r
}

// collectStorage liefert SMART (30 min) und Storage Spaces; gibt es virtuelle Datentraeger, wird deren Zustand
// alle raidEvery neu gelesen.
func (c *collector) collectStorage(ctx context.Context, r *m64proto.Report, want func(string) bool, disks []m64proto.DiskIO, ps bool) {
	if !ps {
		if want(m64proto.SecSmart) {
			addNote(r, m64proto.SecSmart, "PowerShell fehlt")
		}
		return
	}
	res := c.cache.slow(ctx, c.now, keyStorage, m64proto.SecSmart, m64proto.SlowSmartSec*time.Second, c.storageFn(storageScript, m64proto.SecSmart))
	raid := res.raid
	raidErrs := filterErrs(res.errs, m64proto.SecRAID)
	if res.vdisks > 0 && want(m64proto.SecRAID) {
		rr := c.cache.slow(ctx, c.now, keyRAID, m64proto.SecRAID, raidEvery, c.storageFn(raidScript, m64proto.SecRAID))
		if !reading(rr) {
			raid, raidErrs = rr.raid, filterErrs(rr.errs, m64proto.SecRAID)
		}
	}
	if want(m64proto.SecSmart) {
		if res.smart != nil {
			r.SMART = append([]m64proto.SMART(nil), res.smart...)
			fillSmartSerials(r.SMART, disks)
		}
		r.Errors = append(r.Errors, filterErrs(res.errs, m64proto.SecSmart)...)
		for _, n := range res.notes {
			if n.Section == m64proto.SecSmart {
				r.Notes = append(r.Notes, n)
			}
		}
	}
	if want(m64proto.SecRAID) {
		r.RAID = raid
		r.Errors = append(r.Errors, raidErrs...)
	}
}

// reading: noch kein fertiger Lauf (nur der Hinweis NoteReading).
func reading(res slowResult) bool {
	return len(res.notes) == 1 && res.notes[0].Note == NoteReading && res.raid == nil && res.errs == nil
}

func filterErrs(errs []m64proto.SectionErr, sec string) []m64proto.SectionErr {
	var out []m64proto.SectionErr
	for _, e := range errs {
		if e.Section == sec {
			out = append(out, e)
		}
	}
	return out
}

// storageFn fuehrt ein Storage-Skript aus und wertet es aus.
func (c *collector) storageFn(script, sec string) func(context.Context) slowResult {
	return func(ctx context.Context) slowResult {
		ctx, cancel := context.WithTimeout(ctx, timeoutStorage)
		defer cancel()
		b, err := c.ps(ctx, script)
		if err == nil {
			var res slowResult
			if res, err = ParseStorage(b); err == nil {
				return res
			}
		}
		return slowResult{errs: []m64proto.SectionErr{{Section: sec, Error: clip(err.Error())}}}
	}
}

func (c *collector) collectUpdates(ctx context.Context) slowResult {
	ctx, cancel := context.WithTimeout(ctx, timeoutUpdates)
	defer cancel()
	b, err := c.ps(ctx, updatesScript)
	if err == nil {
		var u *m64proto.Updates
		var reboot bool
		if u, reboot, err = ParseUpdates(b, c.now()); err == nil {
			return slowResult{updates: u, reboot: reboot}
		}
	}
	if err == nil {
		err = errors.New("unbekannter Fehler")
	}
	return slowResult{errs: []m64proto.SectionErr{{Section: m64proto.SecUpdates, Error: clip(err.Error())}}}
}

// Caps liefert die Abschnitte, die auf diesem Host Werte liefern koennen (fuer m64proto.Info.Caps).
func Caps(opt Options) []string {
	c := newCollector(opt)
	caps := []string{m64proto.SecCPU, m64proto.SecMem, m64proto.SecFS, m64proto.SecDisk, m64proto.SecNet,
		m64proto.SecWinSvc, m64proto.SecReboot}
	if hasPowerShell() {
		caps = append(caps, m64proto.SecSmart, m64proto.SecUpdates)
		if res, ok := c.cache.peek(keyStorage); ok && res.vdisks > 0 {
			caps = append(caps, m64proto.SecRAID)
		}
	}
	return caps
}
