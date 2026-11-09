package monitor64

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Abbildung eines Berichts (Agent bzw. SSH ohne Agent) auf Dienste und Messgroessen (Plan "Kernmodell").
// Zaehler werden hier in Raten umgerechnet (aus dem vorigen Bericht); Ueberlauf bzw. Neustart des Hosts
// (Zaehler kleiner als vorher) ergibt fuer diese Runde keinen Wert statt eines Sprungs.

// Typen aus dem Paket model (gemeinsam mit den API-Sammlern).
type (
	Service = model.Service
	Metric  = model.Metric
	Fact    = model.Fact
)

// Arten der Messgroessen (siehe model).
const (
	RuleCPU       = model.RuleCPU
	RuleLoad      = model.RuleLoad
	RuleMem       = model.RuleMem
	RuleSwap      = model.RuleSwap
	RuleFS        = model.RuleFS
	RuleStore     = model.RuleStore
	RuleDiskTemp  = model.RuleDiskTemp
	RuleNVMeTemp  = model.RuleNVMeTemp
	RuleWear      = model.RuleWear
	RuleIfUtil    = model.RuleIfUtil
	RuleIfErrRate = model.RuleIfErrRate
	RuleTemp      = model.RuleTemp
)

// MapReport bildet einen Bericht auf Dienste ab; prev ist der vorige Bericht desselben Zugangs (nil = erster).
func MapReport(prev, cur *m64proto.Report) []Service {
	if cur == nil {
		return nil
	}
	dt := 0.0
	if prev != nil && cur.Time > prev.Time {
		dt = float64(cur.Time-prev.Time) / 1000
	}
	var out []Service
	if s, ok := mapCPU(prevCPU(prev), cur.CPU); ok {
		out = append(out, s)
	}
	if cur.Load != nil {
		s := Service{Key: "load", Name: "Load", Kind: "load", Default: true,
			Metrics: []Metric{{Name: "l1", Value: cur.Load.L1}, {Name: "l5", Value: cur.Load.L5}, {Name: "l15", Value: cur.Load.L15}}}
		if cur.CPU != nil && cur.CPU.Cores > 0 {
			s.Metrics = append(s.Metrics, Metric{Name: "per_core", Value: round2(cur.Load.L5 / float64(cur.CPU.Cores)), Rule: RuleLoad})
		}
		s.Text = fmt.Sprintf("%.2f %.2f %.2f", cur.Load.L1, cur.Load.L5, cur.Load.L15)
		out = append(out, s)
	}
	if m := cur.Mem; m != nil && m.Total > 0 {
		used := float64(m.Total-min(m.Available, m.Total)) / float64(m.Total) * 100
		out = append(out, Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
			Metrics: []Metric{{Name: "used", Value: round2(used), Unit: "%", Rule: RuleMem, Max: float64(m.Total)}, {Name: "avail", Value: float64(m.Available), Unit: "B"}},
			Text:    fmt.Sprintf("%s von %s frei", bytesText(m.Available), bytesText(m.Total))})
		if m.SwapTotal > 0 {
			su := float64(m.SwapTotal-min(m.SwapFree, m.SwapTotal)) / float64(m.SwapTotal) * 100
			out = append(out, Service{Key: "swap", Name: "Swap", Kind: "swap", Default: true,
				Metrics: []Metric{{Name: "used", Value: round2(su), Unit: "%", Rule: RuleSwap, Max: float64(m.SwapTotal)}}})
		}
	}
	for _, f := range cur.FS {
		out = append(out, mapFS(f))
	}
	out = append(out, mapDisks(prev, cur, dt)...)
	out = append(out, mapNet(prev, cur, dt)...)
	for _, b := range cur.Bonds {
		out = append(out, mapBond(b))
	}
	for _, r := range cur.RAID {
		out = append(out, mapRAID(r))
	}
	for _, z := range cur.ZFS {
		out = append(out, mapZFS(z))
	}
	for _, t := range cur.Temps {
		out = append(out, Service{Key: "temp:" + t.Name, Name: "Temperatur " + firstNonEmpty(t.Label, t.Name), Kind: "temp", Default: true,
			Metrics: []Metric{{Name: "temp", Value: round2(t.C), Unit: "°C", Rule: RuleTemp}}})
	}
	if s := cur.Systemd; s != nil {
		sv := Service{Key: "systemd", Name: "systemd-Dienste", Kind: "systemd", Default: true,
			Metrics: []Metric{{Name: "failed", Value: float64(len(s.Failed))}}}
		if len(s.Failed) > 0 {
			sv.Facts = append(sv.Facts, Fact{Code: "systemd_failed", Text: strings.Join(limitList(s.Failed, 5), ", ")})
			sv.Text = fmt.Sprintf("%d fehlgeschlagen: %s", len(s.Failed), strings.Join(limitList(s.Failed, 5), ", "))
		} else {
			sv.Text = "keine fehlgeschlagen"
		}
		out = append(out, sv)
	}
	if u := cur.Updates; u != nil {
		sv := Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true,
			Metrics: []Metric{{Name: "pending", Value: float64(u.Pending)}, {Name: "security", Value: float64(u.Security)}},
			Text:    fmt.Sprintf("%d verfügbar, %d Sicherheitsupdates", u.Pending, u.Security)}
		if u.Security > 0 {
			sv.Facts = append(sv.Facts, Fact{Code: "updates_security", Text: fmt.Sprintf("%d Sicherheitsupdates", u.Security)})
		}
		out = append(out, sv)
	}
	if r := cur.Reboot; r != nil {
		sv := Service{Key: "reboot", Name: "Neustart nötig", Kind: "reboot", Default: true, Text: "nein"}
		if r.Required {
			sv.Text = "ja"
			sv.Facts = append(sv.Facts, Fact{Code: "reboot_required", Text: strings.Join(limitList(r.Packages, 5), ", ")})
		}
		out = append(out, sv)
	}
	for _, l := range cur.Local {
		out = append(out, mapLocal(l))
	}
	out = append(out, mapWinSvc(cur.WinSvc)...) // Sammeldienst "Windows-Dienste" plus je Dienst (nicht vorgeschlagen)
	sort.SliceStable(out, func(i, j int) bool { return kindOrder(out[i].Kind) < kindOrder(out[j].Kind) })
	out = dedupeKeys(out)
	return out
}

func prevCPU(p *m64proto.Report) *m64proto.CPU {
	if p == nil {
		return nil
	}
	return p.CPU
}

func mapCPU(prev, cur *m64proto.CPU) (Service, bool) {
	if cur == nil {
		return Service{}, false
	}
	s := Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true}
	if cur.Cores > 0 {
		s.Text = fmt.Sprintf("%d Kerne", cur.Cores)
	}
	if cur.Util != nil { // fertiger Wert (Windows, SNMP)
		s.Metrics = append(s.Metrics, Metric{Name: "util", Value: round2(*cur.Util), Unit: "%", Rule: RuleCPU})
		return s, true
	}
	if prev == nil {
		return s, true // erste Runde: noch keine Rate
	}
	tot := func(c *m64proto.CPU) uint64 {
		return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
	}
	dTot, ok := delta(tot(prev), tot(cur))
	if !ok || dTot == 0 {
		return s, true
	}
	dIdle, ok1 := delta(prev.Idle+prev.IOWait, cur.Idle+cur.IOWait)
	dIO, ok2 := delta(prev.IOWait, cur.IOWait)
	dSteal, ok3 := delta(prev.Steal, cur.Steal)
	if !ok1 || !ok2 || !ok3 || dIdle > dTot {
		return s, true
	}
	s.Metrics = append(s.Metrics,
		Metric{Name: "util", Value: round2(float64(dTot-dIdle) / float64(dTot) * 100), Unit: "%", Rule: RuleCPU},
		Metric{Name: "iowait", Value: round2(float64(dIO) / float64(dTot) * 100), Unit: "%"},
		Metric{Name: "steal", Value: round2(float64(dSteal) / float64(dTot) * 100), Unit: "%"})
	return s, true
}

func mapFS(f m64proto.FS) Service {
	s := Service{Key: "fs:" + f.Mount, Name: "Dateisystem " + f.Mount, Kind: "fs", Default: true}
	// ZFS-Datasets von Gaesten (Proxmox subvol-/vm-) nicht von selbst anbieten – die Gaeste sind eigene Dienste
	if f.Type == "zfs" && (strings.Contains(f.Mount, "/subvol-") || strings.Contains(f.Mount, "/vm-") || strings.Contains(f.Mount, "/basevol-")) {
		s.Default = false
	}
	if len(f.Mount) == 2 && f.Mount[1] == ':' { // Windows-Laufwerk
		s.Name = "Laufwerk " + f.Mount
	}
	if f.Total > 0 {
		used := float64(f.Used) / float64(f.Used+f.Avail) * 100 // wie df: Anteil am fuer Benutzer Nutzbaren
		if f.Used+f.Avail == 0 {
			used = 0
		}
		s.Metrics = append(s.Metrics,
			Metric{Name: "used", Value: round2(used), Unit: "%", Rule: RuleFS, Max: float64(f.Total)},
			Metric{Name: "free", Value: float64(f.Avail), Unit: "B", Max: float64(f.Total)})
		s.Text = fmt.Sprintf("%s von %s frei", bytesText(f.Avail), bytesText(f.Total))
	}
	if f.InodesTotal > 0 {
		s.Metrics = append(s.Metrics, Metric{Name: "inodes", Value: round2(float64(f.InodesTotal-min(f.InodesFree, f.InodesTotal)) / float64(f.InodesTotal) * 100), Unit: "%"})
	}
	if f.ReadOnly {
		s.Text = strings.TrimSpace(s.Text + " · nur lesbar")
	}
	return s
}

// mapDisks fasst I/O (diskstats) und SMART je Platte zusammen; Schluessel ist die Seriennummer (stabil bei sda/sdb-Wechsel).
func mapDisks(prev, cur *m64proto.Report, dt float64) []Service {
	type acc struct {
		s      Service
		hasIO  bool
		smart  *m64proto.SMART
		sortBy string
	}
	byKey := map[string]*acc{}
	var order []string
	get := func(serial, name, model string) *acc {
		key := "disk:" + firstNonEmpty(serial, name)
		a, ok := byKey[key]
		if !ok {
			label := name
			if model != "" {
				label = name + " (" + model + ")"
			}
			a = &acc{s: Service{Key: key, Name: label, Kind: "disk", Default: true}, sortBy: name}
			byKey[key] = a
			order = append(order, key)
		}
		return a
	}
	prevIO := map[string]m64proto.DiskIO{}
	if prev != nil {
		for _, d := range prev.Disks {
			prevIO[d.Name] = d
		}
	}
	for _, d := range cur.Disks {
		a := get(d.Serial, d.Name, d.Model)
		a.hasIO = true
		if p, ok := prevIO[d.Name]; ok && dt > 0 {
			rb, ok1 := delta(p.ReadBytes, d.ReadBytes)
			wb, ok2 := delta(p.WriteBytes, d.WriteBytes)
			io, ok3 := delta(p.IOTimeMs, d.IOTimeMs)
			if ok1 && ok2 && ok3 {
				a.s.Metrics = append(a.s.Metrics,
					Metric{Name: "read", Value: math.Round(float64(rb) / dt), Unit: "B/s"},
					Metric{Name: "write", Value: math.Round(float64(wb) / dt), Unit: "B/s"},
					Metric{Name: "busy", Value: round2(math.Min(100, float64(io)/(dt*1000)*100)), Unit: "%"})
			}
		}
	}
	// Seriennummern aus diskstats (sysfs) – damit auch schlafende Platten ihren Schluessel behalten
	serialByName := map[string]string{}
	for _, d := range cur.Disks {
		if d.Serial != "" {
			serialByName[d.Name] = d.Serial
		}
	}
	prevBySerial, prevByDev := map[string]m64proto.SMART{}, map[string]m64proto.SMART{}
	if prev != nil {
		for _, sm := range prev.SMART {
			if sm.Serial != "" {
				prevBySerial[sm.Serial] = sm
			} else {
				prevByDev[sm.Device] = sm
			}
		}
	}
	for i := range cur.SMART {
		sm := &cur.SMART[i]
		devName := strings.TrimPrefix(sm.Device, "/dev/")
		if sm.Serial == "" {
			sm.Serial = serialByName[devName]
		}
		if isStandby(sm.Error) { // Platte schlaeft: letzten Stand behalten statt "nicht lesbar"
			p, ok := prevBySerial[sm.Serial]
			if !ok && sm.Serial == "" {
				p, ok = prevByDev[sm.Device]
			}
			if ok && p.Error == "" && (sm.Serial == "" || p.Serial == sm.Serial) {
				cur.SMART[i] = p
				sm = &cur.SMART[i]
			} else {
				continue // ohne Vorstand: nur I/O (Dienst bleibt ueber die Seriennummer aus sysfs erhalten)
			}
		}
		name := strings.TrimPrefix(sm.Device, "/dev/")
		// Platte schon aus diskstats bekannt? (gleicher Name, aber Seriennummer erst aus SMART)
		if sm.Serial != "" {
			if a, ok := byKey["disk:"+name]; ok {
				delete(byKey, "disk:"+name)
				a.s.Key = "disk:" + sm.Serial
				byKey[a.s.Key] = a
				for j, k := range order {
					if k == "disk:"+name {
						order[j] = a.s.Key
					}
				}
			}
		}
		a := get(sm.Serial, name, sm.Model)
		if sm.Model != "" && !strings.Contains(a.s.Name, "(") {
			a.s.Name = name + " (" + sm.Model + ")"
		}
		a.smart = sm
	}
	prevSmart := map[string]m64proto.SMART{}
	if prev != nil {
		for _, sm := range prev.SMART {
			prevSmart[firstNonEmpty(sm.Serial, sm.Device)] = sm
		}
	}
	var out []Service
	for _, k := range order {
		a := byKey[k]
		if a.smart != nil {
			sm := a.smart
			var parts []string
			if sm.Error != "" {
				parts = append(parts, "SMART nicht lesbar")
				a.s.Facts = append(a.s.Facts, Fact{Code: "smart_unreadable", Text: sm.Error})
			} else if sm.Passed != nil {
				if *sm.Passed {
					parts = append(parts, "SMART ok")
				} else {
					parts = append(parts, "SMART FAILED")
					a.s.Facts = append(a.s.Facts, Fact{Code: "smart_failed", Text: "Gesamtstatus FAILED"})
				}
			}
			if sm.TempC != nil {
				rule := RuleDiskTemp
				if sm.Type == "nvme" {
					rule = RuleNVMeTemp
				}
				a.s.Metrics = append(a.s.Metrics, Metric{Name: "temp", Value: round2(*sm.TempC), Unit: "°C", Rule: rule})
				parts = append(parts, fmt.Sprintf("%.0f °C", *sm.TempC))
			}
			if sm.WearPercentUsed != nil {
				a.s.Metrics = append(a.s.Metrics, Metric{Name: "wear", Value: round2(*sm.WearPercentUsed), Unit: "%", Rule: RuleWear})
				parts = append(parts, fmt.Sprintf("Verschleiß %.0f %%", *sm.WearPercentUsed))
			}
			sectors := uint64(0)
			for _, v := range []*uint64{sm.Reallocated, sm.Pending, sm.Uncorrectable} {
				if v != nil {
					sectors += *v
				}
			}
			addCounter := func(name string, v *uint64) {
				if v != nil {
					a.s.Metrics = append(a.s.Metrics, Metric{Name: name, Value: float64(*v)})
				}
			}
			addCounter("realloc", sm.Reallocated)
			addCounter("pending", sm.Pending)
			addCounter("uncorr", sm.Uncorrectable)
			addCounter("crc", sm.CRCErrors)
			addCounter("media_err", sm.MediaErrors)
			if sectors > 0 {
				code := "smart_sectors"
				if p, ok := prevSmart[firstNonEmpty(sm.Serial, sm.Device)]; ok && p.Pending != nil && sm.Pending != nil && *p.Pending < *sm.Pending {
					code = "smart_sectors_rising" // nur steigende ausstehende Sektoren (Plan)
				}
				a.s.Facts = append(a.s.Facts, Fact{Code: code, Text: fmt.Sprintf("%d umgelegte/ausstehende Sektoren", sectors)})
				parts = append(parts, fmt.Sprintf("%d Sektoren", sectors))
			}
			if sm.MediaErrors != nil && *sm.MediaErrors > 0 {
				a.s.Facts = append(a.s.Facts, Fact{Code: "smart_sectors", Text: fmt.Sprintf("%d Medienfehler", *sm.MediaErrors)})
			}
			if sm.CriticalWarning != nil && *sm.CriticalWarning != 0 {
				a.s.Facts = append(a.s.Facts, Fact{Code: "smart_failed", Text: fmt.Sprintf("NVMe-Warnung 0x%x", *sm.CriticalWarning)})
			}
			a.s.Text = strings.Join(parts, " · ")
		}
		out = append(out, a.s)
	}
	return out
}

func sectorsOf(sm m64proto.SMART) uint64 {
	n := uint64(0)
	for _, v := range []*uint64{sm.Reallocated, sm.Pending, sm.Uncorrectable} {
		if v != nil {
			n += *v
		}
	}
	return n
}

// mapNet: physische Ports, Bonds und Bridges (keine virtuellen Schnittstellen wie veth/tap/docker).
func mapNet(prev, cur *m64proto.Report, dt float64) []Service {
	prevIf := map[string]m64proto.NetIf{}
	if prev != nil {
		for _, n := range prev.Net {
			prevIf[n.Name] = n
		}
	}
	var out []Service
	for _, n := range cur.Net {
		if n.Kind == "virtual" || n.Name == "lo" {
			continue
		}
		s := Service{Key: "if:" + n.Name, Name: n.Name, Kind: "if", Default: n.Up}
		if n.SpeedMbit > 0 {
			s.Name = fmt.Sprintf("%s (%s)", n.Name, speedText(n.SpeedMbit))
		}
		state := "down"
		if n.Up {
			state = "up"
		}
		if p, ok := prevIf[n.Name]; ok && dt > 0 {
			rx, ok1 := delta(p.RxBytes, n.RxBytes)
			tx, ok2 := delta(p.TxBytes, n.TxBytes)
			if ok1 && ok2 {
				in, outb := float64(rx)*8/dt/1e6, float64(tx)*8/dt/1e6
				s.Metrics = append(s.Metrics, Metric{Name: "in", Value: round2(in), Unit: "Mbit/s"}, Metric{Name: "out", Value: round2(outb), Unit: "Mbit/s"})
				if n.SpeedMbit > 0 {
					s.Metrics = append(s.Metrics, Metric{Name: "util", Value: round2(math.Max(in, outb) / float64(n.SpeedMbit) * 100), Unit: "%", Rule: RuleIfUtil})
				}
				s.Text = fmt.Sprintf("↓ %s · ↑ %s", mbitText(in), mbitText(outb))
			}
			rp, ok3 := delta(p.RxPackets, n.RxPackets)
			tp, ok4 := delta(p.TxPackets, n.TxPackets)
			// Fehler ohne Verwerfungen (rx_dropped steigt auch bei harmlosen Frames, z. B. LLDP) und ohne
			// zusaetzliches CRC (rx_errors enthaelt die CRC-Fehler schon)
			re, ok5 := delta(p.RxErrors, n.RxErrors)
			te, ok6 := delta(p.TxErrors, n.TxErrors)
			if ok3 && ok4 && ok5 && ok6 {
				rate := 0.0
				if rp+tp > 0 {
					rate = float64(re+te) / float64(rp+tp) * 100
				}
				s.Metrics = append(s.Metrics, Metric{Name: "errrate", Value: round4(rate), Unit: "%", Rule: RuleIfErrRate}, Metric{Name: "errors", Value: float64(re + te)})
				if rd, okd := delta(p.RxDropped+p.TxDropped, n.RxDropped+n.TxDropped); okd {
					s.Metrics = append(s.Metrics, Metric{Name: "drops", Value: float64(rd)})
				}
				if re+te > 0 {
					s.Text = strings.TrimSpace(s.Text + fmt.Sprintf(" · %d Fehler", re+te))
				}
			}
		}
		if s.Text == "" {
			s.Text = state
		} else if !n.Up {
			s.Text = "down · " + s.Text
		}
		out = append(out, s)
	}
	return out
}

func mapBond(b m64proto.Bond) Service {
	s := Service{Key: "bond:" + b.Name, Name: b.Name, Kind: "bond", Default: true}
	up := 0
	var down []string
	for _, m := range b.Members {
		if strings.EqualFold(m.MII, "up") {
			up++
		} else {
			down = append(down, m.Name)
		}
	}
	lacp := strings.Contains(strings.ToLower(b.Mode), "802.3ad")
	if lacp {
		s.Name = b.Name + " (LACP)"
	}
	s.Metrics = []Metric{{Name: "members_up", Value: float64(up)}, {Name: "members", Value: float64(len(b.Members))}}
	s.Text = fmt.Sprintf("%d von %d aktiv", up, len(b.Members))
	if len(down) > 0 {
		s.Facts = append(s.Facts, Fact{Code: "bond_member_down", Text: strings.Join(down, ", ") + " down"})
		s.Text += " – " + strings.Join(down, ", ") + " down"
	}
	if lacp && b.AggregateID > 0 {
		var other []string
		for _, m := range b.Members {
			if strings.EqualFold(m.MII, "up") && m.AggregateID > 0 && m.AggregateID != b.AggregateID {
				other = append(other, m.Name)
			}
		}
		if len(other) > 0 {
			s.Facts = append(s.Facts, Fact{Code: "lacp_mismatch", Text: strings.Join(other, ", ") + " in anderem Aggregator"})
			s.Text += " – LACP passt nicht (" + strings.Join(other, ", ") + ")"
		}
	}
	return s
}

func mapRAID(r m64proto.RAID) Service {
	s := Service{Key: "raid:" + r.Name, Name: "RAID " + r.Name, Kind: "raid", Default: true,
		Metrics: []Metric{{Name: "active", Value: float64(r.Active)}, {Name: "devices", Value: float64(r.Devices)}}}
	s.Text = fmt.Sprintf("%s · %s · %d von %d aktiv", r.Level, r.State, r.Active, r.Devices)
	if r.SyncPercent != nil {
		s.Text += fmt.Sprintf(" · Sync %.1f %%", *r.SyncPercent)
	}
	st := strings.ToLower(r.State)
	if strings.Contains(st, "degraded") || strings.Contains(st, "fail") || r.Failed > 0 || (r.Devices > 0 && r.Active < r.Devices && r.SyncPercent == nil) {
		s.Facts = append(s.Facts, Fact{Code: "raid_degraded", Text: s.Text})
	}
	return s
}

func mapZFS(z m64proto.ZPool) Service {
	s := Service{Key: "zfs:" + z.Name, Name: "ZFS " + z.Name, Kind: "zfs", Default: true}
	if z.Size > 0 {
		s.Metrics = append(s.Metrics,
			Metric{Name: "used", Value: round2(float64(z.Alloc) / float64(z.Size) * 100), Unit: "%", Rule: RuleStore, Max: float64(z.Size)},
			Metric{Name: "free", Value: float64(z.Free), Unit: "B", Max: float64(z.Size)})
	}
	s.Text = z.Health
	if z.Size > 0 { // ohne Groesse (z. B. node_exporter) kein "0 B frei"
		s.Text = fmt.Sprintf("%s · %s frei", z.Health, bytesText(z.Free))
	}
	if !strings.EqualFold(z.Health, "ONLINE") {
		s.Facts = append(s.Facts, Fact{Code: "zfs_degraded", Text: z.Health + " " + z.Errors})
	} else if e := zfsErrors(z.Errors); e != "" {
		s.Facts = append(s.Facts, Fact{Code: "zfs_degraded", Text: e}) // ONLINE, aber Daten-/Pruefsummenfehler
	}
	return s
}

// zfsErrors: Fehlertext ohne den Hinweis "No known data errors" ("" = keine Fehler). Geraetefehler stehen dahinter
// ("No known data errors; Geraetefehler READ 0 WRITE 0 CKSUM 12") und zaehlen auch bei ONLINE.
func zfsErrors(raw string) string {
	var out []string
	for _, p := range strings.Split(raw, ";") {
		if p = strings.TrimSpace(p); p != "" && !strings.EqualFold(p, "no known data errors") {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

func mapLocal(l m64proto.LocalCheck) Service {
	s := Service{Key: "local:" + l.Name, Name: l.Name, Kind: "local", Default: true, Text: l.Text}
	for _, m := range l.Metrics {
		s.Metrics = append(s.Metrics, Metric{Name: m.Name, Value: m.Value})
	}
	state := l.State
	if state == -1 { // "P": aus den Metriken
		state = 0
		for _, m := range l.Metrics {
			if m.Crit != nil && m.Value >= *m.Crit {
				state = max(state, 2)
			} else if m.Warn != nil && m.Value >= *m.Warn {
				state = max(state, 1)
			}
		}
	}
	switch state {
	case 1:
		s.Facts = append(s.Facts, Fact{Code: "local_warn", Text: l.Text})
	case 2:
		s.Facts = append(s.Facts, Fact{Code: "local_crit", Text: l.Text})
	case 3:
		s.Facts = append(s.Facts, Fact{Code: "local_unknown", Text: l.Text})
	}
	return s
}

// delta: Zaehler-Differenz; false bei Ueberlauf/Neustart (neuer Wert kleiner).
func delta(old, cur uint64) (uint64, bool) {
	if cur < old {
		return 0, false
	}
	return cur - old, true
}

func kindOrder(k string) int {
	order := []string{"cpu", "load", "mem", "swap", "temp", "systemd", "updates", "reboot", "fs", "zfs", "raid", "disk", "if", "bond", "winsvc", "local"}
	for i, o := range order {
		if o == k {
			return i
		}
	}
	return len(order)
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func limitList(l []string, n int) []string {
	if len(l) <= n {
		return l
	}
	return append(append([]string{}, l[:n]...), fmt.Sprintf("+%d", len(l)-n))
}

// bytesText formatiert Bytes (1000er-Einheiten wie bei Plattengroessen).
func bytesText(b uint64) string {
	f := float64(b)
	for _, u := range []string{"B", "KB", "MB", "GB", "TB", "PB"} {
		if f < 1000 || u == "PB" {
			if u == "B" {
				return fmt.Sprintf("%d B", b)
			}
			return strings.Replace(fmt.Sprintf("%.1f %s", f, u), ".", ",", 1)
		}
		f /= 1000
	}
	return ""
}

func speedText(mbit int) string {
	if mbit >= 1000 && mbit%1000 == 0 {
		return fmt.Sprintf("%d Gbit/s", mbit/1000)
	}
	if mbit >= 1000 {
		return strings.Replace(fmt.Sprintf("%.1f Gbit/s", float64(mbit)/1000), ".", ",", 1)
	}
	return fmt.Sprintf("%d Mbit/s", mbit)
}

func mbitText(v float64) string {
	if v >= 1000 {
		return strings.Replace(fmt.Sprintf("%.1f Gbit/s", v/1000), ".", ",", 1)
	}
	if v >= 10 {
		return fmt.Sprintf("%.0f Mbit/s", v)
	}
	return strings.Replace(fmt.Sprintf("%.1f Mbit/s", v), ".", ",", 1)
}

// isStandby: SMART meldet eine schlafende Platte (auch EPC-Zustaende wie STANDBY_Y).
func isStandby(e string) bool {
	return e == m64linux.SmartErrStandby || strings.Contains(strings.ToLower(e), "standby")
}

// dedupeKeys: doppelte Dienst-Schluessel (z. B. Multipath ohne Seriennummer) bekommen einen Zusatz, damit das
// Erkennen nicht an UNIQUE(host_uid, key) scheitert.
func dedupeKeys(in []Service) []Service {
	seen := map[string]int{}
	for i := range in {
		k := in[i].Key
		if n := seen[k]; n > 0 {
			in[i].Key = fmt.Sprintf("%s#%d", k, n+1)
		}
		seen[k]++
	}
	return in
}
