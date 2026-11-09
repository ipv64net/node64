package snmp

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// HOST-RESOURCES-MIB und UCD-SNMP-MIB (net-snmp unter Linux).
const (
	hrStorage      = ".1.3.6.1.2.1.25.2.3.1"
	hrStorageType  = hrStorage + ".2"
	hrStorageDescr = hrStorage + ".3"
	hrStorageUnits = hrStorage + ".4"
	hrStorageSize  = hrStorage + ".5"
	hrStorageUsed  = hrStorage + ".6"
	hrTypes        = ".1.3.6.1.2.1.25.2.1"
	hrTypeOther    = hrTypes + ".1"
	hrTypeRAM      = hrTypes + ".2"
	hrTypeVirtual  = hrTypes + ".3"
	hrTypeFixed    = hrTypes + ".4"
	hrTypeRemov    = hrTypes + ".5"
	hrTypeNetwork  = hrTypes + ".10"
	hrProcLoad     = ".1.3.6.1.2.1.25.3.3.1.2"

	ucdMem       = ".1.3.6.1.4.1.2021.4"
	ucdSwapTotal = ucdMem + ".3.0"
	ucdSwapAvail = ucdMem + ".4.0"
	ucdRealTotal = ucdMem + ".5.0"
	ucdRealAvail = ucdMem + ".6.0"
	ucdBuffer    = ucdMem + ".14.0"
	ucdCached    = ucdMem + ".15.0"
	ucdSwapTotX  = ucdMem + ".18.0" // 64-Bit-Varianten (net-snmp >= 5.8)
	ucdSwapAvX   = ucdMem + ".19.0"
	ucdRealTotX  = ucdMem + ".20.0"
	ucdSysAvail  = ucdMem + ".27.0"           // memSysAvail = MemAvailable (net-snmp >= 5.9)
	ucdLoadInt   = ".1.3.6.1.4.1.2021.10.1.5" // laLoadInt (Load * 100), Index 1/2/3 = 1/5/15 min
	ucdDsk       = ".1.3.6.1.4.1.2021.9.1"
	ucdDskPath   = ucdDsk + ".2"
	ucdDskTotLo  = ucdDsk + ".11"
	ucdDskTotHi  = ucdDsk + ".12"
	ucdDskAvLo   = ucdDsk + ".13"
	ucdDskAvHi   = ucdDsk + ".14"
	ucdDskUsLo   = ucdDsk + ".15"
	ucdDskUsHi   = ucdDsk + ".16"
	ucdSsCPU     = ".1.3.6.1.4.1.2021.11"
)

// ucdCPURaw: ssCpuRaw-Zaehler (user, nice, system, idle, wait, kernel, interrupt, softirq, steal).
var ucdCPURaw = []string{ucdSsCPU + ".50.0", ucdSsCPU + ".51.0", ucdSsCPU + ".52.0", ucdSsCPU + ".53.0", ucdSsCPU + ".54.0",
	ucdSsCPU + ".55.0", ucdSsCPU + ".56.0", ucdSsCPU + ".61.0", ucdSsCPU + ".64.0"}

var winDrive = regexp.MustCompile(`^([A-Za-z]:)\\`)

// Einhaengepunkte, die nicht von selbst angeboten werden (wie tmpfs/overlay/snap beim Agenten).
var fsHidden = []string{"/run", "/dev", "/sys", "/proc", "/snap/", "/var/lib/docker/", "/var/lib/containers/", "/var/lib/kubelet/",
	"/run/", "/System/Volumes/", "/private/var/vm", "/etc/hostname", "/etc/hosts", "/etc/resolv.conf"}

func fsDefault(mount string) bool {
	for _, p := range fsHidden {
		if mount == strings.TrimSuffix(p, "/") || strings.HasPrefix(mount, p) || strings.HasPrefix(mount, strings.TrimSuffix(p, "/")+"/") {
			return false
		}
	}
	return true
}

// collectHost: CPU, Load, RAM, Swap und Dateisysteme aus HOST-RESOURCES und UCD.
func (c *Collector) collectHost(r *round) {
	var ucd map[string]pdu
	if !c.isAbsent("ucd", r.now) {
		res, err := getScalars(r.ctx, r.c, append([]string{ucdRealTotal, ucdRealAvail, ucdBuffer, ucdCached, ucdSwapTotal, ucdSwapAvail,
			ucdSwapTotX, ucdSwapAvX, ucdRealTotX, ucdSysAvail, ucdLoadInt + ".1", ucdLoadInt + ".2", ucdLoadInt + ".3"}, ucdCPURaw...))
		if err != nil {
			r.part.add("UCD-SNMP", err, "mem", "swap", "load", "cpu")
		} else {
			c.markAbsent("ucd", r.now, len(res) == 0)
			ucd = res
		}
	}
	var hr table
	if !c.isAbsent("hr", r.now) {
		t, err := walkColumns(r.ctx, r.c, []string{hrStorageType, hrStorageDescr, hrStorageUnits, hrStorageSize, hrStorageUsed, hrProcLoad}, c.cfg.MaxRep)
		if err != nil {
			r.part.add("HOST-RESOURCES", err, "fs:", "mem", "swap", "cpu")
		} else {
			c.markAbsent("hr", r.now, len(t.rows()) == 0)
			hr = t
		}
	}
	var dsk table
	if !c.isAbsent("ucddsk", r.now) {
		t, err := walkColumns(r.ctx, r.c, []string{ucdDskPath, ucdDskTotLo, ucdDskTotHi, ucdDskAvLo, ucdDskAvHi, ucdDskUsLo, ucdDskUsHi}, c.cfg.MaxRep)
		if err != nil {
			r.part.add("UCD dskTable", err, "fs:")
		} else {
			c.markAbsent("ucddsk", r.now, len(t.col(ucdDskPath)) == 0)
			dsk = t
		}
	}
	cores := 0
	if hr != nil {
		cores = len(hr.col(hrProcLoad))
	}
	// CPU: hrProcessorLoad (Mittel der Kerne), sonst UCD ssCpuRaw
	if cores > 0 {
		sum := 0.0
		for _, p := range hr.col(hrProcLoad) {
			v, _ := num(p)
			sum += v
		}
		util := pct(sum/float64(cores), 100)
		r.out = append(r.out, model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true, Text: fmt.Sprintf("%d Kerne", cores),
			Metrics: []model.Metric{{Name: "util", Value: util, Unit: "%", Rule: model.RuleCPU}}})
	} else if s, ok := c.ucdCPU(r, ucd); ok {
		r.out = append(r.out, s)
	}
	// Load (UCD)
	if l1, ok1 := num(ucd[ucdLoadInt+".1"]); ok1 {
		l5, _ := num(ucd[ucdLoadInt+".2"])
		l15, _ := num(ucd[ucdLoadInt+".3"])
		l1, l5, l15 = l1/100, l5/100, l15/100
		s := model.Service{Key: "load", Name: "Load", Kind: "load", Default: true, Text: fmt.Sprintf("%.2f %.2f %.2f", l1, l5, l15),
			Metrics: []model.Metric{{Name: "l1", Value: l1}, {Name: "l5", Value: l5}, {Name: "l15", Value: l15}}}
		if cores > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "per_core", Value: round2(l5 / float64(cores)), Rule: model.RuleLoad})
		}
		r.out = append(r.out, s)
	}
	// RAM/Swap: UCD (verfuegbar = frei + Puffer + Cache), sonst hrStorage
	memDone, swapDone := false, false
	tot, ok := num(ucd[ucdRealTotX])
	if !ok {
		tot, ok = num(ucd[ucdRealTotal])
	}
	if ok && tot > 0 {
		av, okAv := num(ucd[ucdSysAvail])
		if !okAv {
			free, _ := num(ucd[ucdRealAvail])
			buf, _ := num(ucd[ucdBuffer])
			ca, _ := num(ucd[ucdCached])
			av = free + buf + ca
		}
		r.out = append(r.out, memService(tot*1024, min(tot, max(0, av))*1024))
		memDone = true
		st, ok := num(ucd[ucdSwapTotX])
		sa, _ := num(ucd[ucdSwapAvX])
		if !ok {
			st, _ = num(ucd[ucdSwapTotal])
			sa, _ = num(ucd[ucdSwapAvail])
		}
		if st > 0 {
			r.out = append(r.out, swapService(st*1024, min(st, max(0, sa))*1024))
		}
		swapDone = true
	}
	// Dateisysteme: UCD dskTable (exakt wie df, 64 Bit) vor hrStorage
	seen := map[string]bool{}
	if dsk != nil {
		for _, idx := range dsk.rows() {
			path := text(dsk.col(ucdDskPath)[idx])
			if path == "" {
				continue
			}
			tot := hiLo(dsk, ucdDskTotHi, ucdDskTotLo, idx) * 1024
			av := hiLo(dsk, ucdDskAvHi, ucdDskAvLo, idx) * 1024
			us := hiLo(dsk, ucdDskUsHi, ucdDskUsLo, idx) * 1024
			if tot <= 0 {
				continue
			}
			seen[path] = true
			r.out = append(r.out, fsService(path, tot, us, av, fsDefault(path)))
		}
	}
	if hr == nil {
		return
	}
	var ramSize, ramUsed, cacheUsed, availMem float64
	for _, idx := range hr.rows() {
		typ := ""
		if p, ok := hr.col(hrStorageType)[idx]; ok {
			if s, ok := p.Value.(string); ok {
				typ = normOID(s)
			}
		}
		descr := text(hr.col(hrStorageDescr)[idx])
		units, _ := num(hr.col(hrStorageUnits)[idx])
		size, _ := num(hr.col(hrStorageSize)[idx])
		used, _ := num(hr.col(hrStorageUsed)[idx])
		if units <= 0 {
			continue
		}
		size, used = signed32(size)*units, signed32(used)*units // Integer32, bei manchen Agenten negativ uebergelaufen
		ld := strings.ToLower(descr)
		switch typ {
		case hrTypeRAM:
			ramSize, ramUsed = size, used
		case hrTypeOther:
			switch ld { // net-snmp: Puffer/Cache sind Teil des belegten RAM, "Available memory" = MemAvailable
			case "memory buffers", "cached memory":
				cacheUsed += used
			case "available memory":
				availMem = size
			}
		case hrTypeVirtual:
			if strings.Contains(ld, "swap") && !swapDone && size > 0 {
				r.out = append(r.out, swapService(size, size-min(size, used)))
				swapDone = true
			}
		case hrTypeFixed, hrTypeNetwork, hrTypeRemov:
			mount := descr
			if m := winDrive.FindStringSubmatch(descr); m != nil {
				mount = strings.ToUpper(m[1])
			}
			if mount == "" || seen[mount] || size <= 0 {
				continue
			}
			seen[mount] = true
			r.out = append(r.out, fsService(mount, size, used, size-min(size, used), typ == hrTypeFixed && fsDefault(mount)))
		}
	}
	if !memDone && ramSize > 0 {
		used := ramUsed
		if cacheUsed > 0 && cacheUsed < used {
			used -= cacheUsed
		}
		avail := ramSize - min(ramSize, used)
		if availMem > 0 {
			avail = min(ramSize, availMem)
		}
		r.out = append(r.out, memService(ramSize, avail))
	}
}

// ucdCPU: CPU-Auslastung aus den ssCpuRaw-Zaehlern (Linux ohne hrProcessorLoad).
func (c *Collector) ucdCPU(r *round, ucd map[string]pdu) (model.Service, bool) {
	if ucd == nil {
		return model.Service{}, false
	}
	var d [9]float64
	ok := true
	have := false
	for i, o := range ucdCPURaw {
		p, has := ucd[o]
		if !has {
			continue
		}
		have = true
		v, _, okd := c.delta("cpu|"+o, p, r.now)
		if !okd {
			ok = false
		}
		d[i] = v
	}
	if !have {
		return model.Service{}, false
	}
	s := model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true}
	// kernel (55) und interrupt (56) sind bei Linux in system enthalten
	total := d[0] + d[1] + d[2] + d[3] + d[4] + d[7] + d[8]
	if ok && total > 0 {
		idle := d[3] + d[4]
		s.Metrics = append(s.Metrics, model.Metric{Name: "util", Value: pct(total-idle, total), Unit: "%", Rule: model.RuleCPU},
			model.Metric{Name: "iowait", Value: pct(d[4], total), Unit: "%"}, model.Metric{Name: "steal", Value: pct(d[8], total), Unit: "%"})
	}
	return s, true
}

func memService(total, avail float64) model.Service {
	return model.Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
		Metrics: []model.Metric{{Name: "used", Value: pct(total-avail, total), Unit: "%", Rule: model.RuleMem, Max: total}, {Name: "avail", Value: avail, Unit: "B"}},
		Text:    fmt.Sprintf("%s von %s frei", bytesText(avail), bytesText(total))}
}

func swapService(total, free float64) model.Service {
	return model.Service{Key: "swap", Name: "Swap", Kind: "swap", Default: true,
		Metrics: []model.Metric{{Name: "used", Value: pct(total-free, total), Unit: "%", Rule: model.RuleSwap, Max: total}},
		Text:    fmt.Sprintf("%s von %s frei", bytesText(free), bytesText(total))}
}

// fsService wie mapFS im Mapper: belegt als Anteil am fuer Benutzer Nutzbaren (used/(used+avail)).
func fsService(mount string, total, used, avail float64, def bool) model.Service {
	s := model.Service{Key: "fs:" + keyPart(mount), Name: "Dateisystem " + mount, Kind: "fs", Default: def}
	if len(mount) == 2 && mount[1] == ':' {
		s.Name = "Laufwerk " + mount
	}
	u := 0.0
	if used+avail > 0 {
		u = pct(used, used+avail)
	}
	s.Metrics = []model.Metric{{Name: "used", Value: u, Unit: "%", Rule: model.RuleFS, Max: total}, {Name: "free", Value: avail, Unit: "B", Max: total}}
	s.Text = fmt.Sprintf("%s von %s frei", bytesText(avail), bytesText(total))
	return s
}

// hiLo setzt einen 64-Bit-Wert aus zwei 32-Bit-Spalten zusammen.
func hiLo(t table, hi, lo, idx string) float64 {
	l, _ := num(t.col(lo)[idx])
	h, _ := num(t.col(hi)[idx])
	return signed32(h)*4294967296 + signed32(l)
}

// signed32: negativ gelesene Integer32 als vorzeichenlos deuten.
func signed32(v float64) float64 {
	if v < 0 && v >= -2147483648 {
		return v + 4294967296
	}
	return v
}
