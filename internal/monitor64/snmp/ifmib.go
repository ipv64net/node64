package snmp

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// IF-MIB (ifTable, ifXTable) und EtherLike-MIB (Duplex).
const (
	ifTable   = ".1.3.6.1.2.1.2.2.1"
	ifXTable  = ".1.3.6.1.2.1.31.1.1.1"
	ifDescr   = ifTable + ".2"
	ifType    = ifTable + ".3"
	ifSpeed   = ifTable + ".5"
	ifAdmin   = ifTable + ".7"
	ifOper    = ifTable + ".8"
	ifInOct   = ifTable + ".10"
	ifInUc    = ifTable + ".11"
	ifInNUc   = ifTable + ".12"
	ifInDisc  = ifTable + ".13"
	ifInErr   = ifTable + ".14"
	ifOutOct  = ifTable + ".16"
	ifOutUc   = ifTable + ".17"
	ifOutNUc  = ifTable + ".18"
	ifOutDisc = ifTable + ".19"
	ifOutErr  = ifTable + ".20"
	ifName    = ifXTable + ".1"
	ifHCInOct = ifXTable + ".6"
	ifHCInUc  = ifXTable + ".7"
	ifHCInMc  = ifXTable + ".8"
	ifHCInBc  = ifXTable + ".9"
	ifHCOutOc = ifXTable + ".10"
	ifHCOutUc = ifXTable + ".11"
	ifHCOutMc = ifXTable + ".12"
	ifHCOutBc = ifXTable + ".13"
	ifHigh    = ifXTable + ".15"
	ifAlias   = ifXTable + ".18"
	dot3Dup   = ".1.3.6.1.2.1.10.7.2.1.19" // dot3StatsDuplexStatus: 1 unknown, 2 half, 3 full
)

// ifInfo sind die selten wechselnden Angaben eines Ports.
type ifInfo struct {
	name, alias string
	typ         int
}

// Port-Arten (ifType), die von selbst angeboten werden, sobald sie einmal verbunden waren.
var physTypes = map[int]bool{6: true, 7: true, 62: true, 69: true, 71: true, 117: true, 161: true, 209: true}

// Port-Arten, die nie angeboten werden (Loopback, Tunnel, PPP ueber Ethernet intern ...).
var skipTypes = map[int]bool{24: true, 131: true, 150: true, 194: true}

// virtuelle Ports nach Namen (Docker, VMs, Proxmox-Firewall) – wie "virtual" im Agenten.
var virtPrefixes = []string{"veth", "docker", "br-", "virbr", "vnet", "tap", "tun", "fwbr", "fwpr", "fwln", "cali", "flannel", "cni"}

func isVirtual(name string) bool {
	n := strings.ToLower(name)
	if n == "lo" {
		return true
	}
	for _, p := range virtPrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// collectIF: Ports mit Durchsatz, Auslastung, Fehlerrate und Status.
func (c *Collector) collectIF(r *round) {
	if c.isAbsent("if", r.now) {
		return
	}
	if c.ifStatic == nil || r.now.Sub(c.ifStaticAt) >= staticEvery {
		cols := []string{ifDescr, ifType}
		if !r.c.v1() {
			cols = append(cols, ifName, ifAlias)
		}
		t, err := walkColumns(r.ctx, r.c, cols, c.cfg.MaxRep)
		if err != nil {
			r.part.add(model.T("monitor64.txt.mib_names", "mib", "IF-MIB"), err, "if:", "bond:")
			if c.ifStatic == nil {
				return
			}
		} else {
			st := map[string]ifInfo{}
			for _, idx := range t.rows() {
				typ, _ := num(t.col(ifType)[idx])
				name := firstNonEmpty(text(t.col(ifName)[idx]), text(t.col(ifDescr)[idx]), "ifIndex "+idx)
				st[idx] = ifInfo{name: name, alias: text(t.col(ifAlias)[idx]), typ: int(typ)}
			}
			c.markAbsent("if", r.now, len(st) == 0)
			if len(st) == 0 {
				return
			}
			c.ifStatic, c.ifStaticAt = st, r.now
		}
	}
	hc := !r.c.v1() && !c.noHC
	cols := []string{ifAdmin, ifOper, ifSpeed, ifInDisc, ifInErr, ifOutDisc, ifOutErr}
	if hc {
		cols = append(cols, ifHigh, ifHCInOct, ifHCInUc, ifHCInMc, ifHCInBc, ifHCOutOc, ifHCOutUc, ifHCOutMc, ifHCOutBc)
	} else {
		cols = append(cols, ifInOct, ifInUc, ifInNUc, ifOutOct, ifOutUc, ifOutNUc)
		if !r.c.v1() {
			cols = append(cols, ifHigh)
		}
	}
	dup := !c.isAbsent("dot3dup", r.now)
	if dup {
		cols = append(cols, dot3Dup)
	}
	t, err := walkColumns(r.ctx, r.c, cols, c.cfg.MaxRep)
	if err != nil {
		r.part.add("IF-MIB", err, "if:", "bond:")
		return
	}
	if dup {
		c.markAbsent("dot3dup", r.now, len(t.col(dot3Dup)) == 0)
	}
	if hc && len(t.col(ifHCInOct)) == 0 && len(t.col(ifOper)) > 0 {
		c.noHC = true // keine 64-Bit-Zaehler: ab der naechsten Runde 32 Bit
	}
	r.at = c.now() // Messzeitpunkt der Zaehler (nicht Rundenbeginn)
	c.buildPorts(r, t, hc)
}

// portKeys vergibt die Schluessel: ifName, bei doppelten Namen mit ifIndex.
func (c *Collector) portKeyMap() map[string]string {
	count := map[string]int{}
	for _, in := range c.ifStatic {
		count[keyPart(in.name)]++
	}
	out := map[string]string{}
	for idx, in := range c.ifStatic {
		k := "if:" + keyPart(in.name)
		if count[keyPart(in.name)] > 1 {
			k += "#" + idx
		}
		out[idx] = k
	}
	return out
}

func (c *Collector) buildPorts(r *round, t table, hc bool) {
	keys := c.portKeyMap()
	portKeys := map[int]string{}
	for idx, k := range keys {
		if n, err := strconv.Atoi(idx); err == nil {
			portKeys[n] = k
		}
	}
	c.portKeys = portKeys
	c.ifUpNow = map[string]bool{}
	r.ifOK = true
	for _, idx := range t.rows() {
		if v, ok := num(t.col(ifOper)[idx]); ok && v == 1 {
			c.ifUpNow[idx] = true
		}
	}
	for _, idx := range t.rows() {
		in, ok := c.ifStatic[idx]
		if !ok {
			c.ifStaticAt = time.Time{} // neuer Port: Namen in der naechsten Runde neu lesen
			continue
		}
		if skipTypes[in.typ] || isVirtual(in.name) {
			continue
		}
		key := keys[idx]
		oper, _ := num(t.col(ifOper)[idx])
		admin, _ := num(t.col(ifAdmin)[idx])
		up := oper == 1
		speed := 0.0
		if v, ok := num(t.col(ifHigh)[idx]); ok && v > 0 {
			speed = v
		} else if v, ok := num(t.col(ifSpeed)[idx]); ok && v > 0 && v < math.MaxUint32 {
			speed = v / 1e6
		}
		if up && (c.seenUp[key] || len(c.seenUp) < maxSeenUp) {
			c.seenUp[key] = true
		}
		name := model.Raw(in.name) // Namen vom Geraet
		if in.alias != "" && in.alias != in.name {
			name += " · " + model.Raw(in.alias)
		}
		if speed > 0 {
			name = fmt.Sprintf("%s (%s)", name, speedText(speed))
		}
		s := model.Service{Key: key, Name: name, Kind: "if", Default: c.seenUp[key] && physTypes[in.typ]}
		pre := "if|" + idx + "|"
		var inOct, outOct pdu
		var pkts []pdu
		if hc {
			inOct, outOct = t.col(ifHCInOct)[idx], t.col(ifHCOutOc)[idx]
			pkts = []pdu{t.col(ifHCInUc)[idx], t.col(ifHCInMc)[idx], t.col(ifHCInBc)[idx], t.col(ifHCOutUc)[idx], t.col(ifHCOutMc)[idx], t.col(ifHCOutBc)[idx]}
		} else {
			inOct, outOct = t.col(ifInOct)[idx], t.col(ifOutOct)[idx]
			pkts = []pdu{t.col(ifInUc)[idx], t.col(ifInNUc)[idx], t.col(ifOutUc)[idx], t.col(ifOutNUc)[idx]}
		}
		var parts []string
		rin, ok1 := c.rate(pre+"in", inOct, r.at)
		rout, ok2 := c.rate(pre+"out", outOct, r.at)
		if ok1 && ok2 {
			inM, outM := rin*8/1e6, rout*8/1e6
			s.Metrics = append(s.Metrics, model.Metric{Name: "in", Value: round2(inM), Unit: "Mbit/s"}, model.Metric{Name: "out", Value: round2(outM), Unit: "Mbit/s"})
			if speed > 0 {
				s.Metrics = append(s.Metrics, model.Metric{Name: "util", Value: round2(math.Min(100, math.Max(inM, outM)/speed*100)), Unit: "%", Rule: model.RuleIfUtil})
			}
			parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(inM), mbitText(outM)))
		}
		// Fehler ohne Verwerfungen (wie im Mapper); Fehlerrate bezogen auf alle Pakete
		pk, okp := 0.0, true
		for i, p := range pkts {
			if missing(p) {
				continue // NUcast/Multicast fehlen auf manchen Geraeten
			}
			d, _, ok := c.delta(pre+"p"+strconv.Itoa(i), p, r.at)
			if !ok {
				okp = false
			}
			pk += d
		}
		ie, _, ok3 := c.delta(pre+"ie", t.col(ifInErr)[idx], r.at)
		oe, _, ok4 := c.delta(pre+"oe", t.col(ifOutErr)[idx], r.at)
		if okp && ok3 && ok4 {
			rate := 0.0
			if pk > 0 {
				rate = (ie + oe) / pk * 100
			}
			s.Metrics = append(s.Metrics, model.Metric{Name: "errrate", Value: round4(math.Min(100, rate)), Unit: "%", Rule: model.RuleIfErrRate},
				model.Metric{Name: "errors", Value: ie + oe})
			if ie+oe > 0 {
				parts = append(parts, model.T("monitor64.txt.errors_n", "n", fmt.Sprintf("%.0f", ie+oe)))
			}
		}
		id, _, ok5 := c.delta(pre+"id", t.col(ifInDisc)[idx], r.at)
		od, _, ok6 := c.delta(pre+"od", t.col(ifOutDisc)[idx], r.at)
		if ok5 && ok6 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "drops", Value: id + od})
		}
		// Zustand
		switch {
		case admin == 2:
			parts = append([]string{model.T("monitor64.txt.disabled")}, parts...)
		case !up:
			parts = append([]string{"down"}, parts...)
			if admin == 1 && (oper == 2 || oper == 7) {
				s.Facts = append(s.Facts, model.Fact{Code: FactIfDown, Text: model.T("monitor64.txt.no_link", "name", in.name)})
			}
		}
		if up && speed > 0 {
			if mx := c.maxSpeed[key]; mx > 0 && speed < mx {
				s.Facts = append(s.Facts, model.Fact{Code: FactIfSpeedLow, Text: model.T("monitor64.txt.speed_instead", "now", speedText(speed), "max", speedText(mx))})
				parts = append(parts, model.T("monitor64.txt.slower", "v", speedText(mx)))
			}
			c.maxSpeed[key] = math.Max(c.maxSpeed[key], speed)
		}
		if d, ok := num(t.col(dot3Dup)[idx]); ok && d == 2 && up {
			s.Facts = append(s.Facts, model.Fact{Code: FactIfHalfDuplex, Text: model.T("monitor64.txt.half_duplex_name", "name", in.name)})
			parts = append(parts, model.T("monitor64.txt.half_duplex"))
		}
		s.Text = strings.Join(parts, " · ")
		if s.Text == "" {
			s.Text = "up"
		}
		r.out = append(r.out, s)
	}
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
