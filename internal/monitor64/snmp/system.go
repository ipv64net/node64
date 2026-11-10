package snmp

import (
	"errors"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// System-Gruppe (SNMPv2-MIB) und Laufzeit des Hosts (HOST-RESOURCES).
const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysUpTime   = ".1.3.6.1.2.1.1.3.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	oidHrUptime    = ".1.3.6.1.2.1.25.1.1.0" // Laufzeit des Hosts (sysUpTime ist die des SNMP-Dienstes)
)

// sysInfo ist die System-Gruppe einer Runde.
type sysInfo struct {
	descr, objectID, name string
	ticks                 uint64 // Laufzeit in 1/100 s
	source                string // "hr" (Host) oder "sys" (SNMP-Dienst)
	hasTicks              bool
}

// sysState merkt sich die Laufzeit zwischen Runden (Neustart erkennen).
type sysState struct {
	sysInfo
	uptime    time.Duration
	at        time.Time
	restartAt time.Time
	known     bool
}

// querySystem fragt die System-Gruppe ab; ohne Antwort ist der Zugang nicht erreichbar.
func (c *Collector) querySystem(r *round) (sysInfo, error) {
	res, err := getScalars(r.ctx, r.c, []string{oidSysDescr, oidSysObjectID, oidSysUpTime, oidSysName, oidHrUptime})
	if err != nil {
		return sysInfo{}, err
	}
	if len(res) == 0 {
		return sysInfo{}, errors.New(model.T("monitor64.txt.snmp_no_system"))
	}
	si := sysInfo{descr: text(res[oidSysDescr]), name: text(res[oidSysName])}
	if p, ok := res[oidSysObjectID]; ok {
		if s, ok := p.Value.(string); ok {
			si.objectID = normOID(s)
		}
	}
	if v, ok := u64(res[oidHrUptime]); ok {
		si.ticks, si.source, si.hasTicks = v, "hr", true
	} else if v, ok := u64(res[oidSysUpTime]); ok {
		si.ticks, si.source, si.hasTicks = v, "sys", true
	}
	c.detectRestart(si, r.now)
	return si, nil
}

// detectRestart erkennt einen Neustart: Laufzeit kleiner als zuvor (ohne 32-Bit-Ueberlauf nach 497 Tagen) oder
// kleiner als die Zeit seit der letzten Runde. Nach einem Neustart beginnen alle Zaehler von vorn.
func (c *Collector) detectRestart(si sysInfo, now time.Time) {
	prev := c.sys
	c.sys.sysInfo = si
	if !si.hasTicks {
		c.sys.known = false
		return
	}
	c.sys.uptime = time.Duration(si.ticks) * 10 * time.Millisecond
	c.sys.at = now
	c.sys.known = true
	if !prev.known || prev.source != si.source {
		return
	}
	elapsed := now.Sub(prev.at)
	if elapsed <= 0 {
		return
	}
	restarted := false
	switch {
	case si.ticks < prev.ticks:
		elapsedTicks := uint64(elapsed / (10 * time.Millisecond))
		wrapped := prev.ticks > (1<<32)-elapsedTicks-6000 // 32-Bit-TimeTicks laufen nach ~497 Tagen ueber
		restarted = !wrapped
	case c.sys.uptime+2*time.Minute < elapsed:
		restarted = true // Neustart waehrend einer langen Pause
	}
	if restarted {
		c.sys.restartAt = now
		c.counters = map[string]ctr{}
	}
}

// uptimeService: Dienst "Laufzeit" mit Fact restarted fuer DefaultRestartHold nach einem Neustart.
func (c *Collector) uptimeService(r *round) (model.Service, bool) {
	if !c.sys.known {
		return model.Service{}, false
	}
	s := model.Service{Key: "uptime", Name: model.T("monitor64.svc.uptime"), Kind: "uptime", Default: true,
		Metrics: []model.Metric{{Name: "uptime", Value: float64(int64(c.sys.uptime / time.Second)), Unit: "s"}},
		Text:    model.T("monitor64.txt.up_since", "d", model.Sub(durText(c.sys.uptime)))}
	if !c.sys.restartAt.IsZero() && r.now.Sub(c.sys.restartAt) < DefaultRestartHold {
		s.Facts = append(s.Facts, model.Fact{Code: FactRestarted, Text: model.T("monitor64.txt.restart_detected_up", "d", model.Sub(durText(c.sys.uptime)))})
		s.Text += " · " + model.T("monitor64.txt.restart_detected")
	}
	return s, true
}

// durText: "5 Min.", "3 Std.", "4 Tagen 2 Std." (uebersetzbar, als Parameter mit model.Sub).
func durText(d time.Duration) string {
	switch {
	case d < time.Hour:
		return model.T("monitor64.txt.dur_min", "n", int(d/time.Minute))
	case d < 48*time.Hour:
		return model.T("monitor64.txt.dur_h", "n", int(d/time.Hour))
	}
	days := int(d / (24 * time.Hour))
	h := int((d % (24 * time.Hour)) / time.Hour)
	if h == 0 {
		return model.T("monitor64.txt.since_days", "n", days)
	}
	return model.T("monitor64.txt.since_days_h", "n", days, "h", h)
}

// ctr ist ein Zaehlerstand der vorigen Runde.
type ctr struct {
	v    uint64
	t    time.Time
	wide bool // 64 Bit
}

// delta: Zuwachs seit der vorigen Runde und vergangene Sekunden. ok=false in der ersten Runde, nach einem Neustart
// bzw. Ruecksetzen des Zaehlers und bei Wechsel 32/64 Bit. Ein 32-Bit-Zaehler, der von oben nach unten springt,
// ist uebergelaufen (wird mitgerechnet); ein 64-Bit-Zaehler laeuft praktisch nie ueber.
func (c *Collector) delta(key string, p pdu, now time.Time) (d, dt float64, ok bool) {
	v, okv := u64(p)
	if !okv {
		return 0, 0, false
	}
	wide := is64(p)
	if !wide && v > 1<<32-1 {
		return 0, 0, false
	}
	prev, had := c.counters[key]
	c.counters[key] = ctr{v: v, t: now, wide: wide}
	if !had || prev.wide != wide {
		return 0, 0, false
	}
	dt = now.Sub(prev.t).Seconds()
	if dt <= 0 {
		return 0, 0, false
	}
	if v >= prev.v {
		return float64(v - prev.v), dt, true
	}
	if !wide && prev.v >= 1<<31 && v < 1<<31 {
		return float64(v + 1<<32 - prev.v), dt, true
	}
	return 0, 0, false
}

// rate: Zuwachs je Sekunde.
func (c *Collector) rate(key string, p pdu, now time.Time) (float64, bool) {
	d, dt, ok := c.delta(key, p, now)
	if !ok {
		return 0, false
	}
	return d / dt, true
}

// cleanCounters vergisst Zaehler, die lange nicht geliefert wurden (verschwundene Ports).
func (c *Collector) cleanCounters(now time.Time) {
	for k, v := range c.counters {
		if now.Sub(v.t) > counterTTL {
			delete(c.counters, k)
		}
	}
}
