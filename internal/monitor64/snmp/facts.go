package snmp

import (
	"fmt"
	"math"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Neue Fact-Codes des SNMP-Sammlers (Zuordnung zu Zustandsregeln im Kern: factKind in internal/monitor64/runner.go).
const (
	FactRestarted     = "restarted"           // Geraet neu gestartet (Laufzeit zurueckgesprungen), steht DefaultRestartHold lang
	FactIfDown        = "if_down"             // Port ohne Link, obwohl eingeschaltet (ifAdminStatus up, ifOperStatus down)
	FactIfSpeedLow    = "if_speed_low"        // Port verbunden, aber langsamer als zuvor gesehen
	FactIfHalfDuplex  = "if_half_duplex"      // Port im Halbduplex
	FactUPSBatteryLow = "ups_low_battery"     // USV-Batterie schwach bzw. erschoepft (gleicher Code wie NUT)
	FactUPSReplace    = "ups_replace_battery" // USV-Batterie tauschen (gleicher Code wie NUT)
	FactUPSAlarm      = "ups_alarm"           // USV meldet Alarm (Ueberlast, Fehler, Bypass ...)
	FactPrinterError  = "printer_error"       // Drucker: kein Papier, Stau, Klappe offen, offline, Wartung
	FactPaperEmpty    = "paper_empty"         // Papierfach leer
	FactHWFailed      = "hw_failed"           // Hardware-Fehler (Luefter, Netzteil, Systemstatus)
	FactPoEFault      = "poe_fault"           // PoE-Port ueberlastet bzw. fehlerhaft
)

// Fact-Codes, die schon im Kern bekannt sind (Mapper, API-Sammler).
const (
	factUPSOnBattery  = "ups_on_battery"
	factBondDown      = "bond_member_down"
	factLACPMismatch  = "lacp_mismatch"
	factSmartFailed   = "smart_failed"
	factSmartSectors  = "smart_sectors"
	factRAIDDegraded  = "raid_degraded"
	factZFSDegraded   = "zfs_degraded"
	factStoreInactive = "store_inactive"
)

// knownFacts: Fact-Codes, die Profile verwenden duerfen.
var knownFacts = map[string]bool{
	factSmartFailed: true, factSmartSectors: true, factRAIDDegraded: true, factZFSDegraded: true, factBondDown: true,
	factLACPMismatch: true, "updates_security": true, "reboot_required": true, factUPSOnBattery: true, factStoreInactive: true,
	FactRestarted: true, FactIfDown: true, FactIfSpeedLow: true, FactIfHalfDuplex: true, FactUPSBatteryLow: true,
	FactUPSReplace: true, FactUPSAlarm: true, FactPrinterError: true, FactPaperEmpty: true, FactHWFailed: true, FactPoEFault: true,
}

// Regel-Arten fuer Zahlenwerte (Schluessel der Standard-Schwellen, Paket eval; im Test gegen eval.Defaults geprueft).
const (
	RulePrinterSupply = model.RulePrinterSupply
	RuleUPSRuntime    = model.RuleUPSRuntime
	RulePoEUsed       = model.RulePoEUsed
)

var knownRules = map[string]bool{
	"cpu.util": true, "load.core": true, "mem.used": true, "swap.used": true, "fs.used": true, "store.used": true,
	"disk.temp": true, "disk.temp_nvme": true, "ssd.wear": true, "if.util": true, "if.errrate": true,
	RulePrinterSupply: true, RuleUPSRuntime: true, RulePoEUsed: true, "temp.system": true,
}

func validRule(r string) bool { return knownRules[r] }

// Einheiten (wie im Mapper; Anzeige rechnet um).
var knownUnits = map[string]bool{
	"": true, "%": true, "°C": true, "B": true, "B/s": true, "Mbit/s": true, "s": true, "V": true, "A": true, "W": true,
	"VA": true, "rpm": true, "Hz": true, "dBm": true,
}

func validUnit(u string) bool { return knownUnits[u] }

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func round2(v float64) float64 { return math.Round(v*100) / 100 }
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

func pct(part, total float64) float64 {
	if total <= 0 {
		return 0
	}
	return round2(math.Max(0, math.Min(100, part/total*100)))
}

// bytesText formatiert Bytes (1000er-Einheiten wie im Mapper).
func bytesText(v float64) string {
	if v < 0 || !finite(v) {
		v = 0
	}
	f := v
	for _, u := range []string{"B", "KB", "MB", "GB", "TB", "PB"} {
		if f < 1000 || u == "PB" {
			if u == "B" {
				return fmt.Sprintf("%.0f B", f)
			}
			return strings.Replace(fmt.Sprintf("%.1f %s", f, u), ".", ",", 1)
		}
		f /= 1000
	}
	return ""
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

func speedText(mbit float64) string {
	m := int64(mbit)
	if m >= 1000 && m%1000 == 0 {
		return fmt.Sprintf("%d Gbit/s", m/1000)
	}
	if m >= 1000 {
		return strings.Replace(fmt.Sprintf("%.1f Gbit/s", mbit/1000), ".", ",", 1)
	}
	return fmt.Sprintf("%d Mbit/s", m)
}

// valueText: Messwert mit Einheit fuer den Dienst-Text.
func valueText(v float64, unit string) string {
	switch unit {
	case "B":
		return bytesText(v)
	case "B/s":
		return bytesText(v) + "/s"
	case "Mbit/s":
		return mbitText(v)
	case "s":
		return durTextSec(v)
	}
	s := strings.Replace(strings.TrimRight(strings.TrimRight(fmt.Sprintf("%.2f", v), "0"), "."), ".", ",", 1)
	if unit == "" {
		return s
	}
	return s + " " + unit
}

func durTextSec(v float64) string {
	switch {
	case v < 120:
		return fmt.Sprintf("%.0f s", v)
	case v < 7200:
		return fmt.Sprintf("%.0f Min.", v/60)
	}
	return fmt.Sprintf("%.0f Std.", v/3600)
}

func limitList(l []string, n int) []string {
	if len(l) <= n {
		return l
	}
	return append(append([]string{}, l[:n]...), fmt.Sprintf("+%d", len(l)-n))
}
