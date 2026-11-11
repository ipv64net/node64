// Package model enthaelt die Typen, mit denen Sammler (Agent-Bericht, SSH, APIs, SNMP) Dienste und Messgroessen
// an den Kern von Monitor64 liefern (Plan docs/PLAN-NODE64-MONITOR64.md, "Kernmodell").
package model

// Arten der Messgroessen fuer die Schwellen (Schluessel der Standard-Schwellen, Paket eval).
const (
	RuleCPU       = "cpu.util"
	RuleLoad      = "load.core"
	RuleMem       = "mem.used"
	RuleGuestMem  = "guest.mem" // RAM einer VM aus Sicht des Hypervisors (mit Cache des Gastes)
	RuleSwap      = "swap.used"
	RuleFS        = "fs.used"
	RuleFSInodes  = "fs.inodes" // Inodes eines Dateisystems belegt in %
	RuleStore     = "store.used"
	RuleDiskTemp  = "disk.temp"
	RuleNVMeTemp  = "disk.temp_nvme"
	RuleWear      = "ssd.wear"
	RuleIfUtil    = "if.util"
	RuleIfErrRate = "if.errrate"
	RuleTemp      = "temp.system"
	// Geraete (SNMP, APIs)
	RulePrinterSupply = "printer.supply" // Toner/Tinte in % (Richtung unten)
	RuleUPSRuntime    = "ups.runtime"    // USV-Restlaufzeit in Sekunden (Richtung unten)
	RulePoEUsed       = "poe.used"       // PoE-Budget belegt in %
	RuleMailQueue     = "mail.queue"     // zurueckgestellte Mails in der Warteschlange
)

// Metric ist ein Messwert eines Dienstes.
type Metric struct {
	Name  string  `json:"name"`           // util, used, in, out, temp ...
	Value float64 `json:"value"`          //
	Unit  string  `json:"unit,omitempty"` // %, Mbit/s, °C, B, B/s
	Rule  string  `json:"rule,omitempty"` // Art fuer Schwellen (leer = nur Anzeige/Verlauf)
	Max   float64 `json:"max,omitempty"`  // z. B. Groesse in Bytes (fuer "GB frei")
}

// Fact ist ein Zustand ohne Zahl, den die festen Regeln bewerten (SMART FAILED, RAID degraded ...).
type Fact struct {
	Code string `json:"code"` // smart_failed, smart_sectors, smart_sectors_rising, raid_degraded, zfs_degraded,
	// bond_member_down, lacp_mismatch, updates_security, reboot_required, systemd_failed, local_warn, local_crit
	Text string `json:"text,omitempty"`
}

// Service ist ein Dienst mit seinen Messgroessen.
type Service struct {
	Key     string   `json:"key"`
	Name    string   `json:"name"`
	Kind    string   `json:"kind"`
	Metrics []Metric `json:"metrics,omitempty"`
	Facts   []Fact   `json:"facts,omitempty"`
	Text    string   `json:"text,omitempty"`
	// Default: beim Erkennen standardmaessig angeboten (false z. B. fuer Ports ohne Link, die noch nie verbunden waren)
	Default bool `json:"default"`
}
