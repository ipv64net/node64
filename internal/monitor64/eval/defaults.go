package eval

import "time"

// Arten von Zahlenwerten (Standard-Schwellen, Plan "Standard-Schwellen"). Einheiten: %, °C, Sekunden, Tage.
const (
	KindCPUUtil       = "cpu.util"       // CPU-Auslastung in %
	KindLoadCore      = "load.core"      // Load je Kern
	KindMemUsed       = "mem.used"       // RAM belegt in %
	KindGuestMem      = "guest.mem"      // RAM einer VM aus Sicht des Hypervisors in % (zaehlt den Cache des Gastes mit)
	KindSwapUsed      = "swap.used"      // Swap belegt in %
	KindFSUsed        = "fs.used"        // Dateisystem belegt in % (oder GB frei)
	KindFSInodes      = "fs.inodes"      // Inodes eines Dateisystems belegt in %
	KindStoreUsed     = "store.used"     // Datastore/Pool belegt in % (oder GB frei)
	KindFSTrendDays   = "fs.trend_days"  // Trend: voll in N Tagen
	KindDiskTemp      = "disk.temp"      // Plattentemperatur in °C
	KindDiskTempNVMe  = "disk.temp_nvme" // NVMe-Temperatur in °C
	KindSSDWear       = "ssd.wear"       // SSD-Verschleiss in % verbraucht
	KindIfUtil        = "if.util"        // Port-Auslastung in % der Link-Geschwindigkeit
	KindIfErrRate     = "if.errrate"     // Port-Fehlerrate in % der Pakete
	KindPrinterSupply = "printer.supply" // Toner/Tinte in % (Richtung unten)
	KindUPSRuntime    = "ups.runtime"    // USV-Restlaufzeit in Sekunden (Richtung unten)
	KindPoEUsed       = "poe.used"       // PoE-Budget belegt in %
	KindMailQueue     = "mail.queue"     // zurueckgestellte Mails in der Warteschlange (Mail Gateway)
	KindTempSystem    = "temp.system"    // System-/CPU-Temperatur in °C
)

// Arten von Zustandsregeln (feste Regeln ohne Zahl; Wert 1 = Bedingung erfuellt).
const (
	KindSmartFailed     = "smart.failed"         // SMART-Gesamtstatus FAILED
	KindSmartSectors    = "smart.sectors"        // ausstehende/umgelegte Sektoren > 0
	KindSmartSectorsUp  = "smart.sectors_rising" // ausstehende Sektoren steigen
	KindRAIDDegraded    = "raid.degraded"        // RAID/ZFS degraded
	KindBondMemberDown  = "bond.member_down"     // Bond-Mitglied down
	KindBondLACP        = "bond.lacp_mismatch"   // LACP-Partner/Aggregator passt nicht
	KindUPSOnBattery    = "ups.on_battery"       // USV auf Batterie
	KindUpdatesSecurity = "updates.security"     // Sicherheitsupdates ausstehend
	KindRebootRequired  = "reboot.required"      // Neustart noetig
	KindFirmwareUpdate  = "firmware.update"      // Geraet: Firmware-Update verfuegbar (FRITZ!Box, MikroTik, UniFi)
	KindGuestDown       = "guest.down"           // Gast/Container laeuft nicht, obwohl er soll
	KindSystemdFailed   = "systemd.failed"       // fehlgeschlagene systemd-Dienste
	KindWinSvcStopped   = "winsvc.stopped"       // Windows-Dienst mit Starttyp Automatisch laeuft nicht
	KindUPSLowBattery   = "ups.low_battery"      // USV: Batterie schwach bzw. Zwangsabschaltung
	KindUPSReplace      = "ups.replace_battery"  // USV: Batterie ersetzen
	KindUPSOverload     = "ups.overload"         // USV: Ueberlast
	KindDeviceWarn      = "device.warn"          // Geraet meldet Warnung (Alarm, Health Warning)
	KindDeviceCrit      = "device.crit"          // Geraet meldet kritisch (Alarm, Health Critical)
	KindParityErrors    = "raid.parity_errors"   // Paritaetspruefung mit Fehlern (Unraid)
	KindHostRestarted   = "host.restarted"       // Geraet neu gestartet (SNMP: Laufzeit zurueckgesprungen)
	KindIfDown          = "if.down"              // Port ohne Link, obwohl eingeschaltet
	KindIfSpeedLow      = "if.speed_low"         // Port langsamer als zuvor
	KindIfHalfDuplex    = "if.half_duplex"       // Port im Halbduplex
	KindUPSAlarm        = "ups.alarm"            // USV meldet Alarm (UPS-MIB)
	KindPrinterError    = "printer.error"        // Druckerfehler (Stau, Klappe offen, offline ...)
	KindPaperEmpty      = "printer.paper_empty"  // Papierfach leer
	KindHWFailed        = "hw.failed"            // Hardware-Fehler (Luefter, Netzteil, Systemstatus)
	KindPoEFault        = "poe.fault"            // PoE-Port ueberlastet bzw. fehlerhaft
	KindTrapReceived    = "trap.received"        // SNMP-Trap empfangen (bis quittiert)
	KindServiceGone     = "svc.vanished"         // Dienst verschwunden (bleibt bis "Entfernen")
	KindAccessFailed    = "access.failed"        // einzelner Zugang antwortet nicht
	KindCtrUnhealthy    = "ctr.unhealthy"        // Container meldet unhealthy
	KindBackupOld       = "backup.old"           // letztes Backup einer Gruppe zu alt (PBS)
	KindJobFailed       = "job.failed"           // Verify/GC/Prune/Sync-Job fehlgeschlagen (PBS)
	KindStoreInactive   = "store.inactive"       // Speicher/Datastore nicht aktiv bzw. fehlerhaft
	KindClusterQuorum   = "cluster.no_quorum"    // Proxmox-Cluster ohne Quorum
	KindClusterNodeDown = "cluster.node_down"    // Node des Proxmox-Clusters offline
	KindHAError         = "ha.error"             // HA-Ressource im Fehlerzustand
	KindCephWarn        = "ceph.warn"            // Ceph HEALTH_WARN
	KindCephErr         = "ceph.err"             // Ceph HEALTH_ERR
)

// UnknownAfter: so viele Intervalle ohne Daten machen eine Messgroesse Unbekannt (wird wie Warnung gemeldet).
const UnknownAfter = 3

// DefaultHyst ist die Standard-Hysterese (2 Einheiten: 2 Prozentpunkte, 2 °C).
const DefaultHyst = 2.0

func num(warn, crit *Limit, dir Direction, dur time.Duration, hyst float64) Rule {
	return Rule{Warn: warn, Crit: crit, Dir: &dir, For: D(dur), Hyst: F(hyst)}
}

func stateRule(sev Severity, dur time.Duration) Rule {
	return Rule{Severity: &sev, For: D(dur)}
}

func fill(t Table) Table {
	// Felder, die in jeder Zeile gleich sind, setzen, damit Resolve immer vollstaendige Werte hat. Jede Zeile
	// bekommt eigene Zeiger: eine Aenderung an einer Art darf keine andere veraendern.
	for k, r := range t {
		if r.Mode == nil {
			r.Mode = new(ModeUsed)
		}
		if r.Report == nil {
			r.Report = new(ReportNotify)
		}
		if r.Severity == nil {
			if r.WarnFree == nil {
				r.WarnFree = LOff()
			}
			if r.CritFree == nil {
				r.CritFree = LOff()
			}
		}
		t[k] = r
	}
	return t
}

// Defaults liefert die Standard-Tabelle (angelehnt an CheckMK/Zabbix, entschieden 2026-11-09).
// Jeder Aufruf liefert eine neue Tabelle; Aenderungen daran wirken nicht zurueck.
func Defaults() Table {
	const m = time.Minute
	return fill(Table{
		KindFSUsed:        num(L(80), L(90), Up, 0, DefaultHyst),
		KindFSInodes:      num(L(80), L(90), Up, 0, DefaultHyst),
		KindStoreUsed:     num(L(80), L(90), Up, 0, DefaultHyst),
		KindFSTrendDays:   num(L(7), L(2), Down, 0, 1),
		KindMemUsed:       num(L(80), L(90), Up, 5*m, DefaultHyst),
		KindGuestMem:      num(LOff(), LOff(), Up, 5*m, DefaultHyst), // nur Anzeige: der Wert enthaelt den Cache des Gastes
		KindSwapUsed:      num(L(50), L(80), Up, 5*m, DefaultHyst),
		KindCPUUtil:       num(L(90), L(95), Up, 15*m, DefaultHyst),
		KindLoadCore:      num(L(2), L(4), Up, 15*m, 0.2),
		KindDiskTemp:      num(L(50), L(60), Up, 5*m, DefaultHyst),
		KindDiskTempNVMe:  num(L(70), L(80), Up, 5*m, DefaultHyst),
		KindSSDWear:       num(L(80), L(90), Up, 0, DefaultHyst),
		KindIfUtil:        num(L(80), L(90), Up, 5*m, DefaultHyst),
		KindIfErrRate:     num(L(0.01), L(0.1), Up, 5*m, 0.005),
		KindPrinterSupply: num(L(15), L(5), Down, 0, DefaultHyst),
		KindUPSRuntime:    num(LOff(), L(600), Down, 0, 60), // Warnung ist "auf Batterie" (ups.on_battery); bewertet nur auf Batterie (runner)
		KindPoEUsed:       num(L(85), L(95), Up, 5*m, DefaultHyst),
		KindMailQueue:     num(L(100), L(500), Up, 10*m, 10),
		KindTempSystem:    num(L(70), L(80), Up, 5*m, DefaultHyst),

		KindSmartFailed:     stateRule(SevCrit, 0),
		KindSmartSectors:    stateRule(SevWarn, 0),
		KindSmartSectorsUp:  stateRule(SevCrit, 0),
		KindRAIDDegraded:    stateRule(SevCrit, 0),
		KindBondMemberDown:  stateRule(SevWarn, 0),
		KindBondLACP:        stateRule(SevWarn, 0),
		KindUPSOnBattery:    stateRule(SevWarn, 0),
		KindUpdatesSecurity: stateRule(SevWarn, 24*time.Hour),
		KindRebootRequired:  stateRule(SevWarn, 24*time.Hour),
		// Firmware von Geraeten spielt sich nicht wie apt-Sicherheitsupdates von selbst ein: sofort melden
		KindFirmwareUpdate:  stateRule(SevWarn, 0),
		KindGuestDown:       stateRule(SevCrit, 0),
		KindSystemdFailed:   stateRule(SevWarn, 0),
		KindWinSvcStopped:   stateRule(SevWarn, 5*time.Minute),
		KindUPSLowBattery:   stateRule(SevCrit, 0),
		KindUPSReplace:      stateRule(SevWarn, 0),
		KindUPSOverload:     stateRule(SevWarn, 0),
		KindDeviceWarn:      stateRule(SevWarn, 0),
		KindDeviceCrit:      stateRule(SevCrit, 0),
		KindParityErrors:    stateRule(SevWarn, 0),
		KindHostRestarted:   stateRule(SevWarn, 0),
		KindIfDown:          stateRule(SevWarn, 0),
		KindIfSpeedLow:      stateRule(SevWarn, 0),
		KindIfHalfDuplex:    stateRule(SevWarn, 0),
		KindUPSAlarm:        stateRule(SevWarn, 0),
		KindPrinterError:    stateRule(SevWarn, 0),
		KindPaperEmpty:      stateRule(SevWarn, 0),
		KindHWFailed:        stateRule(SevCrit, 0),
		KindPoEFault:        stateRule(SevWarn, 0),
		KindTrapReceived:    stateRule(SevWarn, 0),
		KindServiceGone:     stateRule(SevWarn, 0),
		KindAccessFailed:    stateRule(SevWarn, 0),
		KindCtrUnhealthy:    stateRule(SevWarn, 0),
		KindBackupOld:       stateRule(SevWarn, 0),
		KindJobFailed:       stateRule(SevWarn, 0),
		KindStoreInactive:   stateRule(SevCrit, 0),
		KindClusterQuorum:   stateRule(SevCrit, 0),
		KindClusterNodeDown: stateRule(SevWarn, 0),
		KindHAError:         stateRule(SevWarn, 0),
		KindCephWarn:        stateRule(SevWarn, 0),
		KindCephErr:         stateRule(SevCrit, 0),
	})
}

// Bool wandelt eine Bedingung in den Messwert einer Zustandsregel (1 = erfuellt).
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
