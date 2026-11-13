package monitor64

import (
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/eval"
)

// Beschreibungen fuer die Oberflaeche: Arten der Schwellen (Standard-Tabelle), Kategorien der Dienste, Arten der
// Hosts im Assistenten. Texte stehen in den Sprachdateien unter monitor64.*.

// ruleKind beschreibt eine Art der Standard-Tabelle fuer die Oberflaeche.
type ruleKind struct {
	Kind   string  `json:"kind"`
	Group  string  `json:"group"`            // system, storage, disks, network, devices, fixed
	Unit   string  `json:"unit"`             // Anzeige-Einheit (%, °C, Tage, Min.)
	Factor float64 `json:"factor,omitempty"` // Anzeige = Wert / Factor (USV-Restlaufzeit: Sekunden -> Minuten)
	Store  bool    `json:"store,omitempty"`  // Fuellstand: auch "GB frei"
	State  bool    `json:"state,omitempty"`  // Zustandsregel (Kritisch/Warnung/nicht melden)
	Down   bool    `json:"down,omitempty"`   // Schwelle nach unten
	NoFor  bool    `json:"nofor,omitempty"`  // ohne Dauer (Trend)
}

// ruleKinds in der Reihenfolge der Seite Schwellen (wie im Entwurf).
var ruleKinds = []ruleKind{
	{Kind: eval.KindCPUUtil, Group: "system", Unit: "%"},
	{Kind: eval.KindLoadCore, Group: "system"},
	{Kind: eval.KindMemUsed, Group: "system", Unit: "%"},
	{Kind: eval.KindGuestMem, Group: "system", Unit: "%"},
	{Kind: eval.KindSwapUsed, Group: "system", Unit: "%"},
	{Kind: eval.KindTempSystem, Group: "system", Unit: "°C"},
	{Kind: eval.KindFSUsed, Group: "storage", Unit: "%", Store: true},
	{Kind: eval.KindFSInodes, Group: "storage", Unit: "%"},
	{Kind: eval.KindStoreUsed, Group: "storage", Unit: "%", Store: true},
	{Kind: eval.KindFSTrendDays, Group: "storage", Unit: "days", Down: true, NoFor: true},
	{Kind: eval.KindDiskTemp, Group: "disks", Unit: "°C"},
	{Kind: eval.KindDiskTempNVMe, Group: "disks", Unit: "°C"},
	{Kind: eval.KindSSDWear, Group: "disks", Unit: "%"},
	{Kind: eval.KindIfUtil, Group: "network", Unit: "%"},
	{Kind: eval.KindIfErrRate, Group: "network", Unit: "%"},
	{Kind: eval.KindPrinterSupply, Group: "devices", Unit: "%", Down: true},
	{Kind: eval.KindUPSRuntime, Group: "devices", Unit: "min", Factor: 60, Down: true},
	{Kind: eval.KindPoEUsed, Group: "devices", Unit: "%"},
	{Kind: eval.KindMailQueue, Group: "mail"},

	{Kind: eval.KindSmartFailed, Group: "fixed", State: true},
	{Kind: eval.KindSmartSectors, Group: "fixed", State: true},
	{Kind: eval.KindSmartSectorsUp, Group: "fixed", State: true},
	{Kind: eval.KindRAIDDegraded, Group: "fixed", State: true},
	{Kind: eval.KindBondMemberDown, Group: "fixed", State: true},
	{Kind: eval.KindBondLACP, Group: "fixed", State: true},
	{Kind: eval.KindUPSOnBattery, Group: "fixed", State: true},
	{Kind: eval.KindUpdatesSecurity, Group: "fixed", State: true},
	{Kind: eval.KindRebootRequired, Group: "fixed", State: true},
	{Kind: eval.KindGuestDown, Group: "fixed", State: true},
	{Kind: eval.KindSystemdFailed, Group: "fixed", State: true},
	{Kind: eval.KindWinSvcStopped, Group: "fixed", State: true},
	{Kind: eval.KindUPSLowBattery, Group: "fixed", State: true},
	{Kind: eval.KindUPSReplace, Group: "fixed", State: true},
	{Kind: eval.KindUPSOverload, Group: "fixed", State: true},
	{Kind: eval.KindDeviceWarn, Group: "fixed", State: true},
	{Kind: eval.KindDeviceCrit, Group: "fixed", State: true},
	{Kind: eval.KindParityErrors, Group: "fixed", State: true},
	{Kind: eval.KindHostRestarted, Group: "fixed", State: true},
	{Kind: eval.KindIfDown, Group: "fixed", State: true},
	{Kind: eval.KindIfSpeedLow, Group: "fixed", State: true},
	{Kind: eval.KindIfHalfDuplex, Group: "fixed", State: true},
	{Kind: eval.KindUPSAlarm, Group: "fixed", State: true},
	{Kind: eval.KindPrinterError, Group: "fixed", State: true},
	{Kind: eval.KindPaperEmpty, Group: "fixed", State: true},
	{Kind: eval.KindHWFailed, Group: "fixed", State: true},
	{Kind: eval.KindPoEFault, Group: "fixed", State: true},
	{Kind: eval.KindTrapReceived, Group: "fixed", State: true},
	{Kind: eval.KindServiceGone, Group: "fixed", State: true},
	{Kind: eval.KindAccessFailed, Group: "fixed", State: true},
	{Kind: eval.KindCtrUnhealthy, Group: "fixed", State: true},
	{Kind: eval.KindBackupOld, Group: "fixed", State: true},
	{Kind: eval.KindJobFailed, Group: "fixed", State: true},
	{Kind: eval.KindStoreInactive, Group: "fixed", State: true},
	{Kind: eval.KindClusterQuorum, Group: "fixed", State: true},
	{Kind: eval.KindClusterNodeDown, Group: "fixed", State: true},
	{Kind: eval.KindHAError, Group: "fixed", State: true},
	{Kind: eval.KindCephWarn, Group: "fixed", State: true},
	{Kind: eval.KindCephErr, Group: "fixed", State: true},
}

// coreTexts sind Texte, die der Kern als "i18n:<schluessel>?..." liefert (Ursache, Zugangsfehler, Ablauf eines
// Problems); das Skript uebersetzt sie mit diesen Schluesseln (unter monitor64.).
var coreTexts = []string{"detail.vanished", "detail.not_running", "detail.access", "detail.threshold", "detail.maint_silent", "detail.unack",
	"detail.secret_unreadable", "detail.no_data", "detail.host_removed", "detail.zfs_errors", "detail.push_waiting", "detail.hostkey_unconfirmed", "err.not_running", "detail.traps", "detail.trap_last",
	"detail.cluster_takeover", "detail.cluster_handover", "detail.handover",
	"detail.agent_updated", "agent.err_fallback", "agent.err_no_index", "agent.err_no_file"}

// ruleGroups ist die Reihenfolge der Abschnitte auf der Seite Schwellen.
var ruleGroups = []string{"system", "storage", "disks", "network", "devices", "mail"}

func ruleKindOf(kind string) (ruleKind, bool) {
	for _, k := range ruleKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return ruleKind{}, false
}

// kindKey ist der Teil des Sprachschluessels einer Art (Punkte sind in den Sprachdateien Ebenen).
func kindKey(kind string) string { return strings.ReplaceAll(kind, ".", "_") }

// svcCategory ordnet die Art eines Dienstes einer Kategorie der Dienste-Tabelle zu.
func svcCategory(kind string) string {
	switch kind {
	case "cpu", "load", "mem", "swap", "temp", "systemd", "updates", "reboot", "cluster", "ha", "ceph", "alerts", "system", "uptime", "traps":
		return "system"
	case "ups", "fan", "psu", "power", "printer", "supply", "tray", "hw":
		return "devices"
	case "mailq", "mail", "quarantine":
		return "mail"
	case "fs":
		return "fs"
	case "zfs", "btrfs", "raid", "store", "ds", "ctrl":
		return "storage"
	case "disk":
		return "disks"
	case "if", "bond", "poe", "wlan", "wan", "dsl", "routing":
		return "network"
	case "vm", "ct", "backup", "job":
		return "guests"
	case "ctr":
		return "docker"
	case "winsvc":
		return "winsvc"
	case "local":
		return "local"
	case "access":
		return "access"
	}
	return "other"
}

// svcCategories in der Reihenfolge der Dienste-Tabelle.
var svcCategories = []string{"system", "fs", "storage", "disks", "network", "devices", "mail", "guests", "docker", "winsvc", "local", "access", "other"}

// guestKind: Dienst mit Soll-Zustand (Proxmox-Gast, Docker-Container).
func guestKind(kind string) bool { return kind == "vm" || kind == "ct" || kind == "ctr" }

// hostKinds sind die Arten im Assistenten "Host hinzufuegen" (Reihenfolge wie im Entwurf). Access ist der Zugang,
// den der Assistent anlegt; Soon = noch nicht waehlbar.
type hostKind struct {
	Kind   string `json:"kind"`
	Icon   string `json:"icon"`
	Access string `json:"access"`
	Soon   bool   `json:"soon,omitempty"`
}

var hostKinds = []hostKind{
	{Kind: "linux-agent", Icon: "bi-ubuntu", Access: "agent"},
	{Kind: "windows", Icon: "bi-windows", Access: "agent"},
	{Kind: "freebsd", Icon: "bi-shield-check", Access: "agent"},
	{Kind: "raspberrypi", Icon: "bi-cpu", Access: "agent"},
	{Kind: "ssh", Icon: "bi-terminal", Access: "ssh"},
	{Kind: "pve", Icon: "bi-hdd-rack", Access: "pve"},
	{Kind: "pbs", Icon: "bi-archive", Access: "pbs"},
	{Kind: "pmg", Icon: "bi-envelope-check", Access: "pmg"},
	{Kind: "mailcow", Icon: "bi-mailbox", Access: "mailcow"},
	{Kind: "fritzbox", Icon: "bi-router", Access: "fritzbox"},
	{Kind: "mikrotik", Icon: "bi-hdd-network", Access: "mikrotik"},
	{Kind: "docker", Icon: "bi-box-seam", Access: "docker"},
	{Kind: "truenas", Icon: "bi-device-hdd", Access: "truenas"},
	{Kind: "unraid", Icon: "bi-hdd-stack", Access: "unraid"},
	{Kind: "server", Icon: "bi-motherboard", Access: "redfish"},
	{Kind: "ups", Icon: "bi-battery-charging", Access: "nut"},
	{Kind: "prom", Icon: "bi-graph-up", Access: "prom"},
	{Kind: "snmp", Icon: "bi-diagram-3", Access: "snmp"},
	{Kind: "nas", Icon: "bi-device-hdd", Access: "snmp"},
}

func hostKindOf(kind string) (hostKind, bool) {
	for _, k := range hostKinds {
		if k.Kind == kind {
			return k, true
		}
	}
	return hostKind{}, false
}

// hostIcon ist das Symbol eines Hosts nach seiner Art.
func hostIcon(kind string) string {
	if k, ok := hostKindOf(kind); ok {
		return k.Icon
	}
	return "bi-pc-display"
}

// accessTypes sind die Zugangsarten, die angelegt werden koennen.
var accessTypes = []string{"agent", "ssh", "pve", "pbs", "pmg", "mailcow", "fritzbox", "mikrotik", "docker", "prom", "nut", "truenas", "unraid", "redfish", "snmp"}

func validAccessType(t string) bool {
	for _, a := range accessTypes {
		if a == t {
			return true
		}
	}
	return false
}
