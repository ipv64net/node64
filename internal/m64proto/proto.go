// Package m64proto ist das Datenformat zwischen Monitor64-Agent (bzw. SSH-Abfrage ohne Agent) und Node64
// (Plan docs/PLAN-NODE64-MONITOR64.md, Abschnitt "Monitor64-Agent").
//
// Regeln:
//   - Zaehler werden roh geliefert (Bytes, Pakete, Jiffies); Raten rechnet die Node aus zwei Berichten.
//   - Unbekannte Felder werden ignoriert (encoding/json ohne DisallowUnknownFields), damit alte Agents zu neuen
//     Nodes passen und umgekehrt. Neue Felder nur anhaengen, nie umdeuten.
//   - Alles, was ein Host liefert, ist nicht vertrauenswuerdig: die Node prueft Groessen (MaxReportBytes) und
//     escaped Texte bei der Ausgabe.
package m64proto

// Version des Formats. Steigt nur bei inkompatiblen Aenderungen (bisher keine).
const Version = 1

// Anfragen an den Agent (SSH "exec"-Anfrage; alles andere lehnt der Agent ab).
const (
	ReqInfo    = "info"    // Info als JSON; optional "info latest=<version>": die Node nennt die verfuegbare Version
	ReqCollect = "collect" // Report als JSON; optional Abschnitte: "collect cpu,mem,fs"
	ReqUpdate  = "update"  // stdin: signierte neue Datei (UpdateHeader + Binary), Antwort UpdateResult
	ReqKeys    = "keys"    // stdin: neue Schluesselliste (authorized_keys-Format), Antwort KeysResult
)

// Grenzen (Node und Agent pruefen sie).
const (
	MaxReportBytes = 4 << 20   // Antwort auf collect bzw. Ausgabe der SSH-Abfrage
	MaxInfoBytes   = 64 << 10  // Antwort auf info
	MaxUpdateBytes = 64 << 20  // Datei fuer update
	MaxKeysBytes   = 64 << 10  // Schluesselliste
	DefaultPort    = 6465      // Standard-Port des Agents (TCP)
	SlowSmartSec   = 30 * 60   // SMART hoechstens alle 30 min neu lesen (Agent puffert)
	SlowUpdatesSec = 60 * 60   // Paket-Updates hoechstens stuendlich
	LocalTimeoutMs = 30 * 1000 // eigene Skripte: Zeitlimit je Skript
	LocalMaxBytes  = 64 << 10  // eigene Skripte: Ausgabe je Skript
)

// Abschnitte von collect (leer = alle).
const (
	SecCPU     = "cpu"
	SecMem     = "mem"
	SecLoad    = "load"
	SecFS      = "fs"
	SecDisk    = "disk"
	SecNet     = "net"
	SecBond    = "bond"
	SecSmart   = "smart"
	SecRAID    = "raid"
	SecZFS     = "zfs"
	SecTemp    = "temp"
	SecSystemd = "systemd"
	SecUpdates = "updates"
	SecReboot  = "reboot"
	SecLocal   = "local"
	SecWinSvc  = "winsvc" // Windows (Phase 2)
)

// Info beschreibt Agent und Host (Antwort auf "info").
type Info struct {
	V        int      `json:"v"`
	Agent    string   `json:"agent"`              // "monitor64-agent"
	Version  string   `json:"version"`            // SemVer des Agents
	OS       string   `json:"os"`                 // linux, windows, freebsd
	Arch     string   `json:"arch"`               // amd64, arm64, arm
	Hostname string   `json:"hostname"`           //
	Platform string   `json:"platform,omitempty"` // z. B. "Debian GNU/Linux 12 (bookworm)", "Windows 11 Pro"
	Kernel   string   `json:"kernel,omitempty"`   //
	Caps     []string `json:"caps,omitempty"`     // verfuegbare Abschnitte (z. B. smart nur mit smartctl)
	BootTime int64    `json:"boot,omitempty"`     // Unix-Sekunden
}

// Report ist die Antwort auf "collect" (bzw. das Ergebnis der SSH-Abfrage ohne Agent).
type Report struct {
	V      int     `json:"v"`
	Time   int64   `json:"t"`                // Unix-Millisekunden (Uhr des Hosts; nur fuer Raten zwischen zwei Berichten)
	Uptime float64 `json:"uptime,omitempty"` // Sekunden

	CPU     *CPU          `json:"cpu,omitempty"`
	Mem     *Mem          `json:"mem,omitempty"`
	Load    *Load         `json:"load,omitempty"`
	FS      []FS          `json:"fs,omitempty"`
	Disks   []DiskIO      `json:"disk,omitempty"`
	Net     []NetIf       `json:"net,omitempty"`
	Bonds   []Bond        `json:"bond,omitempty"`
	SMART   []SMART       `json:"smart,omitempty"`
	RAID    []RAID        `json:"raid,omitempty"`
	ZFS     []ZPool       `json:"zfs,omitempty"`
	Btrfs   []Btrfs       `json:"btrfs,omitempty"` // gehoert zum Abschnitt raid
	Temps   []Temp        `json:"temp,omitempty"`
	Power   *Power        `json:"power,omitempty"` // Raspberry Pi (gehoert zum Abschnitt temp)
	Systemd *Systemd      `json:"systemd,omitempty"`
	Updates *Updates      `json:"updates,omitempty"`
	Reboot  *Reboot       `json:"reboot,omitempty"`
	Local   []LocalCheck  `json:"local,omitempty"`
	WinSvc  []WinService  `json:"winsvc,omitempty"`
	Errors  []SectionErr  `json:"errors,omitempty"` // Abschnitte, die nicht gelesen werden konnten (Grund fuer "Unbekannt")
	Notes   []SectionNote `json:"notes,omitempty"`  // Hinweise ohne Fehler (z. B. "smartctl fehlt")

	localized bool // Errors/Notes sind schon Texte fuer die Anzeige (Localize)
}

// CPU: Summen-Zaehler aus /proc/stat (Jiffies, USER_HZ); Auslastung rechnet die Node aus zwei Berichten.
type CPU struct {
	Cores   int    `json:"cores"`
	User    uint64 `json:"user"`
	Nice    uint64 `json:"nice"`
	System  uint64 `json:"system"`
	Idle    uint64 `json:"idle"`
	IOWait  uint64 `json:"iowait"`
	IRQ     uint64 `json:"irq"`
	SoftIRQ uint64 `json:"softirq"`
	Steal   uint64 `json:"steal"`
	// Util: fertige Auslastung in Prozent, wenn der Host keine Zaehler hat (Windows, SNMP); sonst 0 und nil.
	Util *float64 `json:"util,omitempty"`
}

// Mem in Bytes.
type Mem struct {
	Total     uint64 `json:"total"`
	Available uint64 `json:"avail"`
	SwapTotal uint64 `json:"swap_total"`
	SwapFree  uint64 `json:"swap_free"`
}

// Load: Durchschnittslast 1/5/15 min.
type Load struct {
	L1  float64 `json:"l1"`
	L5  float64 `json:"l5"`
	L15 float64 `json:"l15"`
}

// FS ist ein Dateisystem bzw. Laufwerk (Bytes). Pseudo-Dateisysteme liefert der Agent nicht.
type FS struct {
	Mount       string `json:"mount"` // "/", "/var/lib/vz", "C:"
	Device      string `json:"dev,omitempty"`
	Type        string `json:"type,omitempty"`
	Total       uint64 `json:"total"`
	Used        uint64 `json:"used"`
	Avail       uint64 `json:"avail"` // fuer Nicht-root nutzbar
	InodesTotal uint64 `json:"inodes,omitempty"`
	InodesFree  uint64 `json:"inodes_free,omitempty"`
	ReadOnly    bool   `json:"ro,omitempty"`
}

// DiskIO: Zaehler aus /proc/diskstats (nur ganze Platten, keine Partitionen).
type DiskIO struct {
	Name       string `json:"name"`             // sda, nvme0n1
	Serial     string `json:"serial,omitempty"` // fuer stabile Zuordnung
	Model      string `json:"model,omitempty"`
	ReadBytes  uint64 `json:"rb"`
	WriteBytes uint64 `json:"wb"`
	ReadOps    uint64 `json:"ro"`
	WriteOps   uint64 `json:"wo"`
	IOTimeMs   uint64 `json:"io_ms"`
	Rotational *bool  `json:"rot,omitempty"`
}

// NetIf: Zaehler und Zustand je Netzwerkschnittstelle.
type NetIf struct {
	Name      string `json:"name"`
	Kind      string `json:"kind,omitempty"`   // physical, bond, bridge, vlan, virtual
	Master    string `json:"master,omitempty"` // Bond/Bridge, zu dem sie gehoert
	Up        bool   `json:"up"`               // Link (operstate up)
	SpeedMbit int    `json:"speed,omitempty"`  // 0 = unbekannt
	Duplex    string `json:"duplex,omitempty"`
	MAC       string `json:"mac,omitempty"`
	MTU       int    `json:"mtu,omitempty"`
	RxBytes   uint64 `json:"rxb"`
	TxBytes   uint64 `json:"txb"`
	RxPackets uint64 `json:"rxp"`
	TxPackets uint64 `json:"txp"`
	RxErrors  uint64 `json:"rxe"`
	TxErrors  uint64 `json:"txe"`
	RxDropped uint64 `json:"rxd"`
	TxDropped uint64 `json:"txd"`
	RxCRC     uint64 `json:"crc,omitempty"` // rx_crc_errors, falls vorhanden
}

// Bond (Linux /proc/net/bonding, Switch per SNMP LAG-MIB).
type Bond struct {
	Name        string      `json:"name"`
	Mode        string      `json:"mode"`              // z. B. "IEEE 802.3ad Dynamic link aggregation"
	MII         string      `json:"mii"`               // up/down
	AggregateID int         `json:"agg,omitempty"`     // 802.3ad: aktiver Aggregator
	PartnerMAC  string      `json:"partner,omitempty"` // 802.3ad
	Members     []BondSlave `json:"members"`
}

// BondSlave ist ein Mitglied eines Bonds.
type BondSlave struct {
	Name         string `json:"name"`
	MII          string `json:"mii"`
	SpeedMbit    int    `json:"speed,omitempty"`
	AggregateID  int    `json:"agg,omitempty"`
	LinkFailures int    `json:"failures,omitempty"`
}

// SMART einer Platte (Linux smartctl -j, Windows Storage-Zuverlaessigkeit, Proxmox-API).
type SMART struct {
	Device          string   `json:"dev"`            // /dev/sda
	Type            string   `json:"type,omitempty"` // ata, nvme, scsi
	Model           string   `json:"model,omitempty"`
	Serial          string   `json:"serial,omitempty"` // Schluessel des Dienstes
	CapacityBytes   uint64   `json:"cap,omitempty"`
	Passed          *bool    `json:"passed,omitempty"` // Gesamtstatus
	TempC           *float64 `json:"temp,omitempty"`
	PowerOnHours    *uint64  `json:"poh,omitempty"`
	Reallocated     *uint64  `json:"realloc,omitempty"`
	Pending         *uint64  `json:"pending,omitempty"`
	Uncorrectable   *uint64  `json:"uncorr,omitempty"`
	CRCErrors       *uint64  `json:"crc,omitempty"`
	WearPercentUsed *float64 `json:"wear,omitempty"`      // SSD/NVMe: verbraucht in %
	MediaErrors     *uint64  `json:"media_err,omitempty"` // NVMe
	CriticalWarning *uint64  `json:"crit_warn,omitempty"` // NVMe (Bitfeld)
	Error           string   `json:"error,omitempty"`     // Platte nicht lesbar (z. B. USB-Bridge ohne SMART)
}

// RAID ist ein mdraid-Verbund (bzw. Synology/QNAP per SNMP).
type RAID struct {
	Name        string   `json:"name"` // md0
	Level       string   `json:"level,omitempty"`
	State       string   `json:"state"` // clean, active, degraded, resyncing, recovering, failed
	Devices     int      `json:"devices"`
	Active      int      `json:"active"`
	Failed      int      `json:"failed,omitempty"`
	Spare       int      `json:"spare,omitempty"`
	SyncPercent *float64 `json:"sync,omitempty"`
	Members     []string `json:"members,omitempty"`
}

// ZPool ist ein ZFS-Pool.
type ZPool struct {
	Name     string  `json:"name"`
	Health   string  `json:"health"` // ONLINE, DEGRADED, FAULTED, ...
	Size     uint64  `json:"size"`
	Alloc    uint64  `json:"alloc"`
	Free     uint64  `json:"free"`
	FragPct  float64 `json:"frag,omitempty"`
	Errors   string  `json:"errors,omitempty"` // "No known data errors" bzw. Kurztext
	ScanText string  `json:"scan,omitempty"`   // letzter Scrub
}

// Btrfs ist ein eingehaengtes btrfs-Dateisystem (aus /sys/fs/btrfs): Geraete, fehlende Geraete, Summe der
// Fehlerzaehler aller Geraete (wie "btrfs device stats") und die Belegung der zugeteilten Daten- und Metadaten-Bloecke.
type Btrfs struct {
	UUID      string `json:"uuid"`
	Label     string `json:"label,omitempty"`
	Profile   string `json:"profile,omitempty"` // Profil der Daten: single, dup, raid1, raid10 ...
	Devices   int    `json:"devices"`
	Missing   int    `json:"missing,omitempty"`
	Errors    uint64 `json:"errors,omitempty"`
	DataTotal uint64 `json:"data_total,omitempty"`
	DataUsed  uint64 `json:"data_used,omitempty"`
	MetaTotal uint64 `json:"meta_total,omitempty"`
	MetaUsed  uint64 `json:"meta_used,omitempty"`
}

// Temp ist ein Temperatursensor (hwmon, thermal_zone; Pi: cpu-thermal).
type Temp struct {
	Name  string   `json:"name"` // stabiler Schluessel, z. B. "coretemp/Package id 0"
	Label string   `json:"label,omitempty"`
	C     float64  `json:"c"`
	High  *float64 `json:"high,omitempty"`
	Crit  *float64 `json:"crit,omitempty"`
}

// Power: Stromversorgung eines Raspberry Pi. Flags wie "vcgencmd get_throttled": die unteren Bits gelten jetzt, die
// oberen "seit dem Start aufgetreten".
type Power struct {
	Flags uint32 `json:"flags"`
}

const (
	PowerUnderVolt  uint32 = 1 << 0 // Unterspannung
	PowerFreqCapped uint32 = 1 << 1 // Takt begrenzt
	PowerThrottled  uint32 = 1 << 2 // gedrosselt
	PowerSoftTemp   uint32 = 1 << 3 // weiche Temperaturgrenze
	PowerSeenShift         = 16     // dieselben Bits um 16 nach oben: seit dem Start aufgetreten
)

// Systemd: fehlgeschlagene Units.
type Systemd struct {
	Failed []string `json:"failed"`
	State  string   `json:"state,omitempty"` // systemctl is-system-running: running, degraded, ...
}

// Updates: ausstehende Paket-Updates.
type Updates struct {
	Manager  string `json:"mgr"` // apt, dnf, zypper, pacman, apk, windows
	Pending  int    `json:"pending"`
	Security int    `json:"security"`
	Checked  int64  `json:"checked,omitempty"` // Unix-Sekunden der letzten Pruefung
}

// Reboot: Neustart noetig (Linux /var/run/reboot-required, needs-restarting, Windows).
type Reboot struct {
	Required bool     `json:"required"`
	Packages []string `json:"pkgs,omitempty"`
}

// LocalCheck ist eine Zeile eines eigenen Skripts im Format der CheckMK-"local checks":
// <Status> <Name> <Metriken> <Text>; Status 0..3 oder "P" (Zustand aus den Metriken).
type LocalCheck struct {
	Name    string   `json:"name"`
	State   int      `json:"state"` // 0 OK, 1 Warnung, 2 Kritisch, 3 Unbekannt; "P" wertet der Agent selbst aus (-1 nur von aelteren Quellen)
	Text    string   `json:"text,omitempty"`
	Metrics []Metric `json:"metrics,omitempty"`
	Script  string   `json:"script,omitempty"` // Dateiname
}

// Metric ist ein Messwert eines eigenen Skripts (name=value;warn;crit;min;max).
type Metric struct {
	Name  string   `json:"name"`
	Value float64  `json:"value"`
	Warn  *float64 `json:"warn,omitempty"`
	Crit  *float64 `json:"crit,omitempty"`
	Min   *float64 `json:"min,omitempty"`
	Max   *float64 `json:"max,omitempty"`
}

// WinService ist ein Windows-Dienst (Phase 2).
type WinService struct {
	Name      string `json:"name"`
	Display   string `json:"display,omitempty"`
	State     string `json:"state"` // running, stopped, ...
	StartType string `json:"start"` // auto, manual, disabled
}

// SectionErr: ein Abschnitt konnte nicht gelesen werden.
type SectionErr struct {
	Section string `json:"sec"`
	Error   string `json:"err"`
}

// SectionNote: Hinweis zu einem Abschnitt (kein Fehler), z. B. "smartctl fehlt".
type SectionNote struct {
	Section string `json:"sec"`
	Note    string `json:"note"`
}

// UpdateHeader steht vor der neuen Datei bei "update" (eine JSON-Zeile, dann die Datei).
type UpdateHeader struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`    // hex
	Signature string `json:"signature"` // base64 ed25519 ueber SignedMessage(...)
}

// SignedMessage ist der signierte Inhalt eines Updates: Version, Plattform und Pruefsumme.
func SignedMessage(version, os, arch, sha256hex string) []byte {
	return []byte("monitor64-agent\n" + version + "\n" + os + "/" + arch + "\n" + sha256hex + "\n")
}

// UpdateResult ist die Antwort auf "update".
type UpdateResult struct {
	OK      bool   `json:"ok"`
	Version string `json:"version,omitempty"` // neue Version (Neustart folgt)
	Error   string `json:"error,omitempty"`
}

// KeysResult ist die Antwort auf "keys".
type KeysResult struct {
	OK    bool   `json:"ok"`
	Count int    `json:"count,omitempty"`
	Error string `json:"error,omitempty"`
}
