// Package proxmox ueberwacht Proxmox-VE-Systeme (Einzel-Node oder Cluster) ueber die API – nur lesend, Node64 aendert
// in Proxmox nichts. Plan: docs/PLAN-NODE64-PROXMOX.md. Das Paket kennt weder Oberflaeche noch Benachrichtigung; die
// Einbindung (Healthchecks, Menue „Proxmox VE“) liegt in internal/healthchecks/proxmox_*.go.
//
// Diese Datei ist der Vertrag der parallelen Teile (client/poller, store/history/rules, Einbindung).
//
// Docker: ein Docker-Host ist ein System der Art KindDocker (docker.go), seine Container sind Gaeste vom Typ
// TypeDocker (Key docker/<name>). Regeln, Verlauf, Einstellungen und Benachrichtigung sind dieselben.
//
// Proxmox Backup Server: ein System der Art KindPBS (pbs.go) mit genau einem Node und ohne Gaeste; seine Datastores
// stehen nur zur Anzeige im Snapshot (Snapshot.PBS).
package proxmox

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

// Arten von Systemen (System.Kind).
const (
	KindPVE    = "pve"
	KindDocker = "docker"
	KindPBS    = "pbs"
)

// System ist ein eingerichtetes Proxmox-System (Einzel-Node oder Cluster) bzw. ein Docker-Host (Kind docker).
type System struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`                 // pve (Standard), docker oder pbs
	Name      string    `json:"name"`                 // Anzeigename (Standard: Clustername bzw. Node-Name)
	Addresses []string  `json:"addresses"`            // https://host:8006 – eine reicht, weitere Nodes kommen aus cluster/status; Docker: unix:///var/run/docker.sock
	TokenID   string    `json:"token_id"`             // user@realm!tokenid
	Secret    string    `json:"-"`                    // Token-Secret (verschluesselt gespeichert, nie ausgeben)
	PinSHA256 string    `json:"pin_sha256,omitempty"` // Fingerabdruck des Zertifikats (hex, ohne Doppelpunkte); leer = System-CA
	Interval  int       `json:"interval"`             // Sekunden fuer cluster/resources (15–300, Standard 30)
	Enabled   bool      `json:"enabled"`
	Created   time.Time `json:"created"`
	UID       string    `json:"uid"`            // Kennung im Cluster (32 hex, gleich auf allen Nodes)
	Home      string    `json:"home,omitempty"` // Node, die das System angelegt hat (Cluster); leer = diese Node
}

// Guest-Typen und Node-Zustaende wie in der API.
const (
	TypeQEMU   = "qemu"
	TypeLXC    = "lxc"
	TypeNode   = "node"
	TypeDocker = "docker" // Container eines Docker-Hosts
)

// IsDocker sagt, ob das System ein Docker-Host ist.
func (s *System) IsDocker() bool { return s != nil && s.Kind == KindDocker }

// State ist der bewertete Zustand (Anzeige und Regeln).
type State string

const (
	StateRunning   State = "running"
	StateStopped   State = "stopped"
	StatePaused    State = "paused"
	StateSuspended State = "suspended"
	StateBackup    State = "backup"  // lock=backup (laeuft weiter, Hinweis)
	StateLocked    State = "locked"  // anderer lock (migrate, snapshot, clone …) – Lock im Feld Lock
	StateOnline    State = "online"  // Node
	StateOffline   State = "offline" // Node
	StateUnknown   State = "unknown" // Node offline bzw. keine Daten
	StateError     State = "error"   // Absturz: qmpstatus internal-error, guest-panicked bzw. io-error (Gast „haengt“)
)

// Resource ist ein Node oder Gast in einem Snapshot.
type Resource struct {
	Type     string   `json:"type"`           // qemu, lxc, node
	Node     string   `json:"node"`           // Node-Name (bei Nodes = Name)
	VMID     int      `json:"vmid,omitempty"` // Gaeste
	Name     string   `json:"name"`
	State    State    `json:"state"`
	Status   string   `json:"status"`        // roh aus der API (running, stopped, online …)
	QMP      string   `json:"qmp,omitempty"` // qmpstatus bei laufenden VMs
	Lock     string   `json:"lock,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	HAState  string   `json:"ha_state,omitempty"`
	Template bool     `json:"template,omitempty"`

	CPU     float64 `json:"cpu"` // Anteil 0..1 (bezogen auf MaxCPU)
	MaxCPU  float64 `json:"max_cpu"`
	Mem     int64   `json:"mem"`
	MaxMem  int64   `json:"max_mem"`
	Disk    int64   `json:"disk"` // bei QEMU meist 0 (ohne Gast-Agent)
	MaxDisk int64   `json:"max_disk"`
	Uptime  int64   `json:"uptime"` // Sekunden

	// Raten seit der letzten Abfrage (Byte/s), aus den Zaehlern der API berechnet; 0 bei erster Abfrage.
	NetIn     float64 `json:"net_in"`
	NetOut    float64 `json:"net_out"`
	DiskRead  float64 `json:"disk_read"`
	DiskWrite float64 `json:"disk_write"`

	Restarted bool `json:"restarted,omitempty"` // uptime ist zurueckgesprungen, obwohl weiter laufend
	// AfterLock: die vorige Abfrage hatte einen Lock (Backup, Migration …) – ein jetzt laufender Gast kann noch der
	// fuers Backup gestartete sein und zaehlt noch nicht als „lief schon einmal“.
	AfterLock bool `json:"-"`

	// IP fuer den Ping der Latenz (Check-Typ proxmox): Node aus cluster/status, laufender Gast ueber den Gast-Agent
	// bzw. die LXC-Schnittstellen (nur Gaeste mit Check, siehe Poller.WantIP); leer = keine bekannt.
	IP string `json:"ip,omitempty"`

	// Nur Docker (Type docker): Key ist der Name (bleibt beim Neuanlegen), die ID wird mitgefuehrt.
	ContainerID string            `json:"container_id,omitempty"` // 12 Zeichen
	Image       string            `json:"image,omitempty"`
	Health      string            `json:"health,omitempty"` // healthy, unhealthy, starting ('' = ohne Healthcheck)
	Restarts    int               `json:"restart_count,omitempty"`
	ExitCode    int               `json:"exit_code,omitempty"`
	OOMKilled   bool              `json:"oom_killed,omitempty"`
	Created     int64             `json:"created,omitempty"` // Unix-Zeit
	Ports       []string          `json:"ports,omitempty"`   // z. B. 8080->80/tcp
	Labels      map[string]string `json:"labels,omitempty"`
	Detail      string            `json:"detail,omitempty"` // Docker-Stoerung: unhealthy, restarting, exited, oom, dead
}

// Key ist die stabile Kennung eines Nodes oder Gasts innerhalb eines Systems: "node/<name>" bzw. "qemu/<vmid>",
// "lxc/<vmid>" (Gaeste behalten ihre ID beim Umzug auf einen anderen Node).
func (r *Resource) Key() string {
	switch r.Type {
	case TypeNode:
		return "node/" + r.Node
	case TypeDocker:
		return TypeDocker + "/" + r.Name
	}
	return r.Type + "/" + strconv.Itoa(r.VMID)
}

// Excluded: Vorlage bzw. Tag nomonitor (Docker: Label node64.nomonitor=true) – keine Regeln, zaehlt nirgends als Gast.
func (r *Resource) Excluded() bool {
	if r.Template {
		return true
	}
	if r.Type == TypeDocker {
		switch strings.ToLower(strings.TrimSpace(r.Labels[LabelNoMonitor])) {
		case "true", "1", "yes", "on":
			return true
		}
		return false
	}
	for _, t := range r.Tags {
		if strings.EqualFold(strings.TrimSpace(t), TagNoMonitor) {
			return true
		}
	}
	return false
}

// Measurable: Werte sind aussagekraeftig (Node online, Gast laeuft – auch mit Lock).
func (r *Resource) Measurable() bool {
	if r.Type == TypeNode {
		return r.State == StateOnline
	}
	if r.Type == TypeDocker {
		return r.Status == "running" // auch unhealthy bzw. Neustart-Schleife: Werte sind echt
	}
	switch r.State {
	case StateRunning:
		return true
	case StateBackup, StateLocked:
		return r.Status == "running"
	}
	return false
}

// MemPercent liefert die RAM-Belegung in Prozent; ok = Maximum bekannt.
func (r *Resource) MemPercent() (float64, bool) {
	if r.MaxMem <= 0 {
		return 0, false
	}
	return float64(r.Mem) * 100 / float64(r.MaxMem), true
}

// PVEStorage ist ein Speicher aus cluster/resources (local, local-lvm, ZFS, NFS, Ceph …). Gemeinsame Speicher (shared)
// stehen nur einmal da (Node leer), lokale je Node.
type PVEStorage struct {
	Storage string `json:"storage"`
	Node    string `json:"node,omitempty"`
	Shared  bool   `json:"shared,omitempty"`
	Type    string `json:"type,omitempty"`    // plugintype: dir, lvmthin, zfspool, nfs, rbd …
	Content string `json:"content,omitempty"` // images,rootdir,iso …
	Status  string `json:"status,omitempty"`  // available, unknown …
	Total   int64  `json:"total"`
	Used    int64  `json:"used"`
}

// Key: gemeinsam nur der Name, lokal Node/Name (Event-ID und Regel-Stand je Speicher).
func (s PVEStorage) Key() string {
	if s.Shared || s.Node == "" {
		return s.Storage
	}
	return s.Node + "/" + s.Storage
}

// Available: der Speicher ist laut Proxmox verfuegbar (sonst keine Belegung).
func (s PVEStorage) Available() bool { return s.Status == "available" }

// UsedPercent: Belegung in Prozent; ok = verfuegbar und Groesse bekannt.
func (s PVEStorage) UsedPercent() (float64, bool) {
	if !s.Available() || s.Total <= 0 || s.Used < 0 {
		return 0, false
	}
	return float64(s.Used) * 100 / float64(s.Total), true
}

// DiskPercent liefert die Disk-Belegung in Prozent; ok = Wert vorhanden (bei QEMU nur mit Gast-Agent, sonst 0).
func (r *Resource) DiskPercent() (float64, bool) {
	if r.MaxDisk <= 0 || (r.Disk <= 0 && r.Type == TypeQEMU) {
		return 0, false
	}
	return float64(r.Disk) * 100 / float64(r.MaxDisk), true
}

// Snapshot ist der Stand eines Systems nach einer Abfrage.
type Snapshot struct {
	SystemID  int64        `json:"system_id"`
	Time      time.Time    `json:"time"`
	OK        bool         `json:"ok"`              // API erreichbar
	Error     string       `json:"error,omitempty"` // letzter Fehler (z. B. „401 token invalid“, „certificate mismatch“)
	Address   string       `json:"address"`         // zuletzt erfolgreich benutzte Adresse
	Version   string       `json:"version,omitempty"`
	Cluster   string       `json:"cluster,omitempty"` // Clustername, leer bei Einzel-Node
	Quorate   *bool        `json:"quorate,omitempty"`
	Warning   string       `json:"warning,omitempty"` // erreichbar, aber eingeschraenkt (z. B. Token ohne Leserechte: Gaeste fehlen)
	Resources []Resource   `json:"resources"`
	Docker    *DockerInfo  `json:"docker,omitempty"`   // nur Docker-Host: /info
	PBS       *PBSInfo     `json:"pbs,omitempty"`      // nur Proxmox Backup Server: Datastores
	Storages  []PVEStorage `json:"storages,omitempty"` // nur Proxmox VE: Speicher aus cluster/resources (nur Anzeige)
	// Interval ist das Abfrageintervall des Pollers: die Verzoegerung „nicht erreichbar“ zaehlt auch zeitlich
	// (schnelle Wiederholungen nach Fehlern verkuerzen sie nicht); nur von Run gesetzt, 0 = nur Abfragen zaehlen.
	Interval time.Duration `json:"-"`
	// APILatency ist die Antwortzeit der letzten erfolgreichen Abfrage von cluster/resources (Latenz der Checks ohne
	// Ping).
	APILatency time.Duration `json:"-"`
}

// Poller fragt ein System regelmaessig ab (poller.go). Neue Snapshots gehen an OnSnapshot.
//
//	p := NewPoller(log, sys, onSnapshot)
//	p.Run(ctx)                 // bis ctx endet
//	p.Last() *Snapshot         // letzter Stand (nil vor der ersten Abfrage)
type SnapshotFunc func(ctx context.Context, s *Snapshot)

// Source fragt ein System ab: Poller (Proxmox) bzw. DockerPoller (Docker-Host).
type Source interface {
	Run(ctx context.Context)
	Poll(ctx context.Context) *Snapshot
	Last() *Snapshot
}

// NewSource baut die Abfrage passend zur Art des Systems.
func NewSource(log *slog.Logger, sys System, fn SnapshotFunc) Source {
	if sys.IsDocker() {
		return NewDockerPoller(log, sys, fn)
	}
	if sys.IsPBS() {
		return NewPBSPoller(log, sys, fn)
	}
	return NewPoller(log, sys, fn)
}

// Probe prueft eine Verbindung beim Anlegen (Assistent): liefert Version, Clustername, Nodes und den
// Fingerabdruck des Zertifikats (fuer die Bestaetigung), auch wenn das Zertifikat nicht vertrauenswuerdig ist.
type ProbeResult struct {
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	Version     string   `json:"version,omitempty"`
	Cluster     string   `json:"cluster,omitempty"`
	Nodes       []string `json:"nodes,omitempty"`
	Guests      int      `json:"guests"`
	Datastores  int      `json:"datastores,omitempty"` // nur PBS
	CertSHA256  string   `json:"cert_sha256"`
	CertSubject string   `json:"cert_subject,omitempty"`
	CertTrusted bool     `json:"cert_trusted"`           // von der System-CA bestaetigt
	PermWarning string   `json:"perm_warning,omitempty"` // z. B. Token sieht keine Gaeste (Rechte fehlen)
	// NeedConfirm: Zertifikat nicht von der System-CA bestaetigt und kein Pin – nur der Fingerabdruck wurde gelesen,
	// das Token nicht gesendet. Nach der Bestaetigung erneut mit diesem Fingerabdruck als Pin testen.
	NeedConfirm bool `json:"need_confirm,omitempty"`
}

// Event ist ein Ergebnis der Regeln (rules.go) fuer die Benachrichtigung.
type Event struct {
	SystemID int64     `json:"system_id"`
	Key      string    `json:"key"` // Resource.Key() oder "" fuer das System selbst
	Name     string    `json:"name"`
	Kind     string    `json:"kind"` // down, up, threshold, threshold_ok, restarted
	What     string    `json:"what"` // z. B. stopped, paused, suspended, offline, unreachable, cpu, mem, disk
	Value    float64   `json:"value,omitempty"`
	Limit    float64   `json:"limit,omitempty"`
	Since    time.Time `json:"since"`
	Text     string    `json:"text"`             // kurzer Text (Sprache wie Anzeige)
	Detail   string    `json:"detail,omitempty"` // Zusatz, z. B. qmpstatus beim Absturz (fuer i18n-Text pve.ev.<Kind>.<What>)
}
