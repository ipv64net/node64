// Package proxmox ueberwacht Proxmox-VE-Systeme (Einzel-Node oder Cluster) ueber die API – nur lesend, Node64 aendert
// in Proxmox nichts. Plan: docs/PLAN-NODE64-PROXMOX.md. Das Paket kennt weder Oberflaeche noch Benachrichtigung; die
// Einbindung (Healthchecks, Menue „Proxmox VE“) liegt in internal/healthchecks/proxmox_*.go.
//
// Diese Datei ist der Vertrag der parallelen Teile (client/poller, store/history/rules, Einbindung).
package proxmox

import (
	"context"
	"time"
)

// System ist ein eingerichtetes Proxmox-System (Einzel-Node oder Cluster).
type System struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`                 // Anzeigename (Standard: Clustername bzw. Node-Name)
	Addresses []string  `json:"addresses"`            // https://host:8006 – eine reicht, weitere Nodes kommen aus cluster/status
	TokenID   string    `json:"token_id"`             // user@realm!tokenid
	Secret    string    `json:"-"`                    // Token-Secret (verschluesselt gespeichert, nie ausgeben)
	PinSHA256 string    `json:"pin_sha256,omitempty"` // Fingerabdruck des Zertifikats (hex, ohne Doppelpunkte); leer = System-CA
	Interval  int       `json:"interval"`             // Sekunden fuer cluster/resources (15–300, Standard 30)
	Enabled   bool      `json:"enabled"`
	Created   time.Time `json:"created"`
}

// Guest-Typen und Node-Zustaende wie in der API.
const (
	TypeQEMU = "qemu"
	TypeLXC  = "lxc"
	TypeNode = "node"
)

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
}

// Key ist die stabile Kennung eines Nodes oder Gasts innerhalb eines Systems: "node/<name>" bzw. "qemu/<vmid>",
// "lxc/<vmid>" (Gaeste behalten ihre ID beim Umzug auf einen anderen Node).
func (r *Resource) Key() string {
	if r.Type == TypeNode {
		return "node/" + r.Node
	}
	return r.Type + "/" + itoa(r.VMID)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// Snapshot ist der Stand eines Systems nach einer Abfrage.
type Snapshot struct {
	SystemID  int64      `json:"system_id"`
	Time      time.Time  `json:"time"`
	OK        bool       `json:"ok"`              // API erreichbar
	Error     string     `json:"error,omitempty"` // letzter Fehler (z. B. „401 token invalid“, „certificate mismatch“)
	Address   string     `json:"address"`         // zuletzt erfolgreich benutzte Adresse
	Version   string     `json:"version,omitempty"`
	Cluster   string     `json:"cluster,omitempty"` // Clustername, leer bei Einzel-Node
	Quorate   *bool      `json:"quorate,omitempty"`
	Resources []Resource `json:"resources"`
}

// Poller fragt ein System regelmaessig ab (poller.go). Neue Snapshots gehen an OnSnapshot.
//
//	p := NewPoller(log, sys, onSnapshot)
//	p.Run(ctx)                 // bis ctx endet
//	p.Last() *Snapshot         // letzter Stand (nil vor der ersten Abfrage)
type SnapshotFunc func(ctx context.Context, s *Snapshot)

// Probe prueft eine Verbindung beim Anlegen (Assistent): liefert Version, Clustername, Nodes und den
// Fingerabdruck des Zertifikats (fuer die Bestaetigung), auch wenn das Zertifikat nicht vertrauenswuerdig ist.
type ProbeResult struct {
	OK          bool     `json:"ok"`
	Error       string   `json:"error,omitempty"`
	Version     string   `json:"version,omitempty"`
	Cluster     string   `json:"cluster,omitempty"`
	Nodes       []string `json:"nodes,omitempty"`
	Guests      int      `json:"guests"`
	CertSHA256  string   `json:"cert_sha256"`
	CertSubject string   `json:"cert_subject,omitempty"`
	CertTrusted bool     `json:"cert_trusted"`           // von der System-CA bestaetigt
	PermWarning string   `json:"perm_warning,omitempty"` // z. B. Token sieht keine Gaeste (Rechte fehlen)
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
	Text     string    `json:"text"` // kurzer Text (Sprache wie Anzeige)
}
