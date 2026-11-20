// Package proxmox fragt Proxmox-VE-Systeme (Einzel-Node oder Cluster), Proxmox Backup Server und Docker-Hosts ueber
// ihre API ab – nur lesend, Node64 aendert dort nichts. Das Paket kennt weder Oberflaeche noch Benachrichtigung; es
// liefert Clients, Abfragen und Typen fuer Monitor64, PROXY64 und DNS64. Die fruehere Einbindung in die Healthchecks
// (Datenhaltung, Regeln, Verlauf) gibt es seit Healthchecks 3.0.0 nicht mehr (nach Monitor64 umgezogen).
//
// Docker: ein Docker-Host ist ein System der Art KindDocker (docker.go), seine Container sind Gaeste vom Typ
// TypeDocker (Key docker/<name>).
//
// Proxmox Backup Server: ein System der Art KindPBS (pbs.go) mit genau einem Node und ohne Gaeste; seine Datastores
// stehen nur zur Anzeige im Snapshot (Snapshot.PBS).
package proxmox

import (
	"context"
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

// Typen wie in der API (qemu/lxc/node fuer Abfragen und Probe) und Container eines Docker-Hosts (Resource.Type).
const (
	TypeQEMU   = "qemu"
	TypeLXC    = "lxc"
	TypeNode   = "node"
	TypeDocker = "docker" // Container eines Docker-Hosts
)

// State ist der bewertete Zustand eines Containers (dockerState).
type State string

const (
	StateRunning State = "running"
	StateStopped State = "stopped"
	StatePaused  State = "paused"
	StateUnknown State = "unknown" // keine Daten
	StateError   State = "error"   // Stoerung, Grund im Feld Detail (dockerState)
)

// Resource ist ein Container eines Docker-Hosts in einem Snapshot (Type docker; die Felder VMID, Tags und Template
// stammen aus der Zeit der Proxmox-Gaeste und bleiben fuer Key und Excluded).
type Resource struct {
	Type     string   `json:"type"`           // docker
	Node     string   `json:"node"`           // Name des Docker-Hosts
	VMID     int      `json:"vmid,omitempty"` // Proxmox-Gaeste (nicht mehr belegt)
	Name     string   `json:"name"`
	State    State    `json:"state"`
	Status   string   `json:"status"`         // roh aus der API (running, exited …)
	Tags     []string `json:"tags,omitempty"` // Docker: Compose-Projekt
	Template bool     `json:"template,omitempty"`

	CPU    float64 `json:"cpu"` // Anteil 0..1 (bezogen auf MaxCPU)
	MaxCPU float64 `json:"max_cpu"`
	Mem    int64   `json:"mem"`
	MaxMem int64   `json:"max_mem"`
	Uptime int64   `json:"uptime"` // Sekunden

	// Raten seit der letzten Abfrage (Byte/s), aus den Zaehlern der API berechnet; 0 bei erster Abfrage.
	NetIn     float64 `json:"net_in"`
	NetOut    float64 `json:"net_out"`
	DiskRead  float64 `json:"disk_read"`
	DiskWrite float64 `json:"disk_write"`

	Restarted bool `json:"restarted,omitempty"` // uptime ist zurueckgesprungen, obwohl weiter laufend

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

// Snapshot ist der Stand eines Systems nach einer Abfrage.
type Snapshot struct {
	SystemID  int64       `json:"system_id"`
	Time      time.Time   `json:"time"`
	OK        bool        `json:"ok"`              // API erreichbar
	Error     string      `json:"error,omitempty"` // letzter Fehler (z. B. „401 token invalid“, „certificate mismatch“)
	Address   string      `json:"address"`         // zuletzt erfolgreich benutzte Adresse
	Version   string      `json:"version,omitempty"`
	Warning   string      `json:"warning,omitempty"` // erreichbar, aber eingeschraenkt (z. B. Token ohne Leserechte: Gaeste fehlen)
	Resources []Resource  `json:"resources"`
	Docker    *DockerInfo `json:"docker,omitempty"` // nur Docker-Host: /info
	// Interval ist das Abfrageintervall des Pollers: die Verzoegerung „nicht erreichbar“ zaehlt auch zeitlich
	// (schnelle Wiederholungen nach Fehlern verkuerzen sie nicht); nur von Run gesetzt, 0 = nur Abfragen zaehlen.
	Interval time.Duration `json:"-"`
}

// SnapshotFunc nimmt einen neuen Stand entgegen (DockerPoller).
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
	Datastores  int      `json:"datastores,omitempty"` // nur PBS
	CertSHA256  string   `json:"cert_sha256"`
	CertSubject string   `json:"cert_subject,omitempty"`
	CertTrusted bool     `json:"cert_trusted"`           // von der System-CA bestaetigt
	PermWarning string   `json:"perm_warning,omitempty"` // z. B. Token sieht keine Gaeste (Rechte fehlen)
	// NeedConfirm: Zertifikat nicht von der System-CA bestaetigt und kein Pin – nur der Fingerabdruck wurde gelesen,
	// das Token nicht gesendet. Nach der Bestaetigung erneut mit diesem Fingerabdruck als Pin testen.
	NeedConfirm bool `json:"need_confirm,omitempty"`
}

// TagNoMonitor schliesst einen Gast aus (Proxmox-Tag).
const TagNoMonitor = "nomonitor"
