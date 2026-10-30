package checks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// Proxmox-Check: ein Gast (VM/Container) oder Node eines Proxmox-VE-Systems „auch als Check gefuehrt“. Der Check
// fragt Proxmox nicht selbst, sondern liest den letzten Stand der Abfrage des Systems (Healthchecks → Proxmox VE)
// ueber Runner.Proxmox – so haengt dieses Paket nicht von internal/proxmox ab. Bewertung:
//   running, backup, locked (Gast) bzw. online (Node)           -> up (gestoppt mit Lock nur eine Weile, danach stopped)
//   stopped / paused / suspended / error (Absturz)              -> down (pve_stopped, pve_paused, pve_suspended, pve_crashed)
//   Abfrage laeuft, aber noch kein Stand (Start, System gespeichert) -> voriges Ergebnis bleibt (hoechstens
//                                                                       ProxmoxPendingGrace), danach down
//   Node offline, Gast auf Node offline bzw. ohne Daten         -> down (pve_offline, pve_unknown)
//   Gast bzw. Node nicht mehr vorhanden                         -> down (pve_missing)
//   System nicht erreichbar, abgeschaltet, Stand zu alt         -> down (pve_unreachable)
// Laeuft ausschliesslich lokal auf der Node, die das System abfragt.

const TypeProxmox Type = "proxmox"

// ProxmoxPendingGrace: so lange nach dem Start der Abfrage gilt „noch kein Stand“ nicht als Stoerung.
const ProxmoxPendingGrace = 2 * time.Minute

const (
	ReasonPVEStopped     Reason = "pve_stopped"
	ReasonPVEPaused      Reason = "pve_paused"
	ReasonPVESuspended   Reason = "pve_suspended"
	ReasonPVECrashed     Reason = "pve_crashed"
	ReasonPVEOffline     Reason = "pve_offline"
	ReasonPVEUnknown     Reason = "pve_unknown"
	ReasonPVEMissing     Reason = "pve_missing"
	ReasonPVEUnreachable Reason = "pve_unreachable"
)

// ProxmoxParams sind die Parameter eines Proxmox-Checks.
type ProxmoxParams struct {
	SystemID int64  `json:"system_id"`
	Key      string `json:"key"`              // node/<name>, qemu/<vmid>, lxc/<vmid>
	System   string `json:"system,omitempty"` // nur Anzeige: Clustername bzw. Name des Systems (Gruppierung, auch im Portal)
	// Kennung des Systems im Cluster (32 hex): die ID ist je Node verschieden, gilt die Kennung, wenn gesetzt
	SystemUID string `json:"system_uid,omitempty"`
	// System von Hand gesetzt (Untergruppe im Check-Formular): die Node uebernimmt den Clusternamen nicht mehr
	SystemCustom bool `json:"system_custom,omitempty"`
}

// ProxmoxState ist der Stand eines Gasts bzw. Nodes aus der letzten Abfrage (geliefert von Runner.Proxmox).
type ProxmoxState struct {
	System    string    // Name des Systems
	Polling   bool      // das System wird abgefragt (eingerichtet, eingeschaltet, Secret lesbar)
	Reachable bool      // letzte Abfrage erfolgreich
	Error     string    // Fehler der letzten Abfrage bzw. warum nicht abgefragt wird
	Time      time.Time // Zeit der letzten Abfrage (Null = noch keine)
	Started   time.Time // Start der Abfrage (fuer „noch kein Stand“)
	Last      Status    // voriges Ergebnis des Checks (leer = keins), bleibt bis zum ersten Stand
	Interval  time.Duration
	Found     bool   // Gast bzw. Node in der letzten Abfrage enthalten
	Name      string // Anzeigename des Gasts bzw. Nodes
	Node      string
	State     string // running, stopped, paused, suspended, backup, locked, online, offline, unknown, error
	Status    string // roh aus der API
	QMP       string
	Lock      string
	Uptime    int64
	// Latenz (nur Anzeige): Adresse fuer den Ping (Node aus cluster/status, Gast ueber Gast-Agent bzw. LXC-
	// Schnittstellen; leer = keine) und Antwortzeit der letzten erfolgreichen Abfrage von cluster/resources (Rueckfall)
	IP         string
	APILatency time.Duration
}

var pveCheckKey = regexp.MustCompile(`^(node/[A-Za-z0-9._-]{1,64}|(qemu|lxc)/[1-9][0-9]{0,9})$`)

func validateProxmox(def Definition) error {
	var p ProxmoxParams
	if err := decode(def.Params, &p); err != nil {
		return err
	}
	if p.SystemID <= 0 {
		return errors.New("system_id is required (proxmox system)")
	}
	if !pveCheckKey.MatchString(p.Key) {
		return errors.New("key must look like node/<name>, qemu/<vmid> or lxc/<vmid>")
	}
	if p.SystemUID != "" && !pveUID.MatchString(p.SystemUID) {
		return errors.New("system_uid must be 32 hex characters")
	}
	return nil
}

var pveUID = regexp.MustCompile(`^[0-9a-f]{32}$`)

type proxmoxChecker struct{ r *Runner }

func (proxmoxChecker) Type() Type { return TypeProxmox }

func (c proxmoxChecker) Check(ctx context.Context, def Definition, _ net.IP) Result {
	var p ProxmoxParams
	_ = decode(def.Params, &p)
	res := Result{Details: map[string]any{"system_id": p.SystemID, "key": p.Key}}
	if c.r == nil || c.r.Proxmox == nil {
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, "proxmox monitoring is not running"
		return res
	}
	if p.SystemUID != "" && c.r.ProxmoxUID != nil {
		id, ok := c.r.ProxmoxUID(p.SystemUID)
		if !ok {
			res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, "proxmox system is not set up on this node (cluster: area Proxmox VE)"
			return res
		}
		p.SystemID = id
		res.Details["system_id"] = id
	}
	st := c.r.Proxmox(p.SystemID, p.Key)
	if st.System != "" {
		res.Details["system"] = st.System
	}
	now := time.Now()
	if c.r.Now != nil {
		now = c.r.Now()
	}
	stale := st.Interval > 0 && !st.Time.IsZero() && now.Sub(st.Time) > 3*st.Interval+time.Minute
	switch {
	case !st.Polling:
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, ifEmpty(st.Error, "proxmox system is not monitored")
		return res
	case st.Time.IsZero() && !st.Started.IsZero() && now.Sub(st.Started) < ProxmoxPendingGrace:
		// gerade gestartet: Zustand nicht aendern (sonst kurz down nach Neustart bzw. Speichern des Systems)
		res.Status, res.Reason, res.Message = Up, ReasonOK, "waiting for the first data from proxmox"
		if st.Last == Down {
			res.Status, res.Reason = Down, ReasonPVEUnreachable
		}
		return res
	case st.Time.IsZero():
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, "no data from proxmox yet"
		return res
	case stale:
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, "no current data from proxmox (last "+st.Time.UTC().Format(time.RFC3339)+")"
		return res
	case !st.Reachable:
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnreachable, "proxmox api not reachable"+ifNotEmpty(": ", st.Error)
		return res
	case !st.Found:
		res.Status, res.Reason, res.Message = Down, ReasonPVEMissing, p.Key+" not found on "+ifEmpty(st.System, "the proxmox system")
		return res
	}
	res.Details["state"], res.Details["status"], res.Details["node"] = st.State, st.Status, st.Node
	if st.Name != "" {
		res.Details["name"] = st.Name
	}
	if st.QMP != "" {
		res.Details["qmpstatus"] = st.QMP
	}
	if st.Lock != "" {
		res.Details["lock"] = st.Lock
	}
	up := ""
	if st.Uptime > 0 {
		up = ", up " + (time.Duration(st.Uptime) * time.Second).String()
	}
	where := ""
	if st.Node != "" && !strings.HasPrefix(p.Key, "node/") {
		where = " on " + st.Node
	}
	switch st.State {
	case "running", "online":
		res.Status, res.Reason, res.Message = Up, ReasonOK, st.State+where+up
	case "backup":
		res.Status, res.Reason, res.Message = Up, ReasonOK, "backup running"+ifNotEmpty(" (guest ", stoppedOnly(st.Status))+closeIf(stoppedOnly(st.Status))+where+up
	case "locked":
		res.Status, res.Reason, res.Message = Up, ReasonOK, fmt.Sprintf("locked (%s)%s%s", ifEmpty(st.Lock, "lock"), where, up)
	case "stopped":
		res.Status, res.Reason, res.Message = Down, ReasonPVEStopped, "stopped"+ifNotEmpty(" (lock ", st.Lock)+closeIf(st.Lock)+where
	case "paused":
		res.Status, res.Reason, res.Message = Down, ReasonPVEPaused, "paused"+where
	case "suspended":
		res.Status, res.Reason, res.Message = Down, ReasonPVESuspended, "suspended"+where
	case "error":
		res.Status, res.Reason, res.Message = Down, ReasonPVECrashed, "crashed"+ifNotEmpty(" (qmpstatus ", st.QMP)+ifNotEmpty("", closeIf(st.QMP))+where
	case "offline":
		res.Status, res.Reason, res.Message = Down, ReasonPVEOffline, "node offline"
	default:
		res.Status, res.Reason, res.Message = Down, ReasonPVEUnknown, "state unknown"+ifNotEmpty(" (node ", st.Node)+ifNotEmpty("", closeIf(st.Node))
	}
	// Latenz nur zur Anzeige (der Status bleibt der Stand aus Proxmox): Ping zur Adresse des Gasts bzw. Nodes, sonst
	// die Antwortzeit der API
	if st.APILatency > 0 {
		res.Latency, res.Details["latency_source"] = st.APILatency, "api"
	}
	if ip := net.ParseIP(st.IP); ip != nil && res.Status == Up {
		res.Details["ip"] = st.IP
		if d, ok := c.r.pingLatency(ctx, ip); ok {
			res.Latency, res.Details["latency_source"] = d, "ping"
		}
	}
	return res
}

func ifEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// stoppedOnly: Status nur nennen, wenn der Gast nicht laeuft (Backup im Stopp-Modus).
func stoppedOnly(status string) string {
	if status == "running" {
		return ""
	}
	return status
}

func closeIf(s string) string {
	if s == "" {
		return ""
	}
	return ")"
}
