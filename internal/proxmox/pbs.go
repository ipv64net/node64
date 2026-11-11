package proxmox

import (
	"context"
	"strings"
	"time"
)

// Proxmox Backup Server als System (Kind pbs): derselbe Client (Token, Pin, Adressen; Port 8007, Kopf PBSAPIToken)
// und dieselbe Weiterverarbeitung (Regeln, Verlauf, Check-Typ proxmox) wie bei Proxmox VE. Ein PBS hat keine Gaeste,
// er ist ein Node (Key node/localhost wie in der PBS-API – den Hostnamen liefert die API mit der Rolle Audit nicht;
// angezeigt wird der Name des Systems) mit CPU, RAM, Root-Disk, Netz und Disk-I/O; dazu Datastores, Backups, Dienste
// und fehlgeschlagene Tasks nur zur Anzeige – keine Regeln und keine Checks dafuer.
// Alles liest die Rolle Audit auf „/“ (Sys.Audit, Datastore.Audit). Je Abfrage (sys.Interval):
//   /nodes/localhost/status    CPU, RAM, Root-Disk, Uptime
//   /nodes/localhost/rrd       letzter Wert der Stunde: netin/netout, read_bytes/write_bytes (Byte/s)
//   /nodes/localhost/services  Dienste proxmox-backup und proxmox-backup-proxy (nur Anzeige)
//   /status/datastore-usage    Datastores (Groesse, Belegung, geschaetzt voll, Dedup aus gc-status)
// Beim Start und alle 10 min (pbsSlowEvery):
//   /version, /nodes/localhost/apt/update (verfuegbare Version von proxmox-backup-server fuer das Badge),
//   je Datastore /admin/datastore/{store}/namespace und /groups?ns= (Gruppen, Snapshots, letztes Backup – die Backups
//   liegen meist in Namespaces), /nodes/localhost/tasks?errors=1 (fehlgeschlagene Tasks der letzten 7 Tage)

const ()

// PBSInfo ist der Teil eines Snapshots, den nur ein PBS hat (alles nur Anzeige).
type PBSInfo struct {
	Datastores []PBSDatastore `json:"datastores"`
	Services   []PBSService   `json:"services,omitempty"`
	// Update: verfuegbare Version von proxmox-backup-server laut apt ("" = keine); UpdateOK = apt/update gelesen
	Update   string    `json:"update,omitempty"`
	UpdateOK bool      `json:"update_checked,omitempty"`
	Failed   []PBSTask `json:"failed_tasks"` // fehlgeschlagene Tasks der letzten 7 Tage (neueste zuerst)
}

// PBSService ist ein Dienst aus /nodes/localhost/services.
type PBSService struct {
	Name  string `json:"name"`
	State string `json:"state"` // running, dead …
}

// PBSTask ist ein Task aus /nodes/localhost/tasks.
type PBSTask struct {
	Type   string `json:"type"` // backup, garbage_collection, verify, prune …
	ID     string `json:"id,omitempty"`
	Start  int64  `json:"start"`
	End    int64  `json:"end,omitempty"`
	Status string `json:"status"`
}

// StartTime ist der Start des Tasks.
func (t PBSTask) StartTime() time.Time { return time.Unix(t.Start, 0) }

// ServicesDown: Dienste aus pbsServices, die nicht laufen (nur gelesene).
func (p *PBSInfo) ServicesDown() []string {
	if p == nil {
		return nil
	}
	var out []string
	for _, s := range p.Services {
		if s.State != "running" {
			out = append(out, s.Name)
		}
	}
	return out
}

// PBSDatastore ist ein Datastore aus /status/datastore-usage.
type PBSDatastore struct {
	Store   string  `json:"store"`
	Total   int64   `json:"total"`
	Used    int64   `json:"used"`
	Avail   int64   `json:"avail"`
	Full    int64   `json:"estimated_full,omitempty"` // Unix-Zeit „geschaetzt voll“ (0 = keine Schaetzung)
	Error   string  `json:"error,omitempty"`
	Mount   string  `json:"mount_status,omitempty"` // mounted, notmounted, nonremovable
	Backend string  `json:"backend,omitempty"`      // filesystem, s3
	Dedup   float64 `json:"dedup,omitempty"`        // Dedup-Faktor der letzten Garbage Collection (logisch / auf Disk)
	// aus den Gruppen aller Namespaces (alle 10 min; Known = gelesen)
	Known      bool  `json:"backups_known,omitempty"`
	Groups     int   `json:"groups,omitempty"`
	Snapshots  int   `json:"snapshots,omitempty"`
	LastBackup int64 `json:"last_backup,omitempty"` // Unix-Zeit
}

// UsedPercent: Belegung in Prozent; ok = Groesse bekannt.
func (d PBSDatastore) UsedPercent() (float64, bool) {
	if d.Total <= 0 || d.Used < 0 {
		return 0, false
	}
	return float64(d.Used) * 100 / float64(d.Total), true
}

// FullTime: Zeitpunkt „geschaetzt voll“; ok = in der Zukunft (eine Schaetzung in der Vergangenheit heisst laut API:
// Belegung sinkt oder bleibt gleich).
func (d PBSDatastore) FullTime(now time.Time) (time.Time, bool) {
	if d.Full <= 0 {
		return time.Time{}, false
	}
	t := time.Unix(d.Full, 0)
	return t, t.After(now)
}

// IsPBS sagt, ob das System ein Proxmox Backup Server ist.
func (s *System) IsPBS() bool { return s != nil && s.Kind == KindPBS }

// pbsNodeStatus ist die Antwort von /nodes/localhost/status.
type pbsNodeStatus struct {
	CPU     pveNum `json:"cpu"`
	CPUInfo struct {
		CPUs pveNum `json:"cpus"`
	} `json:"cpuinfo"`
	Memory struct {
		Total pveNum `json:"total"`
		Used  pveNum `json:"used"`
	} `json:"memory"`
	Root struct {
		Total pveNum `json:"total"`
		Used  pveNum `json:"used"`
	} `json:"root"`
	Uptime pveNum `json:"uptime"`
}

// pbsUsage ist ein Eintrag aus /status/datastore-usage (history laesst Node64 weg).
type pbsUsage struct {
	Store   string `json:"store"`
	Total   pveNum `json:"total"`
	Used    pveNum `json:"used"`
	Avail   pveNum `json:"avail"`
	Full    pveNum `json:"estimated-full-date"`
	Error   string `json:"error"`
	Mount   string `json:"mount-status"`
	Backend string `json:"backend-type"`
	GC      struct {
		Disk  pveNum `json:"disk-bytes"`
		Index pveNum `json:"index-data-bytes"`
	} `json:"gc-status"`
}

// pbsVersionText: "4.2" + Release "6" -> "4.2.6" (wie die Paketversion von proxmox-backup-server).
func pbsVersionText(v pveVersion) string {
	ver, rel := strings.TrimSpace(v.Version), strings.TrimSpace(v.Release)
	if ver != "" && rel != "" && strings.Count(ver, ".") == 1 && strings.Trim(rel, "0123456789") == "" {
		return ver + "." + rel
	}
	return ver
}

// pbsProbe ergaenzt den Test im Assistenten (nach Zertifikat und Token wie bei Proxmox VE): Version, Host-Status und
// Zahl der sichtbaren Datastores.
func pbsProbe(ctx context.Context, c *Client, sys System, res *ProbeResult) {
	var v pveVersion
	if err := c.Get(ctx, "/version", &v); err != nil {
		res.Error = err.Error()
		return
	}
	res.OK, res.Version = true, pbsVersionText(v)
	var warn []string
	var st pbsNodeStatus
	if err := c.Get(ctx, "/nodes/localhost/status", &st); err != nil {
		warn = append(warn, "the token may not read the host status (Sys.Audit on /system/status)")
	}
	var use []pbsUsage
	if err := c.Get(ctx, "/status/datastore-usage", &use); err != nil {
		warn = append(warn, "datastore-usage failed: "+err.Error())
	} else if res.Datastores = len(use); res.Datastores == 0 {
		warn = append(warn, "the token sees no datastores (fine if there are none)")
	}
	if len(warn) > 0 {
		res.PermWarning = strings.Join(warn, "; ") + " – grant role Audit on path / to the token (Configuration → Access Control → " +
			"Permissions → Add → API Token Permission, or: proxmox-backup-manager acl update / Audit --auth-id '" + sys.TokenID + "')"
	}
}
