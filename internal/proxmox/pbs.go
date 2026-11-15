package proxmox

import (
	"context"
	"strings"
)

// Proxmox Backup Server als System (Kind pbs): derselbe Client (Token, Pin, Adressen; Port 8007, Kopf PBSAPIToken).
// Die regelmaessige Abfrage ist mit Monitor64 entfallen; hier bleibt die Probe beim Anlegen (Version, Erreichbarkeit).

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
