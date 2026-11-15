package proxmox

import (
	"strconv"
	"strings"
	"time"
)

// pveBackoffStart: erste Wartezeit nach einem Fehler (DockerPoller). Die Proxmox- und PBS-Poller sind mit Monitor64
// entfallen; das Paket liefert nur noch Client, Probe und den Docker-Abfrager.
const pveBackoffStart = 5 * time.Second

// ClampInterval bringt ein Intervall in die Grenzen (0 = Standard).
func ClampInterval(sec int) time.Duration {
	switch {
	case sec <= 0:
		sec = DefaultInterval
	case sec < MinInterval:
		sec = MinInterval
	case sec > MaxInterval:
		sec = MaxInterval
	}
	return time.Duration(sec) * time.Second
}

// pveNum nimmt Zahlen auch als String oder null an (Proxmox ist da nicht immer gleich).
type pveNum float64

func (n *pveNum) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if s == "" || s == "null" {
		*n = 0
		return nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		*n = 0 // unbekannter Wert: lieber 0 als die ganze Abfrage verwerfen
		return nil
	}
	*n = pveNum(f)
	return nil
}

// pveResource ist ein Eintrag aus cluster/resources.
type pveResource struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Node      string `json:"node"`
	VMID      pveNum `json:"vmid"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Template  pveNum `json:"template"`
	Lock      string `json:"lock"`
	Tags      string `json:"tags"`
	HAState   string `json:"hastate"`
	Storage   string `json:"storage"`    // nur type storage
	Plugin    string `json:"plugintype"` // nur type storage
	Content   string `json:"content"`    // nur type storage
	Shared    pveNum `json:"shared"`     // nur type storage
	CPU       pveNum `json:"cpu"`
	MaxCPU    pveNum `json:"maxcpu"`
	Mem       pveNum `json:"mem"`
	MaxMem    pveNum `json:"maxmem"`
	Disk      pveNum `json:"disk"`
	MaxDisk   pveNum `json:"maxdisk"`
	Uptime    pveNum `json:"uptime"`
	NetIn     pveNum `json:"netin"`
	NetOut    pveNum `json:"netout"`
	DiskRead  pveNum `json:"diskread"`
	DiskWrite pveNum `json:"diskwrite"`
}

// pveStatusEntry ist ein Eintrag aus cluster/status (type cluster oder node).
type pveStatusEntry struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Online  pveNum `json:"online"`
	Quorate pveNum `json:"quorate"`
	Local   pveNum `json:"local"`
}

// pveVersion ist die Antwort von /version.
type pveVersion struct {
	Version string `json:"version"`
	Release string `json:"release"`
}

// parseStatus: Clustername, quorate (nil bei Einzel-Node), Nodes online, IPs der Nodes, die online sind.
func pveParseStatus(st []pveStatusEntry) (string, *bool, map[string]bool, []string) {
	cluster := ""
	var quorate *bool
	up := map[string]bool{}
	var ips []string
	for _, e := range st {
		switch e.Type {
		case "cluster":
			cluster = e.Name
			q := e.Quorate != 0
			quorate = &q
		case TypeNode:
			up[e.Name] = e.Online != 0
			if e.Online != 0 && e.IP != "" {
				ips = append(ips, e.IP)
			}
		}
	}
	return cluster, quorate, up, ips
}
