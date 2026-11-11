package proxmox

import (
	"strconv"
	"strings"
	"time"
)

// Abfrage eines Systems im Takt des Plans:
//   cluster/resources  alle sys.Interval Sekunden (Standard 30, 15–300) – ein Aufruf fuer Nodes und Gaeste
//   cluster/status     alle 60 s (Clustername, quorate, Nodes online/IP → gelernte Adressen); frueher, wenn
//                      cluster/resources einen Node anders sieht als der letzte Stand
//   version            beim Start und alle 10 min
//   certificates/info  je Node alle 10 min bzw. bei neuen Nodes, nur bei Systemen mit Pin: Fingerabdruck des
//                      Zertifikats, das der Node benutzt, als Pin fuer seine gelernte Adresse (Failover im Cluster)
//   qmpstatus          laufender VMs alle 2 min (hoechstens 4 gleichzeitig); VMs, deren letzter Wert nicht
//                      „running“ ist, bei jeder Abfrage neu (hoechstens pveQMPRecheck), damit ein alter Wert
//                      (angehalten, abgestuerzt) nach Fortsetzen bzw. Neustart nicht stehen bleibt
//   Adressen           laufender Gaeste mit Check (WantIP) je Gast alle 5 min, hoechstens 8 je Abfrage (2 gleichzeitig):
//                      QEMU agent/network-get-interfaces, LXC interfaces – fuer den Ping der Latenz (Check-Typ proxmox)
// Jede Abfrage ergibt einen Snapshot (auch bei Fehler: OK=false, Error, keine Resources) und geht an fn.

const (
	pveStatusEvery    = 60 * time.Second
	pveVersionEvery   = 10 * time.Minute
	pveCertsEvery     = 10 * time.Minute
	pveQMPEvery       = 2 * time.Minute
	pveQMPParallel    = 4
	pveBackoffStart   = 5 * time.Second
	pveQMPRequestWait = 30 * time.Second // alle qmpstatus-Anfragen einer Runde zusammen
	pveQMPRecheck     = 16               // VMs mit qmpstatus ungleich running je Abfrage neu fragen
	pveLockGrace      = 4 * time.Hour    // gestoppter Gast mit Lock (Backup im Stopp-Modus, Migration): so lange neutral
	pveIPEvery        = 5 * time.Minute  // Adresse eines Gasts so oft neu holen (auch nach Fehlern)
	pveIPWant         = 10 * time.Minute // Gast gilt als gewuenscht, solange sein Check so kuerzlich gefragt hat
	pveIPPerRound     = 8                // Adressen je Abfrage
	pveIPParallel     = 2
	pveIPRequestWait  = 8 * time.Second // alle Adress-Anfragen einer Runde zusammen
)

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
