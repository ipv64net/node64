package healthchecks

import (
	"context"
	"strconv"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Prometheus-Kennzahlen der Proxmox-Ueberwachung (Teil von GET /api/metrics): je System Erreichbarkeit und
// Abfragefehler, je Node und Gast Zustand sowie CPU/RAM/Disk. Gaeste insgesamt hoechstens pveMetricGuests (Labels
// begrenzt), Namen gekuerzt. Label system_id unterscheidet gleichnamige Systeme (Name ist nicht eindeutig).

const (
	pveMetricGuests = 1000
	pveMetricName   = 64
)

func pveShortLabel(s string) string {
	if r := []rune(s); len(r) > pveMetricName {
		return string(r[:pveMetricName])
	}
	return s
}

func (m *Module) pveMetrics(ctx context.Context, w *metrics.Writer) {
	list, err := m.pve.st.Systems(ctx)
	if err != nil || len(list) == 0 {
		return
	}
	m.dockerMetrics(ctx, w, list) // Docker-Hosts: node64_docker_* (docker_metrics.go)
	guests := 0
	for _, sys := range list {
		if sys.IsDocker() {
			continue // Docker-Hosts: node64_docker_* (docker_metrics.go)
		}
		sl := pveShortLabel(sys.Name)
		sid := strconv.FormatInt(sys.ID, 10)
		sysl := []string{"system", sl, "system_id", sid}
		row := m.pveSysView(ctx, sys)
		m.pve.mu.Lock()
		fails := m.pve.fails[sys.ID]
		m.pve.mu.Unlock()
		w.Counter("node64_pve_poll_failures_total", "Fehlgeschlagene Abfragen der Proxmox-API seit dem Start.", float64(fails), sysl...)
		w.Gauge("node64_pve_enabled", "Proxmox-System wird ueberwacht (eingeschaltet).", metrics.Bool(sys.Enabled), sysl...)
		if row.Error != "" {
			w.Gauge("node64_pve_error", "Letzte Abfrage fehlgeschlagen bzw. System nicht abfragbar (1).", 1, sysl...)
		} else if sys.Enabled {
			w.Gauge("node64_pve_error", "Letzte Abfrage fehlgeschlagen bzw. System nicht abfragbar (1).", 0, sysl...)
		}
		s := row.Snap
		if s == nil {
			continue
		}
		w.Gauge("node64_pve_up", "Proxmox-API erreichbar (1) oder nicht (0).", metrics.Bool(s.OK), sysl...)
		w.Gauge("node64_pve_last_poll_seconds", "Zeit der letzten Abfrage (Unix-Zeit).", float64(s.Time.Unix()), sysl...)
		if s.Quorate != nil {
			w.Gauge("node64_pve_quorate", "Cluster hat Quorum (1) oder nicht (0).", metrics.Bool(*s.Quorate), sysl...)
		}
		if !s.OK {
			continue
		}
		w.Gauge("node64_pve_guests_running", "Laufende Gaeste (ohne Vorlagen).", float64(row.Running), sysl...)
		w.Gauge("node64_pve_guests_bad", "Gestoerte Gaeste (gestoppt obwohl erwartet, angehalten, abgestuerzt).", float64(row.Bad), sysl...)
		for _, res := range s.Resources {
			r := res
			cpu := r.CPU
			mem, _ := r.MemPercent()
			disk, hasDisk := r.DiskPercent()
			mem, disk = mem/100, disk/100
			measured := r.Measurable() // wie Oberflaeche und Regeln
			if r.Type == proxmox.TypeNode {
				nl := []string{"system", sl, "system_id", sid, "node", pveShortLabel(r.Node)}
				w.Gauge("node64_pve_node_up", "Node online (1) oder nicht (0).", metrics.Bool(r.State == proxmox.StateOnline), nl...)
				if measured {
					w.Gauge("node64_pve_node_cpu_ratio", "CPU-Auslastung des Nodes (0..1).", cpu, nl...)
					w.Gauge("node64_pve_node_memory_ratio", "RAM-Belegung des Nodes (0..1).", mem, nl...)
					if hasDisk {
						w.Gauge("node64_pve_node_disk_ratio", "Belegung des Root-Dateisystems des Nodes (0..1).", disk, nl...)
					}
					w.Gauge("node64_pve_node_uptime_seconds", "Laufzeit des Nodes.", float64(r.Uptime), nl...)
				}
				continue
			}
			if r.Template || guests >= pveMetricGuests {
				continue
			}
			guests++
			vmid := strconv.Itoa(r.VMID)
			w.Gauge("node64_pve_guest_state", "Zustand des Gasts (Wert immer 1, Zustand im Label state).", 1,
				"system", sl, "system_id", sid, "node", pveShortLabel(r.Node), "type", r.Type, "vmid", vmid, "name", pveShortLabel(r.Name), "state", string(r.State))
			gl := []string{"system", sl, "system_id", sid, "type", r.Type, "vmid", vmid}
			w.Gauge("node64_pve_guest_up", "Gast laeuft (1, auch mit Backup/Lock) oder nicht (0).", metrics.Bool(r.Status == "running"), gl...)
			if measured {
				w.Gauge("node64_pve_guest_cpu_ratio", "CPU-Auslastung des Gasts bezogen auf seine CPUs (0..1).", cpu, gl...)
				w.Gauge("node64_pve_guest_memory_ratio", "RAM-Belegung des Gasts (0..1).", mem, gl...)
				if hasDisk {
					w.Gauge("node64_pve_guest_disk_ratio", "Disk-Belegung des Gasts (0..1, bei VMs nur mit Gast-Agent).", disk, gl...)
				}
				w.Gauge("node64_pve_guest_uptime_seconds", "Laufzeit des Gasts.", float64(r.Uptime), gl...)
				w.Gauge("node64_pve_guest_net_in_bytes", "Netz eingehend des Gasts (Byte/s, Mittel seit der letzten Abfrage).", r.NetIn, gl...)
				w.Gauge("node64_pve_guest_net_out_bytes", "Netz ausgehend des Gasts (Byte/s).", r.NetOut, gl...)
				w.Gauge("node64_pve_guest_disk_read_bytes", "Disk lesen des Gasts (Byte/s).", r.DiskRead, gl...)
				w.Gauge("node64_pve_guest_disk_write_bytes", "Disk schreiben des Gasts (Byte/s).", r.DiskWrite, gl...)
				w.Gauge("node64_pve_guest_memory_bytes", "RAM-Belegung des Gasts (Byte).", float64(r.Mem), gl...)
				w.Gauge("node64_pve_guest_cpus", "Zugewiesene CPUs des Gasts.", r.MaxCPU, gl...)
			}
		}
	}
}
