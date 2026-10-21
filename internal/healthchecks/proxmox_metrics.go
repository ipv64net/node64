package healthchecks

import (
	"context"
	"strconv"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Prometheus-Kennzahlen der Proxmox-Ueberwachung (Teil von GET /api/metrics): je System Erreichbarkeit und
// Abfragefehler, je Node und Gast Zustand sowie CPU/RAM/Disk. Gaeste insgesamt hoechstens pveMetricGuests (Labels
// begrenzt), Namen gekuerzt.

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
	guests := 0
	for _, sys := range list {
		sl := pveShortLabel(sys.Name)
		row := m.pveSysView(ctx, sys)
		m.pve.mu.Lock()
		fails := m.pve.fails[sys.ID]
		m.pve.mu.Unlock()
		w.Counter("node64_pve_poll_failures_total", "Fehlgeschlagene Abfragen der Proxmox-API seit dem Start.", float64(fails), "system", sl)
		w.Gauge("node64_pve_enabled", "Proxmox-System wird ueberwacht (eingeschaltet).", metrics.Bool(sys.Enabled), "system", sl)
		if row.Error != "" {
			w.Gauge("node64_pve_error", "Letzte Abfrage fehlgeschlagen bzw. System nicht abfragbar (1).", 1, "system", sl)
		} else if sys.Enabled {
			w.Gauge("node64_pve_error", "Letzte Abfrage fehlgeschlagen bzw. System nicht abfragbar (1).", 0, "system", sl)
		}
		s := row.Snap
		if s == nil {
			continue
		}
		w.Gauge("node64_pve_up", "Proxmox-API erreichbar (1) oder nicht (0).", metrics.Bool(s.OK), "system", sl)
		w.Gauge("node64_pve_last_poll_seconds", "Zeit der letzten Abfrage (Unix-Zeit).", float64(s.Time.Unix()), "system", sl)
		if s.Quorate != nil {
			w.Gauge("node64_pve_quorate", "Cluster hat Quorum (1) oder nicht (0).", metrics.Bool(*s.Quorate), "system", sl)
		}
		if !s.OK {
			continue
		}
		w.Gauge("node64_pve_guests_running", "Laufende Gaeste (ohne Vorlagen).", float64(row.Running), "system", sl)
		w.Gauge("node64_pve_guests_bad", "Gestoerte Gaeste (gestoppt obwohl erwartet, angehalten, abgestuerzt).", float64(row.Bad), "system", sl)
		for _, res := range s.Resources {
			r := res
			cpu, mem, disk, hasDisk := r.CPU, 0.0, 0.0, false
			if r.MaxMem > 0 {
				mem = float64(r.Mem) / float64(r.MaxMem)
			}
			if r.MaxDisk > 0 && (r.Disk > 0 || r.Type != proxmox.TypeQEMU) {
				disk, hasDisk = float64(r.Disk)/float64(r.MaxDisk), true
			}
			measured := r.State == proxmox.StateOnline || r.Status == "running"
			if r.Type == proxmox.TypeNode {
				nl := []string{"system", sl, "node", pveShortLabel(r.Node)}
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
				"system", sl, "node", pveShortLabel(r.Node), "type", r.Type, "vmid", vmid, "name", pveShortLabel(r.Name), "state", string(r.State))
			gl := []string{"system", sl, "type", r.Type, "vmid", vmid}
			w.Gauge("node64_pve_guest_up", "Gast laeuft (1, auch mit Backup/Lock) oder nicht (0).", metrics.Bool(r.Status == "running"), gl...)
			if measured {
				w.Gauge("node64_pve_guest_cpu_ratio", "CPU-Auslastung des Gasts bezogen auf seine CPUs (0..1).", cpu, gl...)
				w.Gauge("node64_pve_guest_memory_ratio", "RAM-Belegung des Gasts (0..1).", mem, gl...)
				if hasDisk {
					w.Gauge("node64_pve_guest_disk_ratio", "Disk-Belegung des Gasts (0..1, bei VMs nur mit Gast-Agent).", disk, gl...)
				}
				w.Gauge("node64_pve_guest_uptime_seconds", "Laufzeit des Gasts.", float64(r.Uptime), gl...)
			}
		}
	}
}
