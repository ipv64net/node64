package healthchecks

import (
	"context"
	"strconv"

	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Prometheus-Kennzahlen der Docker-Hosts (Teil von GET /api/metrics, aufgerufen aus pveMetrics): eigene Reihen
// node64_docker_* (nicht node64_pve_* mit Label), damit bestehende Proxmox-Abfragen und Dashboards gleich bleiben.
// Je Host Erreichbarkeit und Abfragefehler, je Container Zustand und Werte (hoechstens pveMetricGuests Container).

func (m *Module) dockerMetrics(ctx context.Context, w *metrics.Writer, list []*proxmox.System) {
	n := 0
	for _, sys := range list {
		if !sys.IsDocker() {
			continue
		}
		sl := pveShortLabel(sys.Name)
		sid := strconv.FormatInt(sys.ID, 10)
		sysl := []string{"system", sl, "system_id", sid}
		row := m.pveSysView(ctx, sys)
		m.pve.mu.Lock()
		fails := m.pve.fails[sys.ID]
		m.pve.mu.Unlock()
		w.Counter("node64_docker_poll_failures_total", "Fehlgeschlagene Abfragen der Docker-API seit dem Start.", float64(fails), sysl...)
		w.Gauge("node64_docker_enabled", "Docker-Host wird ueberwacht (eingeschaltet).", metrics.Bool(sys.Enabled), sysl...)
		s := row.Snap
		if s == nil {
			continue
		}
		w.Gauge("node64_docker_up", "Docker-API erreichbar (1) oder nicht (0).", metrics.Bool(s.OK), sysl...)
		w.Gauge("node64_docker_last_poll_seconds", "Zeit der letzten Abfrage (Unix-Zeit).", float64(s.Time.Unix()), sysl...)
		if !s.OK {
			continue
		}
		w.Gauge("node64_docker_containers_running", "Laufende Container (ohne gestoerte und ausgeschlossene).", float64(row.Running), sysl...)
		w.Gauge("node64_docker_containers_bad", "Gestoerte Container (unhealthy, Neustart-Schleife, beendet obwohl erwartet …).", float64(row.Bad), sysl...)
		for i := range s.Resources {
			r := &s.Resources[i]
			if r.Type != proxmox.TypeDocker || n >= pveMetricGuests {
				continue
			}
			n++
			cl := []string{"system", sl, "system_id", sid, "name", pveShortLabel(r.Name)}
			w.Gauge("node64_docker_container_state", "Zustand des Containers (Wert immer 1, Zustand im Label state, Ursache im Label detail).", 1,
				append(cl[:len(cl):len(cl)], "state", string(r.State), "detail", r.Detail)...)
			w.Gauge("node64_docker_container_up", "Container laeuft (1) oder nicht (0).", metrics.Bool(r.Status == "running"), cl...)
			w.Gauge("node64_docker_container_restarts", "Neustarts durch Docker (RestartCount).", float64(r.Restarts), cl...)
			if !r.Measurable() {
				continue
			}
			mem, _ := r.MemPercent()
			w.Gauge("node64_docker_container_cpu_ratio", "CPU des Containers bezogen auf sein Limit bzw. alle Kerne des Hosts (0..1).", r.CPU, cl...)
			w.Gauge("node64_docker_container_cpus", "CPU-Limit des Containers bzw. Kerne des Hosts.", r.MaxCPU, cl...)
			w.Gauge("node64_docker_container_memory_ratio", "RAM des Containers bezogen auf sein Limit bzw. den RAM des Hosts (0..1).", mem/100, cl...)
			w.Gauge("node64_docker_container_memory_bytes", "RAM des Containers ohne inactive_file (wie docker stats).", float64(r.Mem), cl...)
			w.Gauge("node64_docker_container_memory_limit_bytes", "RAM-Limit des Containers bzw. RAM des Hosts.", float64(r.MaxMem), cl...)
			w.Gauge("node64_docker_container_uptime_seconds", "Laufzeit seit dem Start.", float64(r.Uptime), cl...)
			w.Gauge("node64_docker_container_net_in_bytes", "Netz eingehend (Byte/s, Mittel seit der letzten Abfrage).", r.NetIn, cl...)
			w.Gauge("node64_docker_container_net_out_bytes", "Netz ausgehend (Byte/s).", r.NetOut, cl...)
			w.Gauge("node64_docker_container_disk_read_bytes", "Block-I/O lesen (Byte/s).", r.DiskRead, cl...)
			w.Gauge("node64_docker_container_disk_write_bytes", "Block-I/O schreiben (Byte/s).", r.DiskWrite, cl...)
		}
	}
}
