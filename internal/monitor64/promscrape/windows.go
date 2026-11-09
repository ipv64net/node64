package promscrape

import (
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// windows_exporter -> derselbe Bericht wie beim Windows-Agent: CPU (Zaehler), RAM/Auslagerung, Laufwerke ("C:"),
// physische Platten (I/O), Netzwerkkarten, Windows-Dienste (Abschnitt winsvc). Unterstuetzt die aktuellen Namen
// (ab 0.30: windows_cpu_time_seconds_total, windows_memory_*, windows_pagefile_*, Label "service") und die aelteren
// (windows_cpu_time_total, windows_cs_*, windows_os_*, Label "name").

var driveRE = regexp.MustCompile(`^[A-Za-z]:$`)

// Teile von Kartennamen virtueller Schnittstellen (Beschreibung des Adapters, Klammern als [ ]).
var winVirtual = []string{"virtual", "miniport", "isatap", "teredo", "loopback", "tap-windows", "wireguard", "tailscale",
	"zerotier", "kernel debug", "pseudo", "6to4", "ip-https"}

// winIO haelt je Platte die zuletzt gemeldete Busy-Zeit (ms), damit sie trotz Messungenauigkeit nie zurueckspringt.
type winIO map[string]uint64

// windowsReport bildet die Metriken eines windows_exporters auf einen Bericht ab.
func windowsReport(m *Metrics, now time.Time, io winIO) *m64proto.Report {
	rep := &m64proto.Report{V: m64proto.Version, Time: now.UnixMilli()}
	hostNow, hasNow := firstValue(m, "windows_time_current_timestamp_seconds", "windows_os_time")
	if boot, ok := firstValue(m, "windows_system_boot_time_timestamp", "windows_system_boot_time_timestamp_seconds",
		"windows_system_system_up_time"); ok && boot > 0 {
		t := hostNow
		if !hasNow {
			t = float64(now.Unix())
		}
		if up := t - boot; up > 0 && up < 1e10 {
			rep.Uptime = math.Round(up)
		}
	}
	rep.CPU = winCPU(m)
	rep.Mem = winMem(m)
	rep.FS = winFS(m)
	rep.Disks = winDisks(m, hostNow, hasNow, io)
	rep.Net = winNet(m)
	rep.WinSvc = winServices(m)
	return rep
}

// winCPU: Zeiten je Modus ueber alle Kerne. "privileged" enthaelt Interrupt- und DPC-Zeit schon, deshalb zaehlen
// nur user, privileged und idle (sonst doppelt).
func winCPU(m *Metrics) *m64proto.CPU {
	ss := m.Get("windows_cpu_time_seconds_total")
	if len(ss) == 0 {
		ss = m.Get("windows_cpu_time_total")
	}
	if len(ss) == 0 {
		return nil
	}
	var user, system, idle float64
	cores := map[string]bool{}
	for _, s := range ss {
		if !finite(s.Value) || s.Value < 0 {
			continue
		}
		if len(cores) < 4096 {
			cores[s.Label("core")] = true
		}
		switch s.Label("mode") {
		case "user":
			user += s.Value
		case "privileged":
			system += s.Value
		case "idle":
			idle += s.Value
		}
	}
	n := len(cores)
	if v, ok := firstValue(m, "windows_cpu_logical_processor", "windows_cs_logical_processors"); ok && v > 0 && v < 4096 {
		n = int(v)
	}
	return &m64proto.CPU{Cores: n, User: ticks(user), System: ticks(system), Idle: ticks(idle)}
}

func winMem(m *Metrics) *m64proto.Mem {
	total, ok := firstValue(m, "windows_memory_physical_total_bytes", "windows_cs_physical_memory_bytes")
	if !ok || total <= 0 {
		return nil
	}
	avail, ok := firstValue(m, "windows_memory_available_bytes", "windows_memory_physical_free_bytes", "windows_os_physical_memory_free_bytes")
	if !ok { // ohne freien Speicher kein Abschnitt (sonst 0 frei = RAM 100 %); der Teilfehler des Sammlers haelt mem
		return nil
	}
	mem := &m64proto.Mem{Total: u64(total), Available: min(u64(avail), u64(total))}
	if m.Has("windows_pagefile_limit_bytes") {
		mem.SwapTotal = u64(sum(m, "windows_pagefile_limit_bytes"))
		mem.SwapFree = min(u64(sum(m, "windows_pagefile_free_bytes")), mem.SwapTotal)
	} else if lim, ok := m.Value("windows_os_paging_limit_bytes"); ok {
		free, _ := m.Value("windows_os_paging_free_bytes")
		mem.SwapTotal = u64(lim)
		mem.SwapFree = min(u64(free), mem.SwapTotal)
	}
	return mem
}

// winFS: Laufwerke mit Buchstaben (Volumes ohne Buchstaben, z. B. Wiederherstellung, wie beim Agent nicht).
func winFS(m *Metrics) []m64proto.FS {
	vol := func(s *Sample) string { return strings.ToUpper(s.Label("volume")) }
	free := index(m, "windows_logical_disk_free_bytes", vol)
	ro := index(m, "windows_logical_disk_readonly", vol)
	fsType := map[string]string{}
	for _, s := range m.Get("windows_logical_disk_info") {
		fsType[vol(&s)] = s.Label("filesystem")
	}
	var out []m64proto.FS
	seen := map[string]bool{}
	for _, s := range m.Get("windows_logical_disk_size_bytes") {
		v := vol(&s)
		if !driveRE.MatchString(v) || seen[v] || !finite(s.Value) || s.Value <= 0 {
			continue
		}
		f, ok := free[v]
		if !ok {
			continue
		}
		seen[v] = true
		fs := m64proto.FS{Mount: v, Type: clip(fsType[v], 40), Total: u64(s.Value), Avail: min(u64(f), u64(s.Value)), ReadOnly: ro[v] > 0}
		fs.Used = fs.Total - fs.Avail
		out = append(out, fs)
	}
	return out
}

// winDisks: physische Platten ("0 C:" -> PhysicalDrive0). Busy-Zeit = Uhrzeit - Leerlaufzeit (beide in Sekunden),
// monoton gehalten; ohne Uhrzeit des Hosts Lese- plus Schreibzeit.
func winDisks(m *Metrics, hostNow float64, hasNow bool, io winIO) []m64proto.DiskIO {
	disk := func(s *Sample) string { return s.Label("disk") }
	wb := index(m, "windows_physical_disk_write_bytes_total", disk)
	ro := index(m, "windows_physical_disk_reads_total", disk)
	wo := index(m, "windows_physical_disk_writes_total", disk)
	idle := index(m, "windows_physical_disk_idle_seconds_total", disk)
	rs := index(m, "windows_physical_disk_read_seconds_total", disk)
	ws := index(m, "windows_physical_disk_write_seconds_total", disk)
	var out []m64proto.DiskIO
	seen := map[string]bool{}
	for _, s := range m.Get("windows_physical_disk_read_bytes_total") {
		d := s.Label("disk")
		num, _, _ := strings.Cut(d, " ")
		if d == "" || d == "_Total" || num == "" || seen[num] {
			continue
		}
		seen[num] = true
		name := "PhysicalDrive" + clip(num, 20)
		var busy uint64
		if iv, ok := idle[d]; ok && hasNow {
			busy = u64((hostNow - iv) * 1000)
		} else {
			busy = u64((rs[d] + ws[d]) * 1000)
		}
		if io != nil {
			if p := io[name]; busy < p {
				busy = p
			}
			if len(io) < maxItems || hasKey(io, name) {
				io[name] = busy
			}
		}
		out = append(out, m64proto.DiskIO{Name: name, ReadBytes: u64(s.Value), WriteBytes: u64(wb[d]), ReadOps: u64(ro[d]),
			WriteOps: u64(wo[d]), IOTimeMs: busy})
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// winNet: Netzwerkkarten (Name = Instanz des Leistungszaehlers, Zustand aus nic_operation_status).
func winNet(m *Metrics) []m64proto.NetIf {
	nic := func(s *Sample) string { return s.Label("nic") }
	tb := index(m, "windows_net_bytes_sent_total", nic)
	rp := index(m, "windows_net_packets_received_total", nic)
	tp := index(m, "windows_net_packets_sent_total", nic)
	re := index(m, "windows_net_packets_received_errors_total", nic)
	te := index(m, "windows_net_packets_outbound_errors_total", nic)
	rd := index(m, "windows_net_packets_received_discarded_total", nic)
	td := index(m, "windows_net_packets_outbound_discarded_total", nic)
	bw := index(m, "windows_net_current_bandwidth_bytes", nic)
	bwBits := index(m, "windows_net_current_bandwidth", nic) // vor 0.25 in Bit/s
	status := map[string]string{}
	for _, s := range m.Get("windows_net_nic_operation_status") {
		if s.Value == 1 {
			status[s.Label("nic")] = s.Label("status")
		}
	}
	mac := map[string]string{}
	for _, s := range m.Get("windows_net_nic_info") {
		mac[s.Label("nic")] = s.Label("mac")
	}
	var out []m64proto.NetIf
	seen := map[string]bool{}
	for _, s := range m.Get("windows_net_bytes_received_total") {
		name := s.Label("nic")
		if name == "" || name == "_Total" || seen[name] {
			continue
		}
		seen[name] = true
		n := m64proto.NetIf{Name: clip(name, 100), Kind: winNetKind(name), RxBytes: u64(s.Value), TxBytes: u64(tb[name]),
			RxPackets: u64(rp[name]), TxPackets: u64(tp[name]), RxErrors: u64(re[name]), TxErrors: u64(te[name]),
			RxDropped: u64(rd[name]), TxDropped: u64(td[name]), MAC: clip(mac[name], 40)}
		speed := 0.0
		if v, ok := bw[name]; ok {
			speed = v * 8 / 1e6
		} else if v, ok := bwBits[name]; ok {
			speed = v / 1e6
		}
		if speed > 0 && speed < 1e8 {
			n.SpeedMbit = int(math.Round(speed))
		}
		if st, ok := status[name]; ok {
			n.Up = st == "up"
		} else {
			n.Up = n.SpeedMbit > 0
		}
		out = append(out, n)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func winNetKind(name string) string {
	l := strings.ToLower(name)
	for _, v := range winVirtual {
		if strings.Contains(l, v) {
			return "virtual"
		}
	}
	return "physical"
}

// winServices: Zustand und Starttyp je Dienst (Anzeigename aus windows_service_info).
func winServices(m *Metrics) []m64proto.WinService {
	svc := func(s *Sample) string { return firstNonEmpty(s.Label("service"), s.Label("name")) }
	states := m.Get("windows_service_state")
	if len(states) == 0 {
		return nil
	}
	start := map[string]string{}
	for _, s := range m.Get("windows_service_start_mode") {
		if s.Value == 1 {
			start[svc(&s)] = s.Label("start_mode")
		}
	}
	display := map[string]string{}
	for _, s := range m.Get("windows_service_info") {
		display[svc(&s)] = s.Label("display_name")
	}
	idx := map[string]int{}
	var out []m64proto.WinService
	for _, s := range states {
		name := svc(&s)
		if name == "" {
			continue
		}
		i, ok := idx[name]
		if !ok {
			if len(out) >= 4*maxItems {
				continue
			}
			i = len(out)
			idx[name] = i
			out = append(out, m64proto.WinService{Name: clip(name, 200), Display: clip(display[name], 200), State: "unknown",
				StartType: clip(start[name], 20)})
		}
		if s.Value == 1 {
			out[i].State = clip(s.Label("state"), 40)
		}
	}
	return out
}
