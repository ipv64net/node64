package promscrape

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// node_exporter -> Agent-Bericht (m64proto.Report). Zaehler bleiben roh (CPU in USER_HZ-Ticks wie /proc/stat,
// Bytes, Pakete, ms); Raten rechnet der Mapper des Kerns aus zwei Berichten. Filter wie beim Agent
// (m64linux.SkipMount, IsWholeDisk, virtuelle Schnittstellen).

const (
	userHZ   = 100 // Ticks je Sekunde (node_cpu_seconds_total -> Jiffies wie /proc/stat)
	maxItems = 512 // Eintraege je Abschnitt (wie der Agent)
)

// Namen virtueller Schnittstellen (wie internal/m64linux/net.go virtualPrefixes; ohne sysfs gibt es keine bessere
// Erkennung).
var virtualPrefixes = []string{"veth", "docker", "br-", "tap", "fwbr", "fwpr", "fwln", "virbr", "vnet", "tun",
	"lxc", "cali", "flannel", "cni", "vxlan", "kube-", "dummy", "ifb", "zt", "tailscale", "wg"}

// nodeReport bildet die Metriken eines node_exporters auf einen Bericht ab.
func nodeReport(m *Metrics, now time.Time) *m64proto.Report {
	rep := &m64proto.Report{V: m64proto.Version, Time: now.UnixMilli()}
	if boot, ok := m.Value("node_boot_time_seconds"); ok && boot > 0 {
		t, ok := m.Value("node_time_seconds")
		if !ok {
			t = float64(now.Unix())
		}
		if up := t - boot; up > 0 && up < 1e10 {
			rep.Uptime = math.Round(up)
		}
	}
	rep.CPU = nodeCPU(m)
	rep.Mem = nodeMem(m)
	if l1, ok1 := m.Value("node_load1"); ok1 {
		l5, ok5 := m.Value("node_load5")
		l15, ok15 := m.Value("node_load15")
		if ok5 && ok15 && l1 >= 0 && l5 >= 0 && l15 >= 0 {
			rep.Load = &m64proto.Load{L1: l1, L5: l5, L15: l15}
		}
	}
	rep.FS = nodeFS(m)
	rep.Disks = nodeDisks(m)
	bondNames := map[string]bool{}
	rep.Bonds = nodeBonds(m, bondNames)
	rep.Net = nodeNet(m, bondNames)
	rep.RAID = nodeRAID(m)
	rep.ZFS = nodeZFS(m)
	rep.Temps = nodeTemps(m)
	rep.Systemd = nodeSystemd(m)
	if v, ok := m.Value("node_reboot_required"); ok { // textfile (z. B. apt bzw. needrestart)
		rep.Reboot = &m64proto.Reboot{Required: v > 0}
	}
	rep.Updates = textfileUpdates(m)
	return rep
}

// nodeCPU summiert node_cpu_seconds_total je Modus ueber alle Kerne (Sekunden -> Ticks).
func nodeCPU(m *Metrics) *m64proto.CPU {
	ss := m.Get("node_cpu_seconds_total")
	if len(ss) == 0 {
		return nil
	}
	var user, nice, system, idle, iowait, irq, softirq, steal float64 // FreeBSD: interrupt statt irq
	cores := map[string]bool{}
	for _, s := range ss {
		if !finite(s.Value) || s.Value < 0 {
			continue
		}
		if len(cores) < 4096 {
			cores[s.Label("cpu")] = true
		}
		switch s.Label("mode") {
		case "user":
			user += s.Value
		case "nice":
			nice += s.Value
		case "system":
			system += s.Value
		case "idle":
			idle += s.Value
		case "iowait":
			iowait += s.Value
		case "irq", "interrupt":
			irq += s.Value
		case "softirq":
			softirq += s.Value
		case "steal":
			steal += s.Value
		}
	}
	return &m64proto.CPU{Cores: len(cores), User: ticks(user), Nice: ticks(nice), System: ticks(system), Idle: ticks(idle),
		IOWait: ticks(iowait), IRQ: ticks(irq), SoftIRQ: ticks(softirq), Steal: ticks(steal)}
}

func nodeMem(m *Metrics) *m64proto.Mem {
	total, ok := m.Value("node_memory_MemTotal_bytes")
	if !ok || total <= 0 {
		return nil
	}
	avail, ok := m.Value("node_memory_MemAvailable_bytes")
	if !ok { // alte Kernel ohne MemAvailable
		free, ok := m.Value("node_memory_MemFree_bytes")
		if !ok { // ohne freien Speicher kein Abschnitt (sonst RAM 100 %)
			return nil
		}
		buf, _ := m.Value("node_memory_Buffers_bytes")
		cached, _ := m.Value("node_memory_Cached_bytes")
		avail = free + buf + cached
	}
	st, _ := m.Value("node_memory_SwapTotal_bytes")
	sf, _ := m.Value("node_memory_SwapFree_bytes")
	return &m64proto.Mem{Total: u64(total), Available: min(u64(avail), u64(total)), SwapTotal: u64(st), SwapFree: min(u64(sf), u64(st))}
}

// nodeFS: echte Dateisysteme (Filter wie beim Agent), je Geraet nur der kuerzeste Mount (Bind-Mounts, Subvolumes).
func nodeFS(m *Metrics) []m64proto.FS {
	key := func(s *Sample) string {
		return s.Label("device") + "\x00" + s.Label("mountpoint") + "\x00" + s.Label("fstype")
	}
	free := index(m, "node_filesystem_free_bytes", key)
	avail := index(m, "node_filesystem_avail_bytes", key)
	files := index(m, "node_filesystem_files", key)
	ffree := index(m, "node_filesystem_files_free", key)
	ro := index(m, "node_filesystem_readonly", key)
	devErr := index(m, "node_filesystem_device_error", key)
	var out []m64proto.FS
	idx := map[string]int{}
	for _, s := range m.Get("node_filesystem_size_bytes") {
		k := key(&s)
		mt := m64linux.Mount{Device: s.Label("device"), Mount: s.Label("mountpoint"), Type: s.Label("fstype")}
		if mt.Mount == "" || m64linux.SkipMount(mt) || s.Label("device_error") != "" || devErr[k] > 0 {
			continue
		}
		if !finite(s.Value) || s.Value <= 0 {
			continue
		}
		f, fok := free[k]
		a, aok := avail[k]
		if !fok || !aok {
			continue
		}
		fs := m64proto.FS{Mount: clip(mt.Mount, 300), Device: clip(mt.Device, 300), Type: clip(mt.Type, 40), Total: u64(s.Value),
			Avail: u64(a), ReadOnly: ro[k] > 0}
		fs.Used = fs.Total - min(u64(f), fs.Total)
		if n := files[k]; n > 0 {
			fs.InodesTotal = u64(n)
			fs.InodesFree = min(u64(ffree[k]), fs.InodesTotal)
		}
		dk := fs.Device
		if dk == "" {
			dk = "mount:" + fs.Mount
		}
		if i, ok := idx[dk]; ok {
			if len(fs.Mount) < len(out[i].Mount) {
				out[i] = fs
			}
			continue
		}
		if len(out) >= maxItems {
			break
		}
		idx[dk] = len(out)
		out = append(out, fs)
	}
	return out
}

// nodeDisks: ganze Platten aus diskstats, Seriennummer/Modell aus node_disk_info (udev).
func nodeDisks(m *Metrics) []m64proto.DiskIO {
	dev := func(s *Sample) string { return s.Label("device") }
	wb := index(m, "node_disk_written_bytes_total", dev)
	ro := index(m, "node_disk_reads_completed_total", dev)
	wo := index(m, "node_disk_writes_completed_total", dev)
	io := index(m, "node_disk_io_time_seconds_total", dev)
	info := map[string]*Sample{}
	for i, s := range m.Get("node_disk_info") {
		if _, ok := info[s.Label("device")]; !ok {
			info[s.Label("device")] = &m.Get("node_disk_info")[i]
		}
	}
	var out []m64proto.DiskIO
	seen := map[string]bool{}
	for _, s := range m.Get("node_disk_read_bytes_total") {
		name := s.Label("device")
		if !m64linux.IsWholeDisk(name) || seen[name] {
			continue
		}
		seen[name] = true
		d := m64proto.DiskIO{Name: name, ReadBytes: u64(s.Value), WriteBytes: u64(wb[name]), ReadOps: u64(ro[name]),
			WriteOps: u64(wo[name]), IOTimeMs: u64(io[name] * 1000)}
		if in := info[name]; in != nil {
			d.Serial = clip(in.Label("serial"), 100)
			d.Model = clip(strings.ReplaceAll(in.Label("model"), "_", " "), 100)
			switch in.Label("rotational") {
			case "1":
				d.Rotational = ptrBool(true)
			case "0":
				d.Rotational = ptrBool(false)
			}
		}
		out = append(out, d)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// nodeNet: Zaehler aus netdev, Zustand/Geschwindigkeit aus netclass.
func nodeNet(m *Metrics, bonds map[string]bool) []m64proto.NetIf {
	dev := func(s *Sample) string { return s.Label("device") }
	tb := index(m, "node_network_transmit_bytes_total", dev)
	rp := index(m, "node_network_receive_packets_total", dev)
	tp := index(m, "node_network_transmit_packets_total", dev)
	re := index(m, "node_network_receive_errs_total", dev)
	te := index(m, "node_network_transmit_errs_total", dev)
	rd := index(m, "node_network_receive_drop_total", dev)
	td := index(m, "node_network_transmit_drop_total", dev)
	up := index(m, "node_network_up", dev)
	carrier := index(m, "node_network_carrier", dev)
	speed := index(m, "node_network_speed_bytes", dev)
	mtu := index(m, "node_network_mtu_bytes", dev)
	info := map[string]*Sample{}
	for i, s := range m.Get("node_network_info") {
		info[s.Label("device")] = &m.Get("node_network_info")[i]
	}
	var out []m64proto.NetIf
	seen := map[string]bool{}
	for _, s := range m.Get("node_network_receive_bytes_total") {
		name := s.Label("device")
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		n := m64proto.NetIf{Name: clip(name, 100), Kind: netKind(name, bonds), RxBytes: u64(s.Value), TxBytes: u64(tb[name]),
			RxPackets: u64(rp[name]), TxPackets: u64(tp[name]), RxErrors: u64(re[name]), TxErrors: u64(te[name]),
			RxDropped: u64(rd[name]), TxDropped: u64(td[name])}
		in := info[name]
		switch {
		case hasKey(up, name):
			n.Up = up[name] > 0
		case in != nil:
			n.Up = in.Label("operstate") == "up"
		default:
			n.Up = carrier[name] > 0
		}
		if v := speed[name]; v > 0 && v < 1e14 {
			n.SpeedMbit = int(math.Round(v * 8 / 1e6))
		}
		if v := mtu[name]; v > 0 && v < 1e6 {
			n.MTU = int(v)
		}
		if in != nil {
			n.MAC = clip(in.Label("address"), 40)
			if d := in.Label("duplex"); d != "" && d != "unknown" {
				n.Duplex = clip(d, 20)
			}
		}
		out = append(out, n)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

func netKind(name string, bonds map[string]bool) string {
	if name == "lo" {
		return "virtual"
	}
	if bonds[name] {
		return "bond"
	}
	for _, p := range virtualPrefixes {
		if strings.HasPrefix(name, p) {
			return "virtual"
		}
	}
	return "physical" // ohne sysfs nicht genauer bestimmbar (Bridges/VLANs zeigt der Mapper wie Ports)
}

// nodeBonds: node_exporter kennt je Bond nur die Zahl der Mitglieder und der aktiven Mitglieder (keine Namen, keinen
// Modus). Die Mitglieder heissen deshalb "Mitglied 1..n"; aktive zuerst.
func nodeBonds(m *Metrics, names map[string]bool) []m64proto.Bond {
	master := func(s *Sample) string { return s.Label("master") }
	active := index(m, "node_bonding_active", master)
	var out []m64proto.Bond
	for _, s := range m.Get("node_bonding_slaves") {
		name := s.Label("master")
		if name == "" || names[name] || !finite(s.Value) {
			continue
		}
		names[name] = true
		n := int(min(max(s.Value, 0), 64))
		act := int(min(max(active[name], 0), float64(n)))
		b := m64proto.Bond{Name: clip(name, 100), MII: "down", Members: []m64proto.BondSlave{}}
		if act > 0 {
			b.MII = "up"
		}
		for i := 1; i <= n; i++ {
			mii := "down"
			if i <= act {
				mii = "up"
			}
			b.Members = append(b.Members, m64proto.BondSlave{Name: fmt.Sprintf("Mitglied %d", i), MII: mii})
		}
		out = append(out, b)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// nodeRAID: mdraid (Zustand, aktive/defekte/Reserve-Platten, Sync-Fortschritt).
func nodeRAID(m *Metrics) []m64proto.RAID {
	dev := func(s *Sample) string { return s.Label("device") }
	required := index(m, "node_md_disks_required", dev)
	raidDisks := index(m, "node_md_raid_disks", dev)
	degraded := index(m, "node_md_degraded", dev)
	blocks := index(m, "node_md_blocks", dev)
	synced := index(m, "node_md_blocks_synced", dev)
	disks := map[string]map[string]float64{}
	for _, s := range m.Get("node_md_disks") {
		if !finite(s.Value) { // NaN -> int(NaN) waere beliebig (MinInt64)
			continue
		}
		d := s.Label("device")
		if disks[d] == nil {
			disks[d] = map[string]float64{}
		}
		disks[d][s.Label("state")] = s.Value
	}
	state := map[string]string{}
	var order []string
	for _, s := range m.Get("node_md_state") {
		d := s.Label("device")
		if _, ok := state[d]; !ok {
			state[d] = ""
			order = append(order, d)
		}
		if s.Value == 1 {
			state[d] = s.Label("state")
		}
	}
	for _, s := range m.Get("node_md_disks_required") { // Geraete ohne node_md_state (aeltere Versionen)
		if d := s.Label("device"); d != "" {
			if _, ok := state[d]; !ok {
				state[d] = ""
				order = append(order, d)
			}
		}
	}
	var out []m64proto.RAID
	for _, d := range order {
		if d == "" {
			continue
		}
		r := m64proto.RAID{Name: clip(d, 100), Level: "mdraid", State: firstNonEmpty(state[d], "unknown")}
		r.Devices = int(min(max(firstPos(required[d], raidDisks[d]), 0), 1024))
		r.Active = int(min(max(disks[d]["active"], 0), 1024))
		r.Failed = int(min(max(disks[d]["failed"], 0), 1024))
		r.Spare = int(min(max(disks[d]["spare"], 0), 1024))
		// Fortschritt vor dem Zusatz "degraded": waehrend des Wiederaufbaus meldet md die fehlende Platte noch als
		// degraded; mit Fortschritt gilt das wie beim Agent als Wiederaufbau (kein raid_degraded)
		switch r.State {
		case "recovering", "resync", "check":
			if b := blocks[d]; b > 0 && synced[d] >= 0 && synced[d] <= b {
				p := math.Round(synced[d]/b*1000) / 10
				r.SyncPercent = &p
			}
		}
		if degraded[d] > 0 && !strings.Contains(r.State, "degraded") && r.SyncPercent == nil {
			r.State += ", degraded"
		}
		out = append(out, r)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// nodeZFS: Zustand je Pool (node_zfs_zpool_state). Groesse/Belegung liefert node_exporter nicht; ersatzweise das
// Wurzel-Dataset des Pools aus node_filesystem_* (nutzbarer Platz, falls eingehaengt).
func nodeZFS(m *Metrics) []m64proto.ZPool {
	health := map[string]string{}
	var order []string
	for _, s := range m.Get("node_zfs_zpool_state") {
		p := s.Label("zpool")
		if p == "" {
			continue
		}
		if _, ok := health[p]; !ok {
			health[p] = ""
			order = append(order, p)
		}
		if s.Value == 1 {
			health[p] = strings.ToUpper(s.Label("state"))
		}
	}
	if len(order) == 0 {
		return nil
	}
	size, avail := map[string]float64{}, map[string]float64{}
	key := func(s *Sample) string { return s.Label("device") + "\x00" + s.Label("mountpoint") }
	av := index(m, "node_filesystem_avail_bytes", key)
	for _, s := range m.Get("node_filesystem_size_bytes") {
		if s.Label("fstype") != "zfs" || !finite(s.Value) {
			continue
		}
		d := s.Label("device")
		if _, ok := health[d]; ok && size[d] == 0 {
			size[d], avail[d] = s.Value, av[key(&s)]
		}
	}
	var out []m64proto.ZPool
	for _, p := range order {
		z := m64proto.ZPool{Name: clip(p, 100), Health: firstNonEmpty(health[p], "UNKNOWN")}
		if sz := size[p]; sz > 0 {
			z.Size, z.Free = u64(sz), min(u64(avail[p]), u64(sz))
			z.Alloc = z.Size - z.Free
		}
		out = append(out, z)
		if len(out) >= maxItems {
			break
		}
	}
	return out
}

// nodeTemps: hwmon wie beim Agent ("<Chip-Name>/<Label oder tempN>", mehrfacher Chip-Name bzw. nvme mit "@<chip>"),
// drivetemp ausgelassen; Thermal-Zonen nur ohne gleichnamigen hwmon.
func nodeTemps(m *Metrics) []m64proto.Temp {
	chipName := map[string]string{}
	for _, s := range m.Get("node_hwmon_chip_names") {
		chipName[s.Label("chip")] = s.Label("chip_name")
	}
	cs := func(s *Sample) string { return s.Label("chip") + "\x00" + s.Label("sensor") }
	label := map[string]string{}
	for _, s := range m.Get("node_hwmon_sensor_label") {
		label[cs(&s)] = s.Label("label")
	}
	high := index(m, "node_hwmon_temp_max_celsius", cs)
	crit := index(m, "node_hwmon_temp_crit_celsius", cs)
	temps := m.Get("node_hwmon_temp_celsius")
	nameOf := func(chip string) string { return firstNonEmpty(chipName[chip], chip) }
	count := map[string]int{}
	seenChip := map[string]bool{}
	for _, s := range temps {
		c := s.Label("chip")
		if !seenChip[c] {
			seenChip[c] = true
			count[nameOf(c)]++
		}
	}
	var out []m64proto.Temp
	used := map[string]int{}
	add := func(t m64proto.Temp) {
		if n := used[t.Name]; n > 0 {
			used[t.Name]++
			t.Name += fmt.Sprintf("#%d", n+1)
		} else {
			used[t.Name] = 1
		}
		if len(out) < maxItems {
			out = append(out, t)
		}
	}
	hwNames := map[string]bool{}
	for _, s := range temps {
		chip, sensor := s.Label("chip"), s.Label("sensor")
		name := nameOf(chip)
		if name == "drivetemp" { // Plattentemperatur kommt aus SMART (wie beim Agent)
			continue
		}
		hwNames[normSensor(name)] = true
		if !plausibleC(s.Value) {
			continue
		}
		prefix := name
		if count[name] > 1 || name == "nvme" {
			prefix += "@" + chip
		}
		lb := clip(label[cs(&s)], 100)
		t := m64proto.Temp{Name: clip(prefix+"/"+firstNonEmpty(lb, sensor), 200), Label: lb, C: s.Value}
		if v := high[cs(&s)]; plausibleC(v) && v > 0 {
			t.High = ptrF64(v)
		}
		if v := crit[cs(&s)]; plausibleC(v) && v > 0 {
			t.Crit = ptrF64(v)
		}
		add(t)
	}
	for _, s := range m.Get("node_thermal_zone_temp") {
		typ := firstNonEmpty(s.Label("type"), "thermal_zone"+s.Label("zone"))
		if hwNames[normSensor(typ)] || !plausibleC(s.Value) {
			continue
		}
		add(m64proto.Temp{Name: clip("thermal/"+typ, 200), Label: clip(typ, 100), C: s.Value})
	}
	return out
}

// nodeSystemd: fehlgeschlagene Units (nur mit --collector.systemd).
func nodeSystemd(m *Metrics) *m64proto.Systemd {
	ss := m.Get("node_systemd_unit_state")
	if len(ss) == 0 {
		return nil
	}
	sd := &m64proto.Systemd{Failed: []string{}}
	for _, s := range ss {
		if s.Label("state") == "failed" && s.Value == 1 && len(sd.Failed) < maxItems {
			sd.Failed = append(sd.Failed, clip(s.Label("name"), 200))
		}
	}
	if v, ok := m.Value("node_systemd_system_running"); ok {
		sd.State = "running"
		if v != 1 {
			sd.State = "degraded"
		}
	}
	return sd
}

// textfileUpdates: ausstehende Updates aus den verbreiteten Textfile-Skripten (prometheus-community
// node-exporter-textfile-collector-scripts: apt_info.py bzw. yum.sh).
func textfileUpdates(m *Metrics) *m64proto.Updates {
	for _, src := range []struct{ name, mgr string }{{"apt_upgrades_pending", "apt"}, {"yum_upgrades_pending", "dnf"}} {
		ss := m.Get(src.name)
		if len(ss) == 0 {
			continue
		}
		u := &m64proto.Updates{Manager: src.mgr}
		for _, s := range ss {
			if !finite(s.Value) || s.Value < 0 || s.Value > 1e6 {
				continue
			}
			u.Pending += int(s.Value)
			if strings.Contains(strings.ToLower(s.Label("origin")), "security") {
				u.Security += int(s.Value)
			}
		}
		return u
	}
	return nil
}

func normSensor(s string) string { return strings.ReplaceAll(strings.ToLower(s), "-", "_") }

// plausibleC: Temperatur in Grad, die ein Sensor wirklich liefern kann (wie der Agent).
func plausibleC(c float64) bool { return finite(c) && c > -60 && c < 200 }
