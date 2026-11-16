package apis

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// UniFi Drive (UNAS Pro, UNAS 2/4, UNAS Pro 4/8) ueber die lokale API der UniFi-OS-Konsole. Der UniFi-Zugang erkennt
// die Apps der Konsole selbst (ufApps): laeuft Drive, kommen diese Abfragen dazu - mit demselben API-Schluessel
// (X-API-KEY) bzw. derselben Sitzung. Es wird nur gelesen. Je Runde:
//
//	/proxy/drive/api/v2/storage               Pools (Zustand, RAID, Redundanz, Belegung, Pruefung) und Platten
//	                                          (Zustand, Temperatur, Sektoren, Betriebsstunden, Verschleiss)
//	/proxy/drive/api/v2/systems/device-info   CPU-Last und -Temperatur, RAM, Netz-Ports, Versionen
//	/proxy/drive/api/v2/systems/network-io    Durchsatz der Konsole
//
// Felder aus der Antwort einer UNAS Pro (UniFi OS 6.0.18, Drive 4.4.31; testdata/unifi_drive, anonymisiert). Ein
// Firmware-Update nennt die API mit dem Schluessel nicht (das steht nur nach einer Anmeldung in /api/system).

const (
	udPrefix    = "/proxy/drive/api/v2"
	udMaxDisks  = 64
	udMaxPools  = 32
	udMaxIfaces = 16
)

type udStorage struct {
	Pools      []udPool `json:"pools"`
	Disks      []udDisk `json:"disks"`
	CacheSlots []udDisk `json:"cacheSlots"`
}

type udPool struct {
	ID          string        `json:"id"`
	Number      optNum        `json:"number"`
	PreferLevel string        `json:"preferLevel"`
	Status      string        `json:"status"`
	Capacity    optNum        `json:"capacity"`
	Usage       optNum        `json:"usage"`
	RaidGroups  []udRaidGroup `json:"raidGroups"`
	Scrubbing   *struct {
		Status string `json:"status"`
	} `json:"dataScrubbing"`
}

type udRaidGroup struct {
	IsSSDCache         bool   `json:"isSSDCache"`
	CurrentLevel       string `json:"currentLevel"`
	CurrentProtection  optNum `json:"currentProtection"`
	ExpectedProtection optNum `json:"expectedProtection"`
	Progress           optNum `json:"progress"`
}

type udDisk struct {
	SlotID          json.RawMessage   `json:"slotId"`
	PoolID          string            `json:"poolId"`
	Type            string            `json:"type"`
	State           string            `json:"state"`
	Model           string            `json:"model"`
	Serial          string            `json:"serial"`
	NVMeVersion     string            `json:"nvmeVersion"`
	Size            optNum            `json:"size"`
	Temperature     optNum            `json:"temperature"`
	PowerOnHours    optNum            `json:"powerOnHours"`
	BadSectors      optNum            `json:"badSectorCount"`
	Uncorrectable   optNum            `json:"uncorrectableSectorCount"`
	ReadKBPS        optNum            `json:"readKBPS"`
	WriteKBPS       optNum            `json:"writeKBPS"`
	HealthScore     optNum            `json:"healthScore"`
	LifeSpan        optNum            `json:"lifeSpan"` // SSD: verbleibende Lebensdauer in %
	RiskReasons     []json.RawMessage `json:"riskReasons"`
	GlobalHotSpare  bool              `json:"isGlobalHotSpare"`
	LocalHotSpare   bool              `json:"isLocalHotSpare"`
	cache           bool              // aus cacheSlots
	slot, poolLabel string
}

type udDeviceInfo struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	Version  string `json:"version"`         // UniFi Drive
	Firmware string `json:"firmwareVersion"` // UniFi OS
	Status   string `json:"status"`
	Startup  string `json:"startupTime"`
	Memory   *struct {
		Total     optNum `json:"total"` // KiB
		Available optNum `json:"available"`
	} `json:"memory"`
	CPU *struct {
		Load optNum `json:"currentload"` // Anteil 0..1
		Temp optNum `json:"temperature"`
	} `json:"cpu"`
	Ifaces []struct {
		Kind      string `json:"interface"` // ethernet, sfp+
		Name      string `json:"interfaceName"`
		Connected bool   `json:"connected"`
		MaxSpeed  string `json:"maxSpeed"`
		LinkSpeed string `json:"linkSpeed"`
	} `json:"networkInterfaces"`
}

type udNetIO struct {
	RX optNum `json:"receiveKBPS"`
	TX optNum `json:"transmitKBPS"`
}

// udGood: Zustaende ohne Befund (Pool bzw. Platte).
var udGood = map[string]bool{"fullyoperational": true, "optimal": true, "healthy": true, "normal": true}

// udState: Zustand lesbar ("fullyOperational" -> in Ordnung), sonst roh.
func udState(s string) string {
	if udGood[strings.ToLower(strings.TrimSpace(s))] {
		return model.T("monitor64.txt.pi_power_ok")
	}
	return model.T("monitor64.txt.health_v", "v", devText(s))
}

// udLevel: "raid5" -> "RAID 5", "none" leer.
func udLevel(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch {
	case s == "" || s == "none":
		return ""
	case strings.HasPrefix(s, "raid"):
		return "RAID " + strings.ToUpper(strings.TrimPrefix(s, "raid"))
	case s == "shr" || strings.HasPrefix(s, "shr"):
		return strings.ToUpper(s)
	}
	return devText(s)
}

// drive fragt UniFi Drive ab (Pools, Platten, System). Ohne storage kein Ergebnis (err); die Systemwerte sind
// Teilfehler.
func (u *Unifi) drive(ctx context.Context, now time.Time, part hintPartial) ([]model.Service, error) {
	var st udStorage
	if err := u.getRaw(ctx, udPrefix+"/storage", &st); err != nil {
		return nil, err
	}
	out := u.udStorageServices(st)
	var di udDeviceInfo
	if err := u.getRaw(ctx, udPrefix+"/systems/device-info", &di); err != nil {
		part.add("drive/device-info", err, "drive", "cpu", "mem", "temp:", "if:")
	} else {
		var io *udNetIO
		var n udNetIO
		if err := u.getRaw(ctx, udPrefix+"/systems/network-io", &n); err == nil {
			io = &n
		} else if !webAbsent(err) {
			part.add("drive/network-io", err)
		}
		out = append(out, udSystemServices(di, io, now)...)
	}
	return out, nil
}

// udStorageServices: je Pool ein Dienst (raid:pool<n>), je Platte einer (disk:<seriennummer>).
func (u *Unifi) udStorageServices(st udStorage) []model.Service {
	var out []model.Service
	labels := map[string]string{} // Pool-ID -> Nummer des Pools
	members := map[string]int{}
	var disks []udDisk
	for i, d := range append(append([]udDisk(nil), st.Disks...), st.CacheSlots...) {
		if len(disks) >= udMaxDisks {
			break
		}
		d.cache = i >= len(st.Disks)
		d.slot = rawText(d.SlotID)
		disks = append(disks, d)
		if d.PoolID != "" {
			members[d.PoolID]++
		}
	}
	for i, p := range st.Pools {
		if i >= udMaxPools {
			break
		}
		n := strconv.Itoa(i + 1)
		if p.Number.Set && p.Number.V > 0 {
			n = strconv.Itoa(int(p.Number.V))
		}
		label := "Pool " + n
		if p.ID != "" {
			labels[p.ID] = n
		}
		out = append(out, udPoolService("raid:pool"+n, label, p, members[p.ID]))
	}
	// Schluessel: Seriennummer, wenn eindeutig, sonst der Schacht
	serials := map[string]int{}
	for _, d := range disks {
		if s := strings.TrimSpace(d.Serial); s != "" {
			serials[s]++
		}
	}
	if u.udSectors == nil {
		u.udSectors = map[string]uint64{}
	}
	for _, d := range disks {
		key := "disk:" + strings.TrimSpace(d.Serial)
		if s := strings.TrimSpace(d.Serial); s == "" || serials[s] > 1 {
			pre := "slot"
			if d.cache {
				pre = "cache"
			}
			key = "disk:" + pre + firstNonEmpty(d.slot, "?")
		}
		d.poolLabel = labels[d.PoolID]
		out = append(out, udDiskService(key, d, u.udSectors))
	}
	return out
}

func udPoolService(key, label string, p udPool, disks int) model.Service {
	s := model.Service{Key: key, Name: model.Raw(label), Kind: "raid", Default: true}
	var parts, bad []string
	level := ""
	for _, g := range p.RaidGroups {
		if g.IsSSDCache {
			continue
		}
		level = firstNonEmpty(level, udLevel(g.CurrentLevel))
		if g.CurrentProtection.Set && g.ExpectedProtection.Set && g.CurrentProtection.V < g.ExpectedProtection.V {
			bad = append(bad, model.T("monitor64.txt.ud_protection", "cur", int(g.CurrentProtection.V), "exp", int(g.ExpectedProtection.V)))
		}
		if g.Progress.Set && g.Progress.V > 0 && g.Progress.V < 100 {
			parts = append(parts, model.T("monitor64.txt.ud_rebuild", "v", fmt.Sprintf("%.0f", g.Progress.V)))
		}
	}
	if level = firstNonEmpty(level, udLevel(p.PreferLevel)); level != "" {
		parts = append([]string{level}, parts...)
	}
	parts = append(parts, udState(p.Status))
	if !udGood[strings.ToLower(strings.TrimSpace(p.Status))] && p.Status != "" {
		bad = append([]string{udState(p.Status)}, bad...)
	}
	if p.Capacity.Set && p.Capacity.V > 0 && p.Usage.Set {
		tot := p.Capacity.V
		free := math.Max(tot-p.Usage.V, 0)
		s.Metrics = append(s.Metrics, model.Metric{Name: "used", Value: pct(p.Usage.V, tot), Unit: "%", Rule: model.RuleStore, Max: tot},
			model.Metric{Name: "free", Value: free, Unit: "B", Max: tot})
		parts = append(parts, model.T("monitor64.txt.free_of", "free", bytesText(free), "total", bytesText(tot)))
	}
	if disks > 0 {
		parts = append(parts, model.T("monitor64.txt.disks_n", "n", disks))
	}
	if sc := p.Scrubbing; sc != nil && strings.EqualFold(sc.Status, "running") {
		parts = append(parts, model.T("monitor64.txt.ud_scrub_running"))
	}
	if len(bad) > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "raid_degraded", Text: strings.Join(limitList(bad, 5), ", ")})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

func udDiskService(key string, d udDisk, prevSectors map[string]uint64) model.Service {
	name := model.T("monitor64.txt.ud_slot", "n", model.Raw(firstNonEmpty(d.slot, "?")))
	if d.cache {
		name = model.T("monitor64.txt.ud_cache_slot", "n", model.Raw(firstNonEmpty(d.slot, "?")))
	}
	if m := strings.TrimSpace(d.Model); m != "" {
		name += " (" + devText(m) + ")"
	}
	s := model.Service{Key: key, Name: name, Kind: "disk", Default: true}
	var parts []string
	if d.Size.Set && d.Size.V > 0 {
		parts = append(parts, bytesText(d.Size.V))
	}
	parts = append(parts, udState(d.State))
	if st := strings.ToLower(strings.TrimSpace(d.State)); st != "" && !udGood[st] {
		s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: model.T("monitor64.txt.disk_word") + " " + udState(d.State)})
	}
	var risks []string
	for _, r := range d.RiskReasons {
		if t := rawText(r); t != "" && t != "{}" && t != "null" {
			risks = append(risks, devText(t))
		}
	}
	if len(risks) > 0 {
		t := model.T("monitor64.txt.ud_risk", "v", model.Raw(strings.Join(limitList(risks, 3), ", ")))
		parts = append(parts, t)
		s.Facts = append(s.Facts, model.Fact{Code: "disk_errors", Text: t})
	}
	switch {
	case d.poolLabel != "":
		parts = append(parts, model.T("monitor64.txt.in_pool", "v", model.Raw(d.poolLabel)))
	case d.GlobalHotSpare || d.LocalHotSpare:
		parts = append(parts, model.T("monitor64.txt.ud_spare"))
	case !d.cache:
		parts = append(parts, model.T("monitor64.txt.ud_no_pool"))
	}
	if d.Temperature.Set && d.Temperature.V > 0 && d.Temperature.V < 150 {
		rule := model.RuleDiskTemp
		if strings.TrimSpace(d.NVMeVersion) != "" || strings.EqualFold(d.Type, "nvme") {
			rule = model.RuleNVMeTemp
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(d.Temperature.V), Unit: "°C", Rule: rule})
		parts = append(parts, fmt.Sprintf("%.0f °C", d.Temperature.V))
	}
	if d.LifeSpan.Set && d.LifeSpan.V >= 0 && d.LifeSpan.V <= 100 && !strings.EqualFold(d.Type, "hdd") {
		w := 100 - d.LifeSpan.V
		s.Metrics = append(s.Metrics, model.Metric{Name: "wear", Value: round2(w), Unit: "%", Rule: model.RuleWear})
		parts = append(parts, model.T("monitor64.txt.wear", "v", fmt.Sprintf("%.0f", w)))
	}
	var sec uint64
	counted := false
	for _, c := range []struct {
		name string
		v    optNum
	}{{"realloc", d.BadSectors}, {"uncorr", d.Uncorrectable}} {
		if c.v.Set && c.v.V >= 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: c.name, Value: c.v.V})
			sec += uint64(c.v.V)
			counted = true
		}
	}
	if sec > 0 {
		code := "smart_sectors"
		if p, ok := prevSectors[key]; ok && p < sec {
			code = "smart_sectors_rising"
		}
		s.Facts = append(s.Facts, model.Fact{Code: code, Text: model.T("monitor64.txt.sectors_bad", "n", sec)})
		parts = append(parts, model.T("monitor64.txt.sectors", "n", sec))
	}
	if counted {
		prevSectors[key] = sec
	}
	if d.PowerOnHours.Set && d.PowerOnHours.V >= 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "power_on_hours", Value: d.PowerOnHours.V, Unit: "h"})
	}
	if d.HealthScore.Set {
		s.Metrics = append(s.Metrics, model.Metric{Name: "health", Value: d.HealthScore.V})
	}
	if d.ReadKBPS.Set && d.WriteKBPS.Set {
		s.Metrics = append(s.Metrics, model.Metric{Name: "read", Value: math.Round(d.ReadKBPS.V * 1024), Unit: "B/s"},
			model.Metric{Name: "write", Value: math.Round(d.WriteKBPS.V * 1024), Unit: "B/s"})
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// udSystemServices: UniFi Drive (Versionen, Laufzeit, Durchsatz), CPU, RAM, CPU-Temperatur und Netz-Ports.
func udSystemServices(di udDeviceInfo, io *udNetIO, now time.Time) []model.Service {
	name := firstNonEmpty(strings.TrimSpace(di.Name), strings.TrimSpace(di.Model), "UniFi Drive")
	sys := model.Service{Key: "drive", Name: devText(name), Kind: "system", Default: true}
	var parts []string
	if v := shortText(di.Firmware); v != "" {
		parts = append(parts, "UniFi OS "+model.Raw(v))
	}
	if v := shortText(di.Version); v != "" {
		parts = append(parts, "Drive "+model.Raw(v))
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(di.Startup)); err == nil && !t.After(now) {
		up := now.Sub(t)
		sys.Metrics = append(sys.Metrics, model.Metric{Name: "uptime", Value: math.Round(up.Seconds()), Unit: "s"})
		parts = append(parts, model.T("monitor64.txt.up_since", "d", model.Sub(hoursText(up))))
	}
	if st := strings.TrimSpace(di.Status); st != "" && !strings.EqualFold(st, "STATE_RUNNING") {
		parts = append(parts, model.T("monitor64.txt.health_v", "v", devText(st)))
		sys.Facts = append(sys.Facts, model.Fact{Code: "device_warn", Text: model.T("monitor64.txt.health_v", "v", devText(st))})
	}
	if io != nil && io.RX.Set && io.TX.Set {
		in, out := io.RX.V*8/1000, io.TX.V*8/1000 // KB/s -> Mbit/s
		sys.Metrics = append(sys.Metrics, model.Metric{Name: "in", Value: round2(in), Unit: "Mbit/s"}, model.Metric{Name: "out", Value: round2(out), Unit: "Mbit/s"})
		parts = append(parts, fmt.Sprintf("↓ %s · ↑ %s", mbitText(in), mbitText(out)))
	}
	sys.Text = strings.Join(parts, " · ")
	out := []model.Service{sys}
	if c := di.CPU; c != nil && c.Load.Set && c.Load.V >= 0 && c.Load.V <= 1 {
		v := round2(c.Load.V * 100)
		out = append(out, model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true, Text: fmt.Sprintf("%.0f %%", v),
			Metrics: []model.Metric{{Name: "util", Value: v, Unit: "%", Rule: model.RuleCPU}}})
	}
	if c := di.CPU; c != nil && c.Temp.Set && c.Temp.V > 0 && c.Temp.V < 150 {
		out = append(out, model.Service{Key: "temp:cpu", Name: model.T("monitor64.txt.ud_cpu_temp"), Kind: "temp", Default: true, Text: fmt.Sprintf("%.0f °C", c.Temp.V),
			Metrics: []model.Metric{{Name: "temp", Value: round2(c.Temp.V), Unit: "°C", Rule: model.RuleTemp}}})
	}
	if m := di.Memory; m != nil && m.Total.Set && m.Total.V > 0 && m.Available.Set {
		tot := m.Total.V * 1024
		used := math.Max(tot-m.Available.V*1024, 0)
		out = append(out, model.Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
			Text: model.T("monitor64.txt.ram_of", "used", bytesText(used), "total", bytesText(tot)),
			Metrics: []model.Metric{{Name: "used", Value: pct(used, tot), Unit: "%", Rule: model.RuleMem, Max: tot},
				{Name: "used_bytes", Value: used, Unit: "B", Max: tot}}})
	}
	var ifs []model.Service
	for i, n := range di.Ifaces {
		if i >= udMaxIfaces || strings.TrimSpace(n.Name) == "" {
			continue
		}
		label := strings.ToUpper(strings.TrimSpace(n.Kind))
		if label == "ETHERNET" {
			label = "Ethernet"
		}
		s := model.Service{Key: "if:" + n.Name, Name: model.Raw(strings.TrimSpace(label + " (" + n.Name + ")")), Kind: "if", Default: n.Connected}
		up := 0.0
		if n.Connected {
			up = 1
			s.Text = devText(firstNonEmpty(n.LinkSpeed, n.MaxSpeed))
		} else {
			s.Text = model.T("monitor64.txt.no_link", "name", model.Raw(n.Name))
			s.Facts = append(s.Facts, model.Fact{Code: "if_down", Text: s.Text})
		}
		s.Metrics = []model.Metric{{Name: "up", Value: up}}
		ifs = append(ifs, s)
	}
	sort.SliceStable(ifs, func(i, j int) bool { return ifs[i].Key < ifs[j].Key })
	return append(out, ifs...)
}
