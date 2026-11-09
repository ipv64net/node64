package apis

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Gemeinsame Teile von Proxmox VE und PBS: Node-Status, Updates, Platten mit SMART.

// nodeStatus ist die Antwort von /nodes/{node}/status (Proxmox VE: rootfs und loadavg als Strings, PBS: root).
type nodeStatus struct {
	CPU     num `json:"cpu"`
	Wait    num `json:"wait"`
	CPUInfo struct {
		CPUs  num    `json:"cpus"`
		Model string `json:"model"`
	} `json:"cpuinfo"`
	LoadAvg []num `json:"loadavg"`
	Memory  struct {
		Total num `json:"total"`
		Used  num `json:"used"`
		Free  num `json:"free"`
	} `json:"memory"`
	Swap struct {
		Total num `json:"total"`
		Used  num `json:"used"`
	} `json:"swap"`
	RootFS fsUsage `json:"rootfs"` // Proxmox VE
	Root   fsUsage `json:"root"`   // PBS
	Uptime num     `json:"uptime"`
}

type fsUsage struct {
	Total num `json:"total"`
	Used  num `json:"used"`
	Avail num `json:"avail"`
	Free  num `json:"free"`
}

// nodeServices: cpu, load, mem, swap und fs:/ aus dem Node-Status.
func nodeServices(st nodeStatus) []model.Service {
	var out []model.Service
	cpus := float64(st.CPUInfo.CPUs)
	cpu := model.Service{Key: "cpu", Name: "CPU", Kind: "cpu", Default: true,
		Metrics: []model.Metric{{Name: "util", Value: round2(float64(st.CPU) * 100), Unit: "%", Rule: model.RuleCPU},
			{Name: "iowait", Value: round2(float64(st.Wait) * 100), Unit: "%"}}}
	if cpus > 0 {
		cpu.Text = fmt.Sprintf("%.0f Kerne", cpus)
	}
	out = append(out, cpu)
	if len(st.LoadAvg) >= 3 {
		l1, l5, l15 := float64(st.LoadAvg[0]), float64(st.LoadAvg[1]), float64(st.LoadAvg[2])
		s := model.Service{Key: "load", Name: "Load", Kind: "load", Default: true,
			Metrics: []model.Metric{{Name: "l1", Value: l1}, {Name: "l5", Value: l5}, {Name: "l15", Value: l15}},
			Text:    fmt.Sprintf("%.2f %.2f %.2f", l1, l5, l15)}
		if cpus > 0 {
			s.Metrics = append(s.Metrics, model.Metric{Name: "per_core", Value: round2(l5 / cpus), Rule: model.RuleLoad})
		}
		out = append(out, s)
	}
	if tot := float64(st.Memory.Total); tot > 0 {
		used := min(float64(st.Memory.Used), tot)
		out = append(out, model.Service{Key: "mem", Name: "RAM", Kind: "mem", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(used, tot), Unit: "%", Rule: model.RuleMem, Max: tot},
				{Name: "avail", Value: tot - used, Unit: "B"}},
			Text: fmt.Sprintf("%s von %s frei", bytesText(tot-used), bytesText(tot))})
	}
	if tot := float64(st.Swap.Total); tot > 0 {
		out = append(out, model.Service{Key: "swap", Name: "Swap", Kind: "swap", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(min(float64(st.Swap.Used), tot), tot), Unit: "%", Rule: model.RuleSwap, Max: tot}}})
	}
	fs := st.RootFS
	if fs.Total <= 0 {
		fs = st.Root
	}
	if tot := float64(fs.Total); tot > 0 {
		avail := float64(fs.Avail)
		if avail <= 0 {
			avail = float64(fs.Free)
		}
		used := float64(fs.Used)
		out = append(out, model.Service{Key: "fs:/", Name: "Dateisystem /", Kind: "fs", Default: true,
			Metrics: []model.Metric{{Name: "used", Value: pct(used, used+avail), Unit: "%", Rule: model.RuleFS, Max: tot}, // wie df
				{Name: "free", Value: avail, Unit: "B", Max: tot}},
			Text: fmt.Sprintf("%s von %s frei", bytesText(avail), bytesText(tot))})
	}
	return out
}

// aptUpdate ist ein Eintrag aus /nodes/{node}/apt/update (Proxmox VE und PBS gleich).
type aptUpdate struct {
	Package    string `json:"Package"`
	Version    string `json:"Version"`
	OldVersion string `json:"OldVersion"`
	Origin     string `json:"Origin"`
	Label      string `json:"Label"`
	Section    string `json:"Section"`
	Title      string `json:"Title"`
}

// updatesService: ausstehende Updates. Sicherheitsupdates nur, wenn erkennbar (Herkunft/Label/Bereich mit
// "security"); die API von Proxmox nennt das Archiv nicht immer, dann gibt es keine Angabe statt einer falschen 0.
func updatesService(list []aptUpdate) model.Service {
	sec := 0
	var names []string
	for _, u := range list {
		for _, f := range []string{u.Origin, u.Label, u.Section, u.Title} {
			if strings.Contains(strings.ToLower(f), "security") {
				sec++
				break
			}
		}
		names = append(names, u.Package)
	}
	s := model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true,
		Metrics: []model.Metric{{Name: "pending", Value: float64(len(list))}}}
	switch {
	case len(list) == 0:
		s.Text = "keine ausstehend"
	case sec > 0:
		s.Text = fmt.Sprintf("%d verfügbar, %d Sicherheitsupdates: %s", len(list), sec, strings.Join(limitList(names, 5), ", "))
	default:
		s.Text = fmt.Sprintf("%d verfügbar: %s", len(list), strings.Join(limitList(names, 5), ", "))
	}
	if sec > 0 {
		s.Metrics = append(s.Metrics, model.Metric{Name: "security", Value: float64(sec)})
		s.Facts = append(s.Facts, model.Fact{Code: "updates_security", Text: fmt.Sprintf("%d Sicherheitsupdates", sec)})
	}
	return s
}

// diskEntry ist ein Eintrag aus /nodes/{node}/disks/list (Proxmox VE: type/health, PBS: disk-type/status).
// wearout ist bei beiden die verbleibende Lebensdauer in % (100 = neu).
type diskEntry struct {
	DevPath  string `json:"devpath"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	DiskType string `json:"disk-type"`
	Model    string `json:"model"`
	Serial   string `json:"serial"`
	Size     num    `json:"size"`
	Health   string `json:"health"`
	Status   string `json:"status"`
	Wearout  optNum `json:"wearout"`
	Used     string `json:"used"`
	WWN      string `json:"wwn"`
}

func (d diskEntry) dev() string {
	if d.Name != "" {
		return d.Name
	}
	return strings.TrimPrefix(d.DevPath, "/dev/")
}

func (d diskEntry) kind() string { return strings.ToLower(firstNonEmpty(d.Type, d.DiskType)) }

// serial ist die Seriennummer ohne Platzhalter ("unknown", "N/A" usw. -> leer).
func (d diskEntry) serial() string {
	s := strings.TrimSpace(d.Serial)
	switch strings.ToLower(s) {
	case "unknown", "n/a", "none", "-", "0":
		return ""
	}
	return s
}

func (d diskEntry) wwn() string {
	w := strings.TrimSpace(d.WWN)
	if strings.EqualFold(w, "unknown") {
		return ""
	}
	return w
}

// diskKeys vergibt die Dienst-Schluessel: Seriennummer, wenn sie eindeutig ist (gleiche Seriennummer mit gleicher
// WWN = Multipath, ein Dienst); sonst (fehlt, Platzhalter, zwei Platten mit derselben Nummer) die WWN bzw. der
// Geraetename, damit keine Platte eine andere verdeckt.
func diskKeys(list []diskEntry) []string {
	ids := map[string]map[string]bool{} // Seriennummer -> WWN (ohne WWN: Geraetename)
	for _, d := range list {
		s := d.serial()
		if s == "" {
			continue
		}
		if ids[s] == nil {
			ids[s] = map[string]bool{}
		}
		ids[s][firstNonEmpty(d.wwn(), "dev:"+d.dev())] = true
	}
	keys := make([]string, len(list))
	for i, d := range list {
		if s := d.serial(); s != "" && len(ids[s]) == 1 {
			keys[i] = "disk:" + s
			continue
		}
		keys[i] = "disk:" + firstNonEmpty(d.wwn(), d.dev())
	}
	return keys
}

// smartResp ist die Antwort von /nodes/{node}/disks/smart (Proxmox VE: health, type ata|text, text; PBS: status,
// wearout, NVMe-Werte als Attribute mit Name und Wert).
type smartResp struct {
	Health     string      `json:"health"`
	Status     string      `json:"status"`
	Type       string      `json:"type"`
	Text       string      `json:"text"`
	Wearout    optNum      `json:"wearout"`
	Attributes []smartAttr `json:"attributes"`
}

type smartAttr struct {
	ID    json.RawMessage `json:"id"`
	Name  string          `json:"name"`
	Raw   json.RawMessage `json:"raw"`
	Value json.RawMessage `json:"value"`
}

// smartData sind die ausgewerteten SMART-Werte einer Platte (nil = nicht bekannt).
type smartData struct {
	passed                                *bool
	temp, wearUsed                        *float64
	realloc, pending, uncorr, crc, mediaE *uint64
	critWarn                              *uint64
}

func (s *smartData) sectors() uint64 {
	n := uint64(0)
	for _, v := range []*uint64{s.realloc, s.pending, s.uncorr} {
		if v != nil {
			n += *v
		}
	}
	return n
}

// healthOf wertet den SMART-Gesamtstatus aus. Proxmox VE reicht den Text von smartctl durch ("PASSED", "FAILED!",
// SAS: "OK" bzw. "FAILURE PREDICTION THRESHOLD EXCEEDED: ascq=…"), PBS liefert "passed"/"failed"/"unknown".
func healthOf(s string) *bool {
	u := strings.ToUpper(strings.TrimSpace(s))
	var b bool
	switch {
	case u == "":
		return nil
	case strings.Contains(u, "FAIL"):
		b = false
	case strings.HasPrefix(u, "PASSED"), u == "OK", strings.HasPrefix(u, "OK "), strings.HasPrefix(u, "OK,"):
		b = true
	default:
		return nil // UNKNOWN u. a.
	}
	return &b
}

// parseSmart wertet die SMART-Antwort aus (ATA-Attribute nach ID, NVMe-Werte aus dem Text bzw. benannten Attributen).
func parseSmart(r smartResp) smartData {
	var d smartData
	d.passed = healthOf(firstNonEmpty(r.Health, r.Status))
	setU := func(p **uint64, v uint64) {
		x := v
		*p = &x
	}
	setF := func(p **float64, v float64) {
		x := v
		*p = &x
	}
	text := map[string]string{} // NVMe: "Temperature" -> "38 Celsius"
	var temp190 *float64
	for _, a := range r.Attributes {
		id, idErr := strconv.Atoi(strings.TrimSpace(rawText(a.ID)))
		raw := rawText(a.Raw)
		if idErr != nil || id == 0 {
			if a.Name != "" {
				text[strings.ToLower(strings.TrimSpace(a.Name))] = firstNonEmpty(rawText(a.Value), raw)
			}
			continue
		}
		v, ok := leadingUint(raw)
		if !ok {
			continue
		}
		switch id {
		case 5:
			setU(&d.realloc, v)
		case 197:
			setU(&d.pending, v)
		case 198:
			setU(&d.uncorr, v)
		case 199:
			setU(&d.crc, v)
		case 194, 190:
			t := v
			if t > 255 { // Rohwert mit Min/Max in den oberen Bytes
				t &= 0xff
			}
			if t > 0 && t < 150 {
				if id == 194 {
					setF(&d.temp, float64(t))
				} else {
					setF(&temp190, float64(t))
				}
			}
		}
	}
	if d.temp == nil {
		d.temp = temp190
	}
	for _, line := range strings.Split(r.Text, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			text[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	// NVMe: Text von smartctl ("Critical Warning: 0x04", hex) bzw. Schluessel aus dem JSON von smartctl, wie PBS sie
	// als Attributnamen liefert ("critical_warning": 4, dezimal).
	if v, ok := text["critical warning"]; ok {
		if n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(strings.Fields(v + " x")[0]), "0x"), 16, 64); err == nil {
			setU(&d.critWarn, n)
		}
	} else if v, ok := text["critical_warning"]; ok {
		f := strings.ToLower(strings.Fields(v + " x")[0])
		var n uint64
		var err error
		if h, isHex := strings.CutPrefix(f, "0x"); isHex {
			n, err = strconv.ParseUint(h, 16, 64)
		} else {
			n, err = strconv.ParseUint(f, 10, 64)
		}
		if err == nil {
			setU(&d.critWarn, n)
		}
	}
	if v, ok := firstText(text, "temperature"); ok && d.temp == nil {
		if n, ok := leadingUint(v); ok && n > 0 && n < 150 {
			setF(&d.temp, float64(n))
		}
	}
	if v, ok := firstText(text, "percentage used", "percentage_used"); ok {
		if n, ok := leadingUint(v); ok {
			setF(&d.wearUsed, float64(n))
		}
	}
	if v, ok := firstText(text, "media and data integrity errors", "media_errors"); ok {
		if n, ok := leadingUint(strings.ReplaceAll(v, ",", "")); ok {
			setU(&d.mediaE, n)
		}
	}
	if d.wearUsed == nil && r.Wearout.Set {
		setF(&d.wearUsed, 100-r.Wearout.V)
	}
	return d
}

// firstText liefert den ersten vorhandenen Eintrag zu einem der Namen.
func firstText(m map[string]string, names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := m[n]; ok {
			return v, true
		}
	}
	return "", false
}

// diskService baut den Dienst einer Platte (Schluessel aus diskKeys) aus disks/list und SMART. prevSectors haelt die
// Sektoren der vorigen SMART-Abfrage je Schluessel (steigen -> smart_sectors_rising) und wird aktualisiert.
func diskService(key string, d diskEntry, sm *smartData, smartErr bool, prevSectors map[string]uint64) model.Service {
	name := d.dev()
	if d.Model != "" {
		name += " (" + strings.TrimSpace(d.Model) + ")"
	}
	s := model.Service{Key: key, Name: name, Kind: "disk", Default: true}
	if sm == nil {
		sm = &smartData{}
	}
	if sm.passed == nil {
		sm.passed = healthOf(firstNonEmpty(d.Health, d.Status))
	}
	if sm.wearUsed == nil && d.Wearout.Set {
		w := 100 - d.Wearout.V
		sm.wearUsed = &w
	}
	var parts []string
	switch {
	case sm.passed != nil && *sm.passed:
		parts = append(parts, "SMART ok")
	case sm.passed != nil:
		parts = append(parts, "SMART FAILED")
		s.Facts = append(s.Facts, model.Fact{Code: "smart_failed", Text: "Gesamtstatus FAILED"})
	case smartErr:
		parts = append(parts, "SMART nicht lesbar")
	}
	if sm.temp != nil {
		rule := model.RuleDiskTemp
		if d.kind() == "nvme" || strings.Contains(d.DevPath, "nvme") {
			rule = model.RuleNVMeTemp
		}
		s.Metrics = append(s.Metrics, model.Metric{Name: "temp", Value: round2(*sm.temp), Unit: "°C", Rule: rule})
		parts = append(parts, fmt.Sprintf("%.0f °C", *sm.temp))
	}
	if sm.wearUsed != nil && d.kind() != "hdd" {
		// ueber 100 % (NVMe "Percentage Used" bis 255, Proxmox-wearout negativ): verbraucht, also 100
		w := min(max(*sm.wearUsed, 0), 100)
		s.Metrics = append(s.Metrics, model.Metric{Name: "wear", Value: round2(w), Unit: "%", Rule: model.RuleWear})
		parts = append(parts, fmt.Sprintf("Verschleiß %.0f %%", w))
	}
	addCounter := func(name string, v *uint64) {
		if v != nil {
			s.Metrics = append(s.Metrics, model.Metric{Name: name, Value: float64(*v)})
		}
	}
	addCounter("realloc", sm.realloc)
	addCounter("pending", sm.pending)
	addCounter("uncorr", sm.uncorr)
	addCounter("crc", sm.crc)
	addCounter("media_err", sm.mediaE)
	if sec := sm.sectors(); sec > 0 {
		code := "smart_sectors"
		if p, ok := prevSectors[key]; ok && p < sec {
			code = "smart_sectors_rising"
		}
		s.Facts = append(s.Facts, model.Fact{Code: code, Text: fmt.Sprintf("%d umgelegte/ausstehende Sektoren", sec)})
		parts = append(parts, fmt.Sprintf("%d Sektoren", sec))
	}
	if sm.realloc != nil || sm.pending != nil || sm.uncorr != nil {
		prevSectors[key] = sm.sectors()
	}
	if sm.mediaE != nil && *sm.mediaE > 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "smart_sectors", Text: fmt.Sprintf("%d Medienfehler", *sm.mediaE)})
	}
	if sm.critWarn != nil && *sm.critWarn != 0 {
		s.Facts = append(s.Facts, model.Fact{Code: "smart_failed", Text: fmt.Sprintf("NVMe-Warnung 0x%x", *sm.critWarn)})
	}
	if d.Size > 0 {
		parts = append([]string{bytesText(float64(d.Size))}, parts...)
	}
	s.Text = strings.Join(parts, " · ")
	return s
}

// authErr: Fehler, die nicht an einer einzelnen Platte liegen (Token, Rechte) – als Teilfehler melden.
func authErr(err error) bool {
	return errors.Is(err, proxmox.ErrToken) || errors.Is(err, proxmox.ErrPermission)
}
