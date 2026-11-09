package m64linux

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

var (
	hwTempRE = regexp.MustCompile(`^temp([0-9]+)_input$`)
	tripRE   = regexp.MustCompile(`^trip_point_([0-9]+)_type$`)
)

// milliC wandelt Milligrad in Grad; ok=false bei unplausiblen Werten (fehlender Sensor, -273, 255 ...).
func milliC(v int64) (float64, bool) {
	c := float64(v) / 1000
	if c <= -60 || c >= 200 {
		return 0, false
	}
	return c, true
}

func normSensor(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "-", "_")
}

type hwmonDev struct {
	dir, name, dev string
}

// readTemps liest hwmon und thermal_zone. Namen: "<hwmon-Name>/<Label oder tempN>"; gibt es einen hwmon-Namen
// mehrfach bzw. bei NVMe, kommt das Geraet dazu ("nvme@nvme1/Composite"). Thermal-Zonen nur, wenn es keinen
// gleichnamigen hwmon gibt (Pi: cpu_thermal bzw. cpu-thermal). drivetemp wird ausgelassen (koennte schlafende
// Platten wecken; Plattentemperatur kommt aus SMART).
func readTemps(src source) []m64proto.Temp {
	var devs []hwmonDev
	count := map[string]int{}
	for _, h := range src.ReadDir("/sys/class/hwmon") {
		if !strings.HasPrefix(h, "hwmon") {
			continue
		}
		base := "/sys/class/hwmon/" + h
		name := clip(readStr(src, base+"/name"))
		if name == "" {
			name = clip(readStr(src, base+"/device/name"))
		}
		if name == "" {
			name = h
		}
		if name == "drivetemp" {
			continue
		}
		devs = append(devs, hwmonDev{dir: base, name: name, dev: clip(linkBase(src, base+"/device"))})
		count[name]++
		if len(devs) >= 64 {
			break
		}
	}
	var out []m64proto.Temp
	used := map[string]int{}
	hwNames := map[string]bool{}
	add := func(t m64proto.Temp) {
		if n := used[t.Name]; n > 0 {
			used[t.Name]++
			t.Name += "#" + strconv.Itoa(n+1)
		} else {
			used[t.Name] = 1
		}
		if len(out) < maxItems {
			out = append(out, t)
		}
	}
	for _, d := range devs {
		hwNames[normSensor(d.name)] = true
		prefix := d.name
		if (count[d.name] > 1 || d.name == "nvme") && d.dev != "" { // nvme immer mit Geraet: Name bleibt bei weiterer Platte
			prefix += "@" + d.dev
		}
		var idx []int
		for _, f := range src.ReadDir(d.dir) {
			if m := hwTempRE.FindStringSubmatch(f); m != nil {
				if n, err := strconv.Atoi(m[1]); err == nil {
					idx = append(idx, n)
				}
			}
		}
		sort.Ints(idx)
		for _, n := range idx {
			p := d.dir + "/temp" + strconv.Itoa(n)
			v, ok := readInt(src, p+"_input")
			if !ok {
				continue
			}
			c, ok := milliC(v)
			if !ok {
				continue
			}
			label := clip(readStr(src, p+"_label"))
			key := label
			if key == "" {
				key = "temp" + strconv.Itoa(n)
			}
			t := m64proto.Temp{Name: prefix + "/" + key, Label: label, C: c}
			if v, ok := readInt(src, p+"_max"); ok {
				if x, ok := milliC(v); ok && x > 0 {
					t.High = ptrF64(x)
				}
			}
			if v, ok := readInt(src, p+"_crit"); ok {
				if x, ok := milliC(v); ok && x > 0 {
					t.Crit = ptrF64(x)
				}
			}
			add(t)
		}
	}
	for _, z := range src.ReadDir("/sys/class/thermal") {
		if !strings.HasPrefix(z, "thermal_zone") {
			continue
		}
		base := "/sys/class/thermal/" + z
		typ := clip(readStr(src, base+"/type"))
		if typ == "" {
			typ = z
		}
		if hwNames[normSensor(typ)] {
			continue
		}
		v, ok := readInt(src, base+"/temp")
		if !ok {
			continue
		}
		c, ok := milliC(v)
		if !ok {
			continue
		}
		t := m64proto.Temp{Name: "thermal/" + typ, Label: typ, C: c}
		for _, f := range src.ReadDir(base) {
			m := tripRE.FindStringSubmatch(f)
			if m == nil || readStr(src, base+"/"+f) != "critical" {
				continue
			}
			if v, ok := readInt(src, base+"/trip_point_"+m[1]+"_temp"); ok {
				if x, ok := milliC(v); ok && x > 0 {
					t.Crit = ptrF64(x)
				}
			}
		}
		add(t)
	}
	return out
}
