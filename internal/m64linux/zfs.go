package m64linux

import (
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Befehl fuer die Pool-Liste (Agent und Skript).
var zpoolListArgs = []string{"list", "-Hp", "-o", "name,size,alloc,free,frag,health"}

// ParseZpoolList liest "zpool list -Hp -o name,size,alloc,free,frag,health" (Tab-getrennt, Bytes).
func ParseZpoolList(b []byte) []m64proto.ZPool {
	var out []m64proto.ZPool
	for _, ln := range lines(b) {
		f := strings.Split(ln, "\t")
		if len(f) < 6 {
			f = strings.Fields(ln)
		}
		if len(f) < 6 || f[0] == "" {
			continue
		}
		p := m64proto.ZPool{Name: clip(f[0]), Size: u64(f[1]), Alloc: u64(f[2]), Free: u64(f[3]), Health: clip(f[5])}
		if v, err := strconv.ParseFloat(strings.TrimSuffix(f[4], "%"), 64); err == nil && v >= 0 && v <= 100 {
			p.FragPct = v
		}
		out = append(out, p)
		if len(out) >= 64 {
			break
		}
	}
	return out
}

// ZpoolStatus sind die Angaben aus "zpool status" je Pool.
type ZpoolStatus struct {
	State  string
	Status string // Hinweistext bei Problemen ("One or more devices ...")
	Scan   string
	Errors string
}

// ParseZpoolStatus liest "zpool status" (ein oder mehrere Pools); Fortsetzungszeilen werden angehaengt.
func ParseZpoolStatus(b []byte) map[string]ZpoolStatus {
	out := map[string]ZpoolStatus{}
	var name string
	var st ZpoolStatus
	key := ""
	flush := func() {
		if name != "" && len(out) < 64 {
			st.Scan, st.Status, st.Errors = clip(st.Scan), clip(st.Status), clip(st.Errors)
			out[name] = st
		}
	}
	for _, ln := range lines(b) {
		t := strings.TrimSpace(ln)
		k, v, ok := strings.Cut(t, ":")
		if ok && k != "" && !strings.ContainsAny(k, " \t") {
			switch k {
			case "pool":
				flush()
				name, st, key = strings.TrimSpace(v), ZpoolStatus{}, ""
				continue
			case "state":
				st.State, key = strings.TrimSpace(v), ""
				continue
			case "status", "scan", "errors", "action", "see", "config", "remove":
				key = k
				v = strings.TrimSpace(v)
				switch k {
				case "status":
					st.Status = v
				case "scan":
					st.Scan = v
				case "errors":
					st.Errors = v
				}
				continue
			}
		}
		if t == "" {
			key = ""
			continue
		}
		if len(st.Scan) > 4*maxText || len(st.Status) > 4*maxText {
			continue
		}
		switch key {
		case "status":
			st.Status += " " + t
		case "scan":
			st.Scan += " " + t
		}
	}
	flush()
	return out
}

// mergeZpoolStatus traegt Fehlertext und Scrub in die Pools ein.
func mergeZpoolStatus(pools []m64proto.ZPool, st map[string]ZpoolStatus) {
	for i := range pools {
		s, ok := st[pools[i].Name]
		if !ok {
			continue
		}
		pools[i].Errors = s.Errors
		if s.Status != "" && pools[i].Health != "ONLINE" {
			pools[i].Errors = clip(s.Status + " " + s.Errors)
		}
		pools[i].ScanText = s.Scan
	}
}
