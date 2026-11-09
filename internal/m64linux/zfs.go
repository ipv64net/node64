package m64linux

import (
	"fmt"
	"math"
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
	State     string
	Status    string // Hinweistext bei Problemen ("One or more devices ...")
	Scan      string
	Errors    string
	DevErrors [3]uint64 // hoechste Fehlerzaehler READ, WRITE, CKSUM aus der Geraetetabelle (config)
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
			if key != "config" { // Tabelle steht zwischen Leerzeilen
				key = ""
			}
			continue
		}
		if key == "config" {
			// NAME STATE READ WRITE CKSUM [Hinweis]; Kopf, Spares ("AVAIL") und Ueberschriften (logs, cache) fallen raus
			if f := strings.Fields(t); len(f) >= 5 && f[0] != "NAME" {
				for i := 0; i < 3; i++ {
					if n, ok := zfsCount(f[2+i]); ok && n > st.DevErrors[i] {
						st.DevErrors[i] = n
					}
				}
			}
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

// zfsCount liest einen Fehlerzaehler aus "zpool status" ("0", "12", "1.2K", "3M").
func zfsCount(s string) (uint64, bool) {
	mult := 1.0
	if n := len(s); n > 1 {
		switch s[n-1] {
		case 'K':
			mult = 1e3
		case 'M':
			mult = 1e6
		case 'G':
			mult = 1e9
		case 'T':
			mult = 1e12
		}
		if mult > 1 {
			s = s[:n-1]
		}
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || v < 0 || v > 1e15 || math.IsNaN(v) {
		return 0, false
	}
	return uint64(v * mult), true
}

// MergeZpoolStatus traegt Fehlertext und Scrub in die Pools ein. Errors bleibt "No known data errors", solange
// weder Datenfehler noch Geraetefehler (READ/WRITE/CKSUM > 0) vorliegen; sonst steht dort ein Kurztext - auch bei
// ONLINE (ZFS korrigiert Pruefsummenfehler und bleibt ONLINE).
func MergeZpoolStatus(pools []m64proto.ZPool, st map[string]ZpoolStatus) {
	for i := range pools {
		s, ok := st[pools[i].Name]
		if !ok {
			continue
		}
		errs := s.Errors
		if d := s.DevErrors; d != [3]uint64{} {
			dev := fmt.Sprintf("Geraetefehler READ %d WRITE %d CKSUM %d", d[0], d[1], d[2])
			if errs == "" {
				errs = dev
			} else {
				errs += "; " + dev
			}
		}
		pools[i].Errors = clip(errs)
		if s.Status != "" && pools[i].Health != "ONLINE" {
			pools[i].Errors = clip(s.Status + " " + errs)
		}
		pools[i].ScanText = s.Scan
	}
}
