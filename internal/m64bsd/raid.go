package m64bsd

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// GEOM-Klassen fuer Software-RAID (Level im Bericht) und der sysctl, der zeigt, ob das Modul geladen ist (ohne
// Modul nichts aufrufen).
const (
	geomMirror = "gmirror"
	geomRAID   = "graid"
)

var geomSysctl = map[string]string{geomMirror: "kern.geom.mirror.debug", geomRAID: "kern.geom.raid.debug"}

var geomPctRE = regexp.MustCompile(`(\d+(?:\.\d+)?)\s*%`)

// Zustaende eines Mitglieds, die nicht "in Ordnung" sind (gmirror: SYNCHRONIZING, STALE, NEW, DISCONNECTED;
// graid: REBUILD, RESYNC, STALE, FAILED, OFFLINE, SPARE ...).
var geomBadWords = []string{"SYNCHRONIZING", "REBUILD", "RESYNC", "STALE", "FAILED", "OFFLINE", "NEW",
	"DISCONNECTED", "BROKEN", "DEGRADED", "SPARE", "NONE", "UNINITIALIZED"}

// ParseGeomStatus liest "gmirror status" bzw. "graid status" (auch mit -s: Name und Zustand in jeder Zeile).
//
//	      Name    Status  Components
//	mirror/gm0  DEGRADED  ada0 (ACTIVE)
//	                      ada1 (SYNCHRONIZING, 45%)
//
// State wie bei mdraid: active, degraded, recovering (Wiederaufbau mit SyncPercent), failed, starting.
func ParseGeomStatus(class string, b []byte) []m64proto.RAID {
	var out []m64proto.RAID
	idx := map[string]int{}
	cur := -1
	addMember := func(text string) {
		if cur < 0 {
			return
		}
		r := &out[cur]
		name, st, _ := strings.Cut(strings.TrimSpace(text), " ")
		if name == "" || len(r.Members) >= 64 {
			return
		}
		st = strings.TrimSpace(st)
		st = strings.TrimSuffix(strings.TrimPrefix(st, "("), ")")
		up := strings.ToUpper(st)
		r.Members = append(r.Members, clipN(name, 64))
		ok := strings.Contains(up, "ACTIVE")
		for _, w := range geomBadWords {
			if strings.Contains(up, w) {
				ok = false
				break
			}
		}
		// Reserve-Platten zaehlen nicht zum Soll (sonst hiesse ein gesundes Array mit Hot-Spare "weniger aktiv als Soll")
		switch {
		case ok:
			r.Active++
		case strings.Contains(up, "FAILED") || strings.Contains(up, "OFFLINE"):
			r.Failed++
		case strings.Contains(up, "SPARE"):
			r.Spare++
		}
		if ok || !strings.Contains(up, "SPARE") {
			r.Devices++
		}
		if m := geomPctRE.FindStringSubmatch(st); m != nil && r.SyncPercent == nil {
			if v, err := strconv.ParseFloat(m[1], 64); err == nil && v >= 0 && v <= 100 {
				r.SyncPercent = ptrF64(v)
			}
		}
	}
	for _, ln := range lines(b) {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		f := strings.Fields(ln)
		if f[0] == "Name" && len(f) >= 2 && f[1] == "Status" {
			continue
		}
		if ln[0] != ' ' && ln[0] != '\t' && len(f) >= 2 {
			name := f[0]
			if !strings.Contains(name, "/") || len(name) > 64 {
				cur = -1
				continue
			}
			i, ok := idx[name]
			if !ok {
				if len(out) >= 64 {
					cur = -1
					continue
				}
				out = append(out, m64proto.RAID{Name: clip(name), Level: class, State: strings.ToUpper(f[1])})
				i = len(out) - 1
				idx[name] = i
			}
			cur = i
			if len(f) >= 3 { // Rest hinter Name und Zustand ist das erste Mitglied
				t := strings.TrimSpace(strings.TrimSpace(ln)[len(f[0]):])
				addMember(t[len(f[1]):])
			}
			continue
		}
		addMember(ln)
	}
	for i := range out {
		out[i].State = geomState(out[i].State, out[i].SyncPercent != nil)
	}
	return out
}

// geomState uebersetzt den GEOM-Zustand in die Woerter von mdraid (die Regeln im Mapper kennen diese).
func geomState(s string, syncing bool) string {
	switch s {
	case "COMPLETE", "OPTIMAL":
		return "active"
	case "DEGRADED", "SUBOPTIMAL":
		if syncing {
			return "recovering"
		}
		return "degraded"
	case "BROKEN":
		return "failed"
	case "STARTING":
		return "starting"
	}
	return clipN(strings.ToLower(s), 20)
}
