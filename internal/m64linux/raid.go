package m64linux

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

var (
	mdHeadRE   = regexp.MustCompile(`^(md[A-Za-z0-9_]+)\s*:\s*(.*)$`)
	mdCountRE  = regexp.MustCompile(`\[(\d+)/(\d+)\]\s*\[([U_]+)\]`)
	mdSyncRE   = regexp.MustCompile(`\b(resync|recovery|reshape|check|repair)\s*=\s*([0-9.]+)%`)
	mdDelayRE  = regexp.MustCompile(`\b(resync|recovery|reshape|check|repair)\s*=\s*(DELAYED|PENDING)`)
	mdMemberRE = regexp.MustCompile(`^([^\[\s]+)\[\d+\]((?:\([A-Z]\))*)$`)
)

// ParseMdstat liest /proc/mdstat.
//
// State: active, degraded (weniger aktive als Soll), recovering (Wiederaufbau), resyncing (resync/reshape),
// failed (inactive). Pruefung (check/repair) laesst den Zustand stehen und setzt nur SyncPercent.
func ParseMdstat(b []byte) []m64proto.RAID {
	var out []m64proto.RAID
	var cur *m64proto.RAID
	for _, ln := range lines(b) {
		if m := mdHeadRE.FindStringSubmatch(ln); m != nil {
			if len(out) >= 64 {
				cur = nil
				continue
			}
			out = append(out, parseMdHead(m[1], m[2]))
			cur = &out[len(out)-1]
			continue
		}
		if cur == nil {
			continue
		}
		t := strings.TrimSpace(ln)
		if t == "" {
			cur = nil
			continue
		}
		if m := mdCountRE.FindStringSubmatch(t); m != nil {
			cur.Devices, _ = strconv.Atoi(m[1])
			cur.Active, _ = strconv.Atoi(m[2])
			if cur.State == "active" && (cur.Active < cur.Devices || strings.Contains(m[3], "_")) {
				cur.State = "degraded"
			}
		}
		if m := mdSyncRE.FindStringSubmatch(t); m != nil {
			if p, err := strconv.ParseFloat(m[2], 64); err == nil && p >= 0 && p <= 100 {
				cur.SyncPercent = ptrF64(p)
			}
			setSyncState(cur, m[1])
		} else if m := mdDelayRE.FindStringSubmatch(t); m != nil {
			setSyncState(cur, m[1])
		}
	}
	for i := range out {
		r := &out[i]
		if r.Devices == 0 && r.State != "failed" { // raid0/linear: keine [n/m]-Angabe
			r.Devices = len(r.Members) - r.Spare
			r.Active = r.Devices - r.Failed
			if r.Failed > 0 {
				r.State = "failed"
			}
		}
	}
	return out
}

func setSyncState(r *m64proto.RAID, kind string) {
	if r.State == "failed" {
		return
	}
	switch kind {
	case "recovery":
		r.State = "recovering"
	case "resync", "reshape":
		r.State = "resyncing"
	}
}

// parseMdHead liest "active raid1 sdb1[1] sda1[0](F)" bzw. "inactive sdc1[0](S)".
func parseMdHead(name, rest string) m64proto.RAID {
	r := m64proto.RAID{Name: name, State: "active"}
	for _, tok := range strings.Fields(rest) {
		switch {
		case tok == "active":
		case tok == "inactive":
			r.State = "failed"
		case strings.HasPrefix(tok, "(") && strings.HasSuffix(tok, ")"): // (auto-read-only), (read-only)
		case strings.HasPrefix(tok, "raid") || tok == "linear" || tok == "multipath" || tok == "faulty":
			r.Level = tok
		default:
			m := mdMemberRE.FindStringSubmatch(tok)
			if m == nil {
				continue
			}
			switch {
			case strings.Contains(m[2], "(F)"):
				r.Failed++
			case strings.Contains(m[2], "(S)"):
				r.Spare++
			}
			if len(r.Members) < 64 {
				r.Members = append(r.Members, clip(m[1]))
			}
		}
	}
	if r.State == "failed" {
		r.Devices = len(r.Members)
	}
	return r
}
