package m64linux

import (
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// ParseBonding liest /proc/net/bonding/<name>.
func ParseBonding(name string, b []byte) (*m64proto.Bond, error) {
	bd := &m64proto.Bond{Name: name, Members: []m64proto.BondSlave{}}
	var cur *m64proto.BondSlave
	inActiveAgg := false
	found := false
	for _, raw := range lines(b) {
		k, v, ok := strings.Cut(raw, ":")
		if !ok {
			continue
		}
		indented := strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "Slave Interface" {
			if len(bd.Members) >= 64 {
				cur = nil
				continue
			}
			bd.Members = append(bd.Members, m64proto.BondSlave{Name: clip(v)})
			cur = &bd.Members[len(bd.Members)-1]
			inActiveAgg = false
			continue
		}
		if cur == nil {
			switch k {
			case "Bonding Mode":
				bd.Mode = clip(v)
				found = true
			case "MII Status":
				if !indented {
					bd.MII = clip(v)
				}
			case "Active Aggregator Info":
				inActiveAgg = true
			case "Aggregator ID":
				if inActiveAgg {
					bd.AggregateID, _ = strconv.Atoi(v)
				}
			case "Partner Mac Address":
				if inActiveAgg {
					bd.PartnerMAC = clip(v)
				}
			}
			continue
		}
		if indented { // "details actor lacp pdu" usw.
			continue
		}
		switch k {
		case "MII Status":
			cur.MII = clip(v)
		case "Speed":
			if f := strings.Fields(v); len(f) > 0 {
				cur.SpeedMbit, _ = strconv.Atoi(f[0])
			}
		case "Aggregator ID":
			cur.AggregateID, _ = strconv.Atoi(v)
		case "Link Failure Count":
			cur.LinkFailures, _ = strconv.Atoi(v)
		}
	}
	if !found {
		return nil, errFormat
	}
	return bd, nil
}

// readBonds liest alle Bonds aus /proc/net/bonding.
func readBonds(src source) ([]m64proto.Bond, []error) {
	var out []m64proto.Bond
	var errs []error
	for _, n := range src.ReadDir("/proc/net/bonding") {
		b, err := src.ReadFile("/proc/net/bonding/" + n)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		bd, err := ParseBonding(n, b)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, *bd)
		if len(out) >= 64 {
			break
		}
	}
	return out, errs
}
