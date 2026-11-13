package snmp

import (
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// IEEE8023-LAG-MIB: Aggregatoren (dot3adAggTable) und ihre Ports (dot3adAggPortTable). Indizes sind ifIndex.
const (
	lagAggMAC        = ".1.2.840.10006.300.43.1.1.1.1.2"  // dot3adAggMACAddress (je Aggregator)
	lagPortPartnerID = ".1.2.840.10006.300.43.1.2.1.1.9"  // dot3adAggPortPartnerOperSystemID
	lagPortPartnerK  = ".1.2.840.10006.300.43.1.2.1.1.11" // dot3adAggPortPartnerOperKey
	lagPortSelected  = ".1.2.840.10006.300.43.1.2.1.1.12" // dot3adAggPortSelectedAggID
	lagPortAttached  = ".1.2.840.10006.300.43.1.2.1.1.13" // dot3adAggPortAttachedAggID
)

// collectLAG: je Aggregator ein Dienst bond:<ifName> wie im Mapper (Mitglied down, LACP-Partner passt nicht).
func (c *Collector) collectLAG(r *round) {
	if c.isAbsent("lag", r.now) || c.ifStatic == nil {
		return
	}
	if !r.ifOK { // Portstatus dieser Runde fehlt (IF-MIB-Teilfehler meldet "bond:"): nicht mit altem Stand rechnen
		return
	}
	t, err := walkColumns(r.ctx, r.c, []string{lagAggMAC, lagPortSelected, lagPortAttached, lagPortPartnerID, lagPortPartnerK}, c.cfg.MaxRep)
	if emptyTable(t, err) { // Geraet ohne LAG-MIB: nicht vorhanden statt Teilfehler
		c.markAbsent("lag", r.now, true)
		return
	}
	if err != nil {
		r.part.add("LAG-MIB", err, "bond:")
		return
	}
	c.markAbsent("lag", r.now, len(t.col(lagPortSelected)) == 0 && len(t.col(lagAggMAC)) == 0)
	type member struct {
		idx, name, partner string
		up                 bool
	}
	aggs := map[string][]member{}
	for idx := range t.col(lagAggMAC) {
		aggs[idx] = nil
	}
	for _, idx := range t.rows() {
		sel, ok1 := num(t.col(lagPortSelected)[idx])
		att, ok2 := num(t.col(lagPortAttached)[idx])
		agg := ""
		switch {
		case ok1 && sel > 0:
			agg = strconv.Itoa(int(sel))
		case ok2 && att > 0:
			agg = strconv.Itoa(int(att))
		}
		if agg == "" {
			continue
		}
		pk, _ := num(t.col(lagPortPartnerK)[idx])
		partner := ""
		if b := rawBytes(t.col(lagPortPartnerID)[idx]); len(b) > 0 && !allZero(b) {
			partner = hex.EncodeToString(b) + "/" + strconv.Itoa(int(pk))
		}
		name := idx
		if in, ok := c.ifStatic[idx]; ok {
			name = in.name
		}
		aggs[agg] = append(aggs[agg], member{idx: idx, name: name, partner: partner,
			up: ok2 && strconv.Itoa(int(att)) == agg && c.ifUpNow[idx]})
	}
	ids := make([]string, 0, len(aggs))
	for id := range aggs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		ms := aggs[id]
		if len(ms) == 0 {
			continue // Aggregator ohne Mitglieder (auf Switches oft vorab angelegt)
		}
		name := "Po" + id
		if in, ok := c.ifStatic[id]; ok {
			name = in.name
		}
		s := model.Service{Key: "bond:" + keyPart(name), Name: model.Raw(name) + " (LACP)", Kind: "bond", Default: true}
		up := 0
		var down []string
		partners := map[string][]string{}
		for _, m := range ms {
			if m.up {
				up++
				if m.partner != "" {
					partners[m.partner] = append(partners[m.partner], m.name)
				}
			} else {
				down = append(down, m.name)
			}
		}
		s.Metrics = []model.Metric{{Name: "members_up", Value: float64(up)}, {Name: "members", Value: float64(len(ms))}}
		s.Text = model.T("monitor64.txt.active_of", "n", up, "total", len(ms))
		if len(down) > 0 {
			list := model.Raw(strings.Join(limitList(down, 5), ", "))
			s.Facts = append(s.Facts, model.Fact{Code: factBondDown, Text: list + " down"})
			s.Text += " – " + list + " down"
		}
		if len(partners) > 1 { // aktive Mitglieder sprechen mit verschiedenen Partnern bzw. Schluesseln
			var minor []string
			best := 0
			for _, l := range partners {
				best = max(best, len(l))
			}
			for _, l := range partners {
				if len(l) < best {
					minor = append(minor, l...)
				}
			}
			if len(minor) == 0 { // gleich viele: alle nennen
				for _, l := range partners {
					minor = append(minor, l...)
				}
			}
			sort.Strings(minor)
			list := strings.Join(limitList(minor, 5), ", ")
			s.Facts = append(s.Facts, model.Fact{Code: factLACPMismatch, Text: model.T("monitor64.txt.lacp_other_partner", "list", list)})
			s.Text += " – " + model.T("monitor64.txt.lacp_mismatch", "list", list)
		}
		r.out = append(r.out, s)
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}
