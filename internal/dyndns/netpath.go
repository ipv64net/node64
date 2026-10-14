package dyndns

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"time"
)

// Anschluss-Analyse: Ob der Anschluss hinter CGNAT oder DS-Lite liegt, laesst sich von innen nicht
// sicher sagen. Ein starkes Indiz sind die ersten Stationen auf dem Weg ins Internet: Provider-NAT
// nutzt 100.64.0.0/10, DS-Lite zeigt den Tunnel-Endpunkt aus 192.0.0.0/29 (meist 192.0.0.1).

const SetNetInfo = "dyndns.netinfo" // letzter Befund als JSON

var (
	cgnatRange  = netip.MustParsePrefix("100.64.0.0/10")
	dsliteRange = netip.MustParsePrefix("192.0.0.0/29")
)

// netInfo ist der Befund der letzten Analyse.
type netInfo struct {
	At   time.Time `json:"at"`
	Kind string    `json:"kind"` // "", cgnat, dslite
	Hop  string    `json:"hop"`  // verdaechtige Station
	Hops []string  `json:"hops"` // Stationen 1..n (leer = keine Antwort)
	Err  string    `json:"err,omitempty"`
}

// classifyHops sucht in den Stationen nach Provider-NAT bzw. DS-Lite.
func classifyHops(hops []netip.Addr) (kind string, hop netip.Addr) {
	for _, h := range hops {
		switch {
		case !h.IsValid():
		case dsliteRange.Contains(h):
			return "dslite", h
		case cgnatRange.Contains(h):
			return "cgnat", h
		}
	}
	return "", netip.Addr{}
}

// analyzePath verfolgt die ersten Stationen Richtung ipv4.ipv64.net und speichert den Befund.
func (m *Module) analyzePath(ctx context.Context) {
	info := netInfo{At: time.Now().UTC()}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", "ipv4.ipv64.net")
	if err != nil || len(ips) == 0 {
		info.Err = "dns"
	} else {
		tctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		hops, terr := m.trace(tctx, ips[0].Unmap(), 6)
		cancel()
		if terr != nil {
			info.Err = terr.Error()
		}
		k, h := classifyHops(hops)
		info.Kind = k
		if h.IsValid() {
			info.Hop = h.String()
		}
		for _, h := range hops {
			s := ""
			if h.IsValid() {
				s = h.String()
			}
			info.Hops = append(info.Hops, s)
		}
	}
	if info.Kind != "" {
		m.log.Info("connection looks like shared IPv4", "kind", info.Kind, "hop", info.Hop)
	}
	raw, _ := json.Marshal(info)
	_ = m.core.SetSetting(ctx, SetNetInfo, string(raw))
}

// lastNetInfo liest den letzten Befund.
func (m *Module) lastNetInfo(ctx context.Context) netInfo {
	var ni netInfo
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, SetNetInfo, "")), &ni)
	return ni
}
