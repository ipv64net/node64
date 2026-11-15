package dnsserver

import (
	"net/netip"

	"github.com/miekg/dns"
)

// Schutz vor DNS-Rebinding: Eine Antwort aus dem Internet darf fuer einen oeffentlichen Namen keine Adresse aus dem
// eigenen Netz liefern (privat, ULA, Loopback, Link-Local) - sonst kann eine Webseite ueber einen eigenen Namen den
// Browser an Router, NAS oder Kamera im Heimnetz schicken. Solche A/AAAA fallen aus der Antwort (bleibt nichts uebrig:
// leere Antwort). Nicht betroffen: eigene Eintraege, Zonen, lokale Namen und eigene Weiterleitungen (die antworten
// vorher) sowie Namen, fuer die Rebind false liefert (Freigaben, ipv64-Domains ...). 0.0.0.0 und :: bleiben (so
// sperren viele Upstreams).

// ReasonRebind: Adressen aus dem eigenen Netz aus der Antwort entfernt.
const ReasonRebind = "rebind"

// RebindFunc: true = der Schutz gilt fuer name (nil = Schutz aus).
type RebindFunc func(name string) bool

// homeAddr: Adresse, die nur im eigenen Netz gilt.
func homeAddr(a netip.Addr) bool {
	a = a.Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast()
}

// rebound entfernt A/AAAA mit Adressen aus dem eigenen Netz; true = es gab welche (resp bleibt unveraendert).
func rebound(resp *dns.Msg) (*dns.Msg, bool) {
	home := func(rr dns.RR) bool {
		var ip []byte
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			return false
		}
		a, ok := netip.AddrFromSlice(ip)
		return ok && homeAddr(a)
	}
	hit := false
	for _, rr := range append(resp.Answer[:len(resp.Answer):len(resp.Answer)], resp.Extra...) {
		if home(rr) {
			hit = true
			break
		}
	}
	if !hit {
		return resp, false
	}
	m := resp.Copy()
	keep := func(in []dns.RR) []dns.RR {
		out := in[:0]
		for _, rr := range in {
			if !home(rr) {
				out = append(out, rr)
			}
		}
		return out
	}
	m.Answer, m.Extra = keep(m.Answer), keep(m.Extra)
	return m, true
}
