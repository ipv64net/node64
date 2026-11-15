package ipam64

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
	"time"
)

// Dynamische IPv6-Praefixe (Plan Stufe I4): Ein Praefix vom Provider (z. B. /56) wird als dynamisch markiert
// (DynSource "auto"). Praefixe darin merken sich ihre Praefix-ID (DynParent, DynIndex: die Bits zwischen Wurzel und
// eigenem Praefix, hex), Adressen brauchen nichts: ihr Teil unterhalb der Wurzel bleibt. Wechselt der Provider das
// Praefix, hat die Node keine Adresse mehr darin, aber eine neue globale Adresse ausserhalb aller Praefixe. Passt sie
// (ueber die Praefix-ID eines Kindes) zu genau einer neuen Wurzel, nummeriert IPAM64 um: Wurzel, Kinder, Adressbereiche
// und Adressen bekommen den neuen oberen Teil, die AAAA-Eintraege in DNS64 folgen (gleicher Bezug). Der letzte Wechsel
// steht in der Uebersicht, samt Zielen anderer Module (PROXY64, Monitor64, Healthchecks), die noch auf das alte Praefix
// zeigen - die passt IPAM64 nicht selbst an (Hinweis, Empfehlung: Ziele per DNS-Name).
// Anker: Jede Node merkt sich (lokal, nicht im Cluster), in welchem Wert einer Wurzel sie zuletzt lag und auf welcher
// Schnittstelle. Umnummeriert wird nur, wenn die Node selbst im aktuellen Wert lag. Kam der Wechsel ueber den Cluster
// und hat die Node noch eine Adresse im alten Praefix, nummeriert sie so nicht zurueck (kein Hin und Her zwischen den
// Nodes). Als neue Adresse zaehlen nur Adressen auf der Schnittstelle des Ankers: eine globale Adresse von WireGuard,
// Docker oder einem zweiten Anschluss fuehrt weder zu "mehrdeutig" noch zu einem falschen Wechsel.
// Umnummeriert wird in einer Transaktion und mit eigenem Kontext (bricht die Anfrage ab, bleibt kein halber Stand).

// DynAuto: Praefix wechselt mit dem Provider, Quelle sind die Adressen der Node.
const DynAuto = "auto"

const (
	setDynLast   = "ipam64.dyn_last"   // letzter Wechsel (JSON DynChange)
	setDynAnchor = "ipam64.dyn_anchor" // je Node: Wurzel-UID -> Wert, in dem die Node zuletzt lag (JSON)
)

// ErrDyn: dynamisch geht nur fuer globale IPv6-Praefixe.
var ErrDyn = errors.New("ipam64: dynamic only for global ipv6 prefixes")

// DynChange ist ein erkannter Wechsel eines dynamischen Praefixes.
type DynChange struct {
	From      string    `json:"from"`
	To        string    `json:"to"`
	At        time.Time `json:"at"`
	Prefixes  int       `json:"prefixes"`
	Addresses int       `json:"addresses"`
}

// dynAnchor: Wert der Wurzel, in dem die Node zuletzt lag, und die Schnittstelle dazu.
type dynAnchor struct {
	Value string `json:"value"`
	Iface string `json:"iface,omitempty"`
}

// UnmarshalJSON liest auch die alte Form (nur der Wert als Text).
func (a *dynAnchor) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*a = dynAnchor{Value: s}
		return nil
	}
	type plain dynAnchor
	return json.Unmarshal(b, (*plain)(a))
}

// replaceTop setzt die oberen Bits von a (bis bits) aus to.
func replaceTop(a netip.Addr, to netip.Prefix) netip.Addr {
	b, t := a.As16(), to.Masked().Addr().As16()
	bits := to.Bits()
	for i := 0; i < 16; i++ {
		switch {
		case bits >= 8*(i+1):
			b[i] = t[i]
		case bits > 8*i:
			mask := byte(0xff << (8 - (bits - 8*i)))
			b[i] = t[i]&mask | b[i]&^mask
		}
	}
	return netip.AddrFrom16(b)
}

// dynIndex liefert die Praefix-ID eines Kindes (Bits zwischen Wurzel und Kind) als hex ("" = keine).
func dynIndex(root, child netip.Prefix) string {
	if child.Bits() <= root.Bits() {
		return ""
	}
	a := child.Masked().Addr().As16()
	n := child.Bits() - root.Bits()
	var v uint64
	for i := 0; i < n && i < 64; i++ {
		bit := root.Bits() + i
		v = v<<1 | uint64(a[bit/8]>>(7-bit%8)&1)
	}
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i], v = byte(v), v>>8
	}
	s := hex.EncodeToString(b)
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

// dynFields setzt DynParent/DynIndex eines Praefixes nach der dynamischen Wurzel, in der es liegt.
func dynFields(p *Prefix, all []Prefix) {
	p.DynParent, p.DynIndex = "", ""
	if p.DynSource == DynAuto || p.Family != 6 {
		return
	}
	pp, err := netip.ParsePrefix(p.Prefix)
	if err != nil {
		return
	}
	for _, r := range all {
		rp, err := netip.ParsePrefix(r.Prefix)
		if err == nil && r.DynSource == DynAuto && r.UID != p.UID && rp.Bits() < pp.Bits() && rp.Contains(pp.Addr()) {
			p.DynParent, p.DynIndex = r.UID, dynIndex(rp, pp)
		}
	}
}

// LastDynChange liefert den letzten erkannten Wechsel (nil = keiner).
func (m *Module) LastDynChange(ctx context.Context) *DynChange {
	var c DynChange
	if s := m.core.SettingOr(ctx, setDynLast, ""); s == "" || json.Unmarshal([]byte(s), &c) != nil {
		return nil
	}
	return &c
}

// CheckDynamic prueft die dynamischen Praefixe gegen die Adressen der Node und nummeriert bei einem Wechsel um.
func (m *Module) CheckDynamic(ctx context.Context) ([]DynChange, error) {
	all, err := m.Prefixes(ctx)
	if err != nil {
		return nil, err
	}
	var known []netip.Prefix
	for _, p := range all {
		if pp, err := netip.ParsePrefix(p.Prefix); err == nil {
			known = append(known, pp)
		}
	}
	var locals []local // globale IPv6-Adressen der Node
	for _, l := range m.locals() {
		if a := l.Addr(); a.Is6() && globalV6.Contains(a) {
			locals = append(locals, l)
		}
	}
	anchor := map[string]dynAnchor{}
	_ = json.Unmarshal([]byte(m.core.SettingOr(ctx, setDynAnchor, "{}")), &anchor)
	dirty := false
	setAnchor := func(uid string, v dynAnchor) {
		if anchor[uid] != v {
			anchor[uid], dirty = v, true
		}
	}
	defer func() {
		if dirty {
			if b, err := json.Marshal(anchor); err == nil {
				_ = m.core.SetSetting(ctx, setDynAnchor, string(b))
			}
		}
	}()
	var out []DynChange
	for _, r := range all {
		root, err := netip.ParsePrefix(r.Prefix)
		if err != nil || r.DynSource != DynAuto {
			continue
		}
		in, iface := false, ""
		for _, l := range locals {
			if root.Contains(l.Addr()) && !in {
				in, iface = true, l.Iface
			}
		}
		if in {
			setAnchor(r.UID, dynAnchor{root.String(), iface})
		}
		anc := anchor[r.UID]
		if in || len(locals) == 0 || anc.Value != root.String() {
			continue
		}
		var children []netip.Prefix // Kinder bis /64: legen fest, wo die Node darin liegen muss
		for _, k := range known {
			if k != root && k.Bits() <= 64 && root.Contains(k.Addr()) && k.Bits() > root.Bits() {
				children = append(children, k)
			}
		}
		cands := map[netip.Prefix]bool{}
		for _, l := range locals {
			if anc.Iface != "" && l.Iface != anc.Iface { // nur die Schnittstelle, auf der die Node in der Wurzel lag
				continue
			}
			a := l.Addr()
			free := true
			for _, k := range known {
				free = free && !k.Contains(a)
			}
			if !free {
				continue
			}
			nr := netip.PrefixFrom(a, root.Bits()).Masked()
			ok := len(children) == 0
			for _, c := range children {
				nc := netip.PrefixFrom(replaceTop(c.Addr(), nr), c.Bits())
				ok = ok || nc.Contains(a)
			}
			if ok {
				cands[nr] = true
			}
		}
		if len(cands) != 1 {
			continue
		}
		for nr := range cands {
			c, err := m.renumber(ctx, root, nr)
			if err != nil {
				return out, err
			}
			setAnchor(r.UID, dynAnchor{nr.String(), anc.Iface})
			out = append(out, c)
		}
	}
	return out, nil
}

// renumber verschiebt alles unter oldRoot nach newRoot (gleiche Laenge) in einer Transaktion und schreibt danach die
// Eintraege nach DNS64. Eigener Kontext: eine abgebrochene Anfrage ("Jetzt pruefen") laesst keinen halben Stand.
func (m *Module) renumber(ctx context.Context, oldRoot, newRoot netip.Prefix) (DynChange, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	c := DynChange{From: oldRoot.String(), To: newRoot.String(), At: m.now().UTC().Truncate(time.Second)}
	now, by := c.At, "dynamic"
	prefixes, err := m.Prefixes(ctx)
	if err != nil {
		return c, err
	}
	ranges, err := m.Ranges(ctx)
	if err != nil {
		return c, err
	}
	addrs, err := m.Addresses(ctx)
	if err != nil {
		return c, err
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer func() { _ = tx.Rollback() }()
	type change struct{ item, uid string }
	var changes []change
	for _, p := range prefixes {
		pp, err := netip.ParsePrefix(p.Prefix)
		if err != nil || !oldRoot.Contains(pp.Addr()) || pp.Bits() < oldRoot.Bits() {
			continue
		}
		p.Prefix = netip.PrefixFrom(replaceTop(pp.Addr(), newRoot), pp.Bits()).String()
		p.Updated, p.UpdatedBy = now, by
		if err := writePrefixOn(ctx, tx, p); err != nil {
			return c, err
		}
		changes = append(changes, change{ClusterItemPrefixes, p.UID})
		c.Prefixes++
	}
	for _, r := range ranges {
		a, err1 := netip.ParseAddr(r.Start)
		b, err2 := netip.ParseAddr(r.End)
		if err1 != nil || err2 != nil || !oldRoot.Contains(a) {
			continue
		}
		r.Start, r.End, r.Updated, r.UpdatedBy = replaceTop(a, newRoot).String(), replaceTop(b, newRoot).String(), now, by
		if err := writeRangeOn(ctx, tx, r); err != nil {
			return c, err
		}
		changes = append(changes, change{ClusterItemRanges, r.UID})
	}
	var moved []Address
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a.Address)
		if err != nil || !oldRoot.Contains(ip) {
			continue
		}
		a.Address, a.Updated, a.UpdatedBy = replaceTop(ip, newRoot).String(), now, by
		if err := writeAddressOn(ctx, tx, a); err != nil {
			return c, err
		}
		changes = append(changes, change{ClusterItemAddresses, a.UID})
		moved = append(moved, a)
		c.Addresses++
	}
	if err := tx.Commit(); err != nil {
		return c, err
	}
	for _, ch := range changes {
		m.changed(ctx, ch.item, ch.uid, false)
	}
	if snap, err := m.netView(ctx); err == nil {
		_ = m.batch(ctx, func(ctx context.Context) error {
			for _, a := range moved {
				if _, err := m.write(ctx, snap, a); err != nil {
					m.log.Warn("ipam64: dynamic prefix dns64", "address", a.Address, "err", err)
				}
			}
			return nil
		})
	}
	if b, err := json.Marshal(c); err == nil {
		_ = m.core.SetSetting(ctx, setDynLast, string(b))
	}
	m.log.Info("ipam64: ipv6 prefix changed", "from", c.From, "to", c.To, "prefixes", c.Prefixes, "addresses", c.Addresses)
	return c, nil
}

// StaleTargets liefert Ziele anderer Module (PROXY64, Monitor64, Healthchecks), die noch auf ein altes Praefix zeigen.
func (m *Module) StaleTargets(ctx context.Context, old string) []string {
	p, err := netip.ParsePrefix(old)
	if err != nil {
		return nil
	}
	var out []string
	for _, src := range m.sources {
		if src.key == SrcDHCP || src.key == SrcDNS {
			continue
		}
		for _, s := range src.f(ctx) {
			if ip, err := netip.ParseAddr(hostOf(s.Addr)); err == nil && p.Contains(ip) {
				label := s.Name
				if label == "" {
					label = s.Note
				}
				out = append(out, src.key+": "+label+" ("+s.Addr+")")
			}
		}
	}
	return out
}
