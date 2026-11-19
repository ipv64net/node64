package ipam64

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// Verbindung zu DNS64 (Plan docs/PLAN-NODE64-IPAM64.md, Stufe I3, Entscheidung E1): IPAM64 schreibt feste Eintraege
// gekennzeichnet nach DNS64 (Bezug = uid der Adresse). Je Adresse:
//   - DHCP an, MAC, IPv4, nicht veraltet: Reservierung im DHCP-Netz, in dem die Adresse liegt.
//   - sonst, wenn die Adresse (aktiv oder reserviert) im DHCP-Adressbereich liegt: Ausnahme (nie vergeben).
//   - DNS an, Rechnername, Zone (an der Adresse, sonst am Praefix bzw. DHCP-Netz), nicht veraltet: A bzw. AAAA, PTR
//     nach Schalter.
//
// Gespeichert wird zuerst in IPAM64, dann in DNS64. Vorher prueft DNS64 die ganze Adresse ohne zu schreiben (Check);
// scheitert DNS64 trotzdem (z. B. MAC schon vergeben, CNAME auf dem Namen), wird die Aenderung in IPAM64 zurueckgenommen
// und der alte Stand nach DNS64 zurueckgeschrieben - ein dabei uebernommener Eintrag von Hand wird freigegeben, nicht
// geloescht. Uebernahmen aus dem Cluster schreiben nichts (die Eintraege kommen ueber den Abgleich von DNS64); der
// Abgleich-Job (alle 10 Minuten) repariert nur Adressen, die seit settleFor unveraendert sind. Verwaiste Eintraege
// loescht er erst, wenn sie in zwei Laeufen hintereinander verwaist sind (so pendelt im Cluster nichts, wenn Eintraege
// in anderer Reihenfolge ankommen), sofort nur, wenn eine Adresse in IPAM64 ihren Platz braucht (gleiche Adresse auf
// zwei Nodes, siehe clusterDouble) - und nie, solange andere Nodes DNS64 abgleichen, aber nicht die Adressen von
// IPAM64 (deren Eintraege kennt diese Node nicht). An DNS64 uebergebene Adressen (Released) schreibt IPAM64 nicht
// mehr; findet der Abgleich dazu noch gekennzeichnete Eintraege (Uebergabe auf einer anderen Node), gibt er sie frei.

const (
	reconcileEvery = 10 * time.Minute
	settleFor      = 5 * time.Minute
)

// ErrNoZone: DNS an, aber keine Zone (weder an der Adresse noch am Praefix).
var ErrNoZone = errors.New("ipam64: no dns zone")

// OwnedRes, OwnedExcl, OwnedRec sind Eintraege in DNS64, die IPAM64 besitzt (Ref = uid der Adresse).
type OwnedRes struct{ Ref, MAC, IP, Name string }

type OwnedExcl struct{ Ref, IP string }

type OwnedRec struct {
	Ref, Name, Type, Value string
	NoPTR                  bool
}

// Owned ist alles, was IPAM64 in DNS64 besitzt.
type Owned struct {
	Reservations []OwnedRes
	Excludes     []OwnedExcl
	Records      []OwnedRec
}

// DNS64 verbindet IPAM64 mit DNS64 (cmd/node64/ipam.go). Running false bzw. nil = DNS64 laeuft nicht (nichts wird
// geschrieben; der Abgleich holt es nach).
type DNS64 struct {
	Running           func() bool
	PutReservation    func(ctx context.Context, ref, mac, ip, name string) error
	DeleteReservation func(ctx context.Context, ref string) error
	PutExclude        func(ctx context.Context, ref, ip, comment string) error
	DeleteExclude     func(ctx context.Context, ref string) error
	PutRecords        func(ctx context.Context, ref, name string, addrs []netip.Addr, ptr bool) (claimed bool, err error)
	DeleteRecords     func(ctx context.Context, ref string) error
	Release           func(ctx context.Context, ref string) (int64, error)
	Entries           func(ctx context.Context) (Owned, error)
	Unowned           func(ctx context.Context) (Owned, error) // Eintraege von Hand (Assistent; Ref leer)
	ErrKey            func(err error) string                   // i18n-Schluessel eines Fehlers aus DNS64 ("" = keiner)
	// Batch fuehrt fn als Stapel aus: DNS64 baut DHCP und Eintraege einmal am Ende neu auf (nil = je Eintrag)
	Batch func(ctx context.Context, fn func(context.Context) error) error
	// Check liefert einen Kontext, in dem die Aufrufe nur pruefen und nichts schreiben (nil = ohne Vorpruefung)
	Check func(ctx context.Context) context.Context
	// Names: Rechnernamen, die DNS64 fuer Client-Adressen kennt (Geraetegruppe, eigene Eintraege, Rueckwaertssuche
	// beim Router, z. B. FRITZ!Box) - fuer Adressen, zu denen IPAM64 sonst keinen Namen hat (nil = keine)
	Names func(ctx context.Context, ips []string) map[string]string
}

// batch fuehrt fn als Stapel in DNS64 aus (Import, Assistent, Umnummerieren, Abgleich: tausende Adressen ohne
// Neuaufbau je Adresse).
func (m *Module) batch(ctx context.Context, fn func(context.Context) error) error {
	if m.dns.Batch == nil {
		return fn(ctx)
	}
	return m.dns.Batch(ctx, fn)
}

// SetDNS64 haengt DNS64 an (vor dem Start).
func (m *Module) SetDNS64(d DNS64) { m.dns = d }

// DNS64Running meldet, ob DNS64 laeuft (sonst schreibt IPAM64 nichts dorthin).
func (m *Module) DNS64Running() bool { return m.dns.Running != nil && m.dns.Running() }

// Effect ist eine Wirkung einer Adresse in DNS64 (fuer Anzeige, Meldung und Audit).
type Effect struct {
	Kind  string `json:"kind"` // reservation | exclude | record
	Text  string `json:"text"` // z. B. "02:00:..:01 -> 192.168.1.10" bzw. "nas.home.lan A 192.168.1.10"
	State string `json:"state"`
}

// want ist der Soll-Stand einer Adresse in DNS64.
type want struct {
	res     *OwnedRes
	excl    *OwnedExcl
	recName string
	recAddr netip.Addr
	ptr     bool
	zoneErr bool // DNS an, aber keine Zone
}

// desired berechnet den Soll-Stand einer Adresse (snap: Praefixe und DHCP-Netze). An DNS64 uebergeben: nichts.
func desired(snap *Snapshot, a Address) want {
	var w want
	ip, err := netip.ParseAddr(a.Address)
	if err != nil || a.Status == StatusDeprecated || a.Released {
		return w
	}
	n := snap.NetOf(ip)
	if a.DHCP && a.MAC != "" && ip.Is4() {
		w.res = &OwnedRes{Ref: a.UID, MAC: a.MAC, IP: a.Address, Name: a.Name}
	} else if ip.Is4() && n != nil && n.inPool(ip) {
		w.excl = &OwnedExcl{Ref: a.UID, IP: a.Address}
	}
	if a.DNS && a.Name != "" {
		zone := a.DNSZone
		if zone == "" && n != nil {
			zone = n.zone
		}
		if zone == "" {
			w.zoneErr = true
		} else {
			w.recName, w.recAddr, w.ptr = a.Name+"."+zone, ip, a.PTR
		}
	}
	return w
}

func (w want) effects() []Effect {
	var out []Effect
	if w.res != nil {
		out = append(out, Effect{Kind: "reservation", Text: w.res.MAC + " → " + w.res.IP})
	}
	if w.excl != nil {
		out = append(out, Effect{Kind: "exclude", Text: w.excl.IP})
	}
	if w.recName != "" {
		typ := "A"
		if w.recAddr.Is6() {
			typ = "AAAA"
		}
		t := w.recName + " " + typ + " " + w.recAddr.String()
		if w.ptr {
			t += " + PTR"
		}
		out = append(out, Effect{Kind: "record", Text: t})
	}
	return out
}

// Effects liefert die Wirkung einer Adresse in DNS64 mit Abgleich gegen den Ist-Stand (State: ok | missing | off).
func (m *Module) Effects(ctx context.Context, a Address) ([]Effect, bool, error) {
	snap, err := m.netView(ctx)
	if err != nil {
		return nil, false, err
	}
	w := desired(snap, a)
	fx := w.effects()
	if !m.DNS64Running() || m.dns.Entries == nil {
		for i := range fx {
			fx[i].State = "off"
		}
		return fx, w.zoneErr, nil
	}
	own, err := m.dns.Entries(ctx)
	if err != nil {
		return nil, false, err
	}
	have := ownedIndex(own)[a.UID]
	for i := range fx {
		fx[i].State = "missing"
		switch fx[i].Kind {
		case "reservation":
			if have.res != nil && *have.res == *w.res {
				fx[i].State = "ok"
			}
		case "exclude":
			if have.excl != nil && *have.excl == *w.excl {
				fx[i].State = "ok"
			}
		case "record":
			if have.rec(w) {
				fx[i].State = "ok"
			}
		}
	}
	return fx, w.zoneErr, nil
}

// ownedOne ist der Ist-Stand einer Adresse in DNS64.
type ownedOne struct {
	res  *OwnedRes
	excl *OwnedExcl
	recs []OwnedRec
}

// ownedIndex ordnet den Ist-Stand nach Bezug (einmal je Abgleich statt je Adresse durch alle Eintraege).
func ownedIndex(own Owned) map[string]ownedOne {
	idx := map[string]ownedOne{}
	for i := range own.Reservations {
		o := idx[own.Reservations[i].Ref]
		o.res = &own.Reservations[i]
		idx[own.Reservations[i].Ref] = o
	}
	for i := range own.Excludes {
		o := idx[own.Excludes[i].Ref]
		o.excl = &own.Excludes[i]
		idx[own.Excludes[i].Ref] = o
	}
	for _, r := range own.Records {
		o := idx[r.Ref]
		o.recs = append(o.recs, r)
		idx[r.Ref] = o
	}
	return idx
}

// any: es gibt mindestens einen Eintrag.
func (o ownedOne) any() bool { return o.res != nil || o.excl != nil || len(o.recs) > 0 }

// blocks: einer der Eintraege belegt, was eine Adresse in claims braucht (IP, MAC, Name und Wert).
func (o ownedOne) blocks(claims map[string]bool) bool {
	if o.res != nil && (claims["ip|"+o.res.IP] || claims["mac|"+o.res.MAC]) {
		return true
	}
	if o.excl != nil && claims["ip|"+o.excl.IP] {
		return true
	}
	for _, r := range o.recs {
		if claims["rec|"+r.Name+"|"+r.Value] {
			return true
		}
	}
	return false
}

// claims: was der Soll-Stand einer Adresse in DNS64 belegt.
func (w want) claims(into map[string]bool) {
	if w.res != nil {
		into["ip|"+w.res.IP], into["mac|"+w.res.MAC] = true, true
	}
	if w.excl != nil {
		into["ip|"+w.excl.IP] = true
	}
	if w.recName != "" {
		into["rec|"+w.recName+"|"+w.recAddr.String()] = true
	}
}

// rec: genau der gewuenschte Eintrag ist vorhanden (bzw. keiner, wenn keiner gewuenscht).
func (o ownedOne) rec(w want) bool {
	if w.recName == "" {
		return len(o.recs) == 0
	}
	typ := "A"
	if w.recAddr.Is6() {
		typ = "AAAA"
	}
	return len(o.recs) == 1 && o.recs[0].Name == w.recName && o.recs[0].Type == typ && o.recs[0].Value == w.recAddr.String() && o.recs[0].NoPTR == !w.ptr
}

// matches: Ist-Stand entspricht dem Soll.
func (o ownedOne) matches(w want) bool {
	resOK := (w.res == nil && o.res == nil) || (w.res != nil && o.res != nil && *w.res == *o.res)
	exOK := (w.excl == nil && o.excl == nil) || (w.excl != nil && o.excl != nil && *w.excl == *o.excl)
	return resOK && exOK && o.rec(w)
}

// write schreibt den Soll-Stand einer Adresse nach DNS64 (erst Eintraege, dann DHCP), vorher als Pruefung ohne
// Schreiben (Check). claimed: ein Eintrag von Hand wurde uebernommen.
func (m *Module) write(ctx context.Context, snap *Snapshot, a Address) (claimed bool, err error) {
	if !m.DNS64Running() {
		return false, nil
	}
	if a.Released { // an DNS64 uebergeben: hoechstens noch gekennzeichnete Eintraege freigeben, nichts loeschen
		return false, m.release(ctx, a.UID)
	}
	w := desired(snap, a)
	if w.zoneErr {
		return false, ErrNoZone
	}
	if m.dns.Check != nil {
		if _, err := m.writeWant(m.dns.Check(ctx), a, w); err != nil {
			return false, err
		}
	}
	return m.writeWant(ctx, a, w)
}

func (m *Module) writeWant(ctx context.Context, a Address, w want) (claimed bool, err error) {
	d := m.dns
	if w.recName != "" {
		if claimed, err = d.PutRecords(ctx, a.UID, w.recName, []netip.Addr{w.recAddr}, w.ptr); err != nil {
			return claimed, err
		}
	} else if err := d.DeleteRecords(ctx, a.UID); err != nil {
		return false, err
	}
	switch {
	case w.res != nil:
		err = d.PutReservation(ctx, a.UID, w.res.MAC, w.res.IP, w.res.Name)
	case w.excl != nil:
		if err = d.DeleteReservation(ctx, a.UID); err == nil {
			err = d.PutExclude(ctx, a.UID, w.excl.IP, a.Name)
		}
	default:
		if err = d.DeleteReservation(ctx, a.UID); err == nil {
			err = d.DeleteExclude(ctx, a.UID)
		}
	}
	return claimed, err
}

// unwrite loescht alles, was IPAM64 fuer eine Adresse in DNS64 hat.
func (m *Module) unwrite(ctx context.Context, ref string) error {
	if !m.DNS64Running() {
		return nil
	}
	return errors.Join(m.dns.DeleteRecords(ctx, ref), m.dns.DeleteReservation(ctx, ref), m.dns.DeleteExclude(ctx, ref))
}

// ApplyAddress speichert eine feste Adresse und schreibt sie nach DNS64; scheitert DNS64, bleibt alles beim alten.
func (m *Module) ApplyAddress(ctx context.Context, a Address, actor string) (Address, error) {
	var old *Address
	if a.UID != "" {
		var err error
		if old, err = m.addressWhere(ctx, `uid = ?`, a.UID); err != nil {
			return a, err
		}
	}
	saved, err := m.SaveAddress(ctx, a, actor)
	if err != nil {
		return saved, err
	}
	snap, err := m.netView(ctx)
	claimed := false
	if err == nil {
		claimed, err = m.write(ctx, snap, saved)
	}
	if err == nil {
		return saved, nil
	}
	// zuruecknehmen: IPAM64 und DNS64 auf den alten Stand. Ein eben uebernommener Eintrag von Hand bleibt (freigeben
	// statt loeschen); Reservierung bzw. Ausnahme des alten Stands nimmt write(old) wieder an sich.
	if claimed && m.dns.Release != nil {
		if _, rerr := m.dns.Release(ctx, saved.UID); rerr != nil {
			m.log.Warn("ipam64: rollback release", "err", rerr)
		}
	}
	if old == nil {
		if _, derr := m.DeleteAddress(ctx, saved.UID); derr != nil {
			m.log.Warn("ipam64: rollback", "err", derr)
		}
		if uerr := m.unwrite(ctx, saved.UID); uerr != nil {
			m.log.Warn("ipam64: rollback dns64", "err", uerr)
		}
		return a, err
	}
	if werr := m.writeAddress(ctx, *old); werr != nil {
		m.log.Warn("ipam64: rollback", "err", werr)
	}
	m.changed(ctx, ClusterItemAddresses, old.UID, false)
	if snap, serr := m.netView(ctx); serr == nil {
		if _, werr := m.write(ctx, snap, *old); werr != nil {
			m.log.Warn("ipam64: rollback dns64", "err", werr)
		}
	}
	return a, err
}

// RemoveAddress loescht eine feste Adresse samt ihren Eintraegen in DNS64.
func (m *Module) RemoveAddress(ctx context.Context, uid string) (*Address, error) {
	a, err := m.addressWhere(ctx, `uid = ?`, uid)
	if err != nil || a == nil {
		return nil, notFound(err)
	}
	if a.Released { // an DNS64 uebergeben: die Eintraege gehoeren DNS64 und bleiben
		if err := m.release(ctx, uid); err != nil {
			return nil, err
		}
	} else if err := m.unwrite(ctx, uid); err != nil {
		return nil, err
	}
	return m.DeleteAddress(ctx, uid)
}

// release gibt die gekennzeichneten Eintraege einer Adresse in DNS64 frei (nichts, wenn DNS64 nicht laeuft).
func (m *Module) release(ctx context.Context, ref string) error {
	if !m.DNS64Running() || m.dns.Release == nil {
		return nil
	}
	_, err := m.dns.Release(ctx, ref)
	return err
}

// reconcile gleicht IPAM64 mit DNS64 ab (Hintergrundschleife, Regeln oben): erst verwaiste Eintraege, dann an DNS64
// uebergebene Adressen freigeben, dann fehlende oder abweichende Eintraege ruhender Adressen schreiben - alles in einem
// Stapel. Liefert die Zahl der Reparaturen.
func (m *Module) reconcile(ctx context.Context) (int, error) {
	if !m.DNS64Running() || m.dns.Entries == nil {
		return 0, nil
	}
	own, err := m.dns.Entries(ctx)
	if err != nil {
		return 0, err
	}
	list, err := m.Addresses(ctx)
	if err != nil {
		return 0, err
	}
	snap, err := m.netView(ctx)
	if err != nil {
		return 0, err
	}
	idx := ownedIndex(own)
	now := m.now()
	known := map[string]bool{}
	claims := map[string]bool{} // was die zu schreibenden Adressen belegen
	var todo []Address
	var release []string
	for _, a := range list {
		known[a.UID] = true
		have := idx[a.UID]
		if a.Released { // an DNS64 uebergeben (auch auf einer anderen Node): freigeben, nie loeschen
			if have.any() {
				release = append(release, a.UID)
			}
			continue
		}
		if now.Sub(a.Updated) < settleFor {
			continue
		}
		w := desired(snap, a)
		if w.zoneErr || have.matches(w) {
			continue
		}
		w.claims(claims)
		todo = append(todo, a)
	}
	var orphans []string
	for ref := range idx {
		if !known[ref] {
			orphans = append(orphans, ref)
		}
	}
	slices.Sort(orphans)
	foreign := m.cluster.ForeignDNS64 != nil && m.cluster.ForeignDNS64(ctx)
	fixed := 0
	_ = m.batch(ctx, func(ctx context.Context) error {
		m.recMu.Lock()
		prev := m.orphans
		m.orphans = map[string]bool{}
		for _, ref := range orphans {
			switch {
			case foreign: // Eintraege anderer Nodes (DNS64 im Cluster, Adressen von IPAM64 nicht): nicht anfassen
				continue
			case idx[ref].blocks(claims) || prev[ref]: // braucht eine Adresse den Platz, sofort
				if err := m.unwrite(ctx, ref); err != nil {
					m.log.Warn("ipam64: reconcile orphan", "ref", ref, "err", err)
				} else {
					fixed++
				}
			default:
				m.orphans[ref] = true
			}
		}
		m.recMu.Unlock()
		for _, ref := range release {
			if m.dns.Release == nil {
				break
			}
			if _, err := m.dns.Release(ctx, ref); err != nil {
				m.log.Warn("ipam64: reconcile release", "ref", ref, "err", err)
			} else {
				fixed++
			}
		}
		for _, a := range todo {
			if _, err := m.write(ctx, snap, a); err != nil {
				m.log.Warn("ipam64: reconcile", "address", a.Address, "err", err)
				continue
			}
			fixed++
		}
		return nil
	})
	return fixed, nil
}

// Handover uebergibt alle Eintraege aus IPAM64 an DNS64: das Kennzeichen faellt weg, die Eintraege bleiben und sind
// in DNS64 frei bearbeitbar. Alle Adressen gelten als uebergeben (Released, DNS und DHCP aus): IPAM64 schreibt fuer sie
// nichts mehr nach DNS64 (auch keine Ausnahme im Pool), und die anderen Nodes im Cluster geben ihre Eintraege beim
// naechsten Abgleich ebenfalls frei, statt sie zu loeschen. Liefert die Zahl der Eintraege in DNS64.
func (m *Module) Handover(ctx context.Context, actor string) (int64, error) {
	if !m.DNS64Running() || m.dns.Release == nil {
		return 0, ErrNoDNS64
	}
	n, err := m.dns.Release(ctx, "")
	if err != nil {
		return n, err
	}
	list, err := m.Addresses(ctx)
	if err != nil {
		return n, err
	}
	for _, a := range list {
		if a.DNS || a.DHCP || !a.Released {
			a.DNS, a.DHCP, a.Released = false, false, true
			a.Updated, a.UpdatedBy = m.now().UTC().Truncate(time.Second), actor
			if err := m.writeAddress(ctx, a); err != nil {
				return n, err
			}
			m.changed(ctx, ClusterItemAddresses, a.UID, false)
		}
	}
	return n, nil
}

// ErrNoDNS64: DNS64 laeuft nicht.
var ErrNoDNS64 = errors.New("ipam64: dns64 not running")

// dnsErrKey liefert den i18n-Schluessel eines Fehlers aus DNS64 ("" = keiner).
func (m *Module) dnsErrKey(err error) string {
	if m.dns.ErrKey == nil || err == nil {
		return ""
	}
	return m.dns.ErrKey(err)
}

// zoneOf liefert die Zone, die fuer eine Adresse gilt (an der Adresse, sonst am Praefix), fuer die Anzeige.
func zoneOf(snap *Snapshot, a Address) string {
	if a.DNSZone != "" {
		return a.DNSZone
	}
	if ip, err := netip.ParseAddr(a.Address); err == nil {
		if n := snap.NetOf(ip); n != nil {
			return n.zone
		}
	}
	return ""
}

// hostOK: Rechnername als DNS-Label (fuer die Vorbelegung aus Quellen).
func hostOK(s string) bool { return hostRe.MatchString(strings.ToLower(s)) }
