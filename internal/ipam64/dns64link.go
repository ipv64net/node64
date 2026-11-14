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
// Gespeichert wird zuerst in IPAM64, dann in DNS64; scheitert DNS64 (z. B. MAC schon vergeben, CNAME auf dem Namen),
// wird die Aenderung in IPAM64 zurueckgenommen und der alte Stand nach DNS64 zurueckgeschrieben. Uebernahmen aus dem
// Cluster schreiben nichts (die Eintraege kommen ueber den Abgleich von DNS64); der Abgleich-Job (alle 10 Minuten)
// repariert nur Adressen, die seit settleFor unveraendert sind, und loescht verwaiste Eintraege erst, wenn sie in zwei
// Laeufen hintereinander verwaist sind - so pendelt im Cluster nichts, wenn Eintraege in anderer Reihenfolge ankommen.

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
	PutRecords        func(ctx context.Context, ref, name string, addrs []netip.Addr, ptr bool) error
	DeleteRecords     func(ctx context.Context, ref string) error
	Release           func(ctx context.Context, ref string) (int64, error)
	Entries           func(ctx context.Context) (Owned, error)
	ErrKey            func(err error) string // i18n-Schluessel eines Fehlers aus DNS64 ("" = keiner)
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

// desired berechnet den Soll-Stand einer Adresse (snap: Praefixe und DHCP-Netze).
func desired(snap *Snapshot, a Address) want {
	var w want
	ip, err := netip.ParseAddr(a.Address)
	if err != nil || a.Status == StatusDeprecated {
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
			zone = n.DNSZone
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
	snap, err := m.Snapshot(ctx)
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
	have := ownedFor(own, a.UID)
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

func ownedFor(own Owned, ref string) ownedOne {
	var o ownedOne
	for i := range own.Reservations {
		if own.Reservations[i].Ref == ref {
			o.res = &own.Reservations[i]
		}
	}
	for i := range own.Excludes {
		if own.Excludes[i].Ref == ref {
			o.excl = &own.Excludes[i]
		}
	}
	for _, r := range own.Records {
		if r.Ref == ref {
			o.recs = append(o.recs, r)
		}
	}
	return o
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

// write schreibt den Soll-Stand einer Adresse nach DNS64 (erst Eintraege, dann DHCP).
func (m *Module) write(ctx context.Context, snap *Snapshot, a Address) error {
	if !m.DNS64Running() {
		return nil
	}
	w := desired(snap, a)
	if w.zoneErr {
		return ErrNoZone
	}
	d := m.dns
	if w.recName != "" {
		if err := d.PutRecords(ctx, a.UID, w.recName, []netip.Addr{w.recAddr}, w.ptr); err != nil {
			return err
		}
	} else if err := d.DeleteRecords(ctx, a.UID); err != nil {
		return err
	}
	switch {
	case w.res != nil:
		if err := d.PutReservation(ctx, a.UID, w.res.MAC, w.res.IP, w.res.Name); err != nil {
			return err
		}
	case w.excl != nil:
		if err := d.DeleteReservation(ctx, a.UID); err != nil {
			return err
		}
		if err := d.PutExclude(ctx, a.UID, w.excl.IP, a.Name); err != nil {
			return err
		}
	default:
		if err := d.DeleteReservation(ctx, a.UID); err != nil {
			return err
		}
		if err := d.DeleteExclude(ctx, a.UID); err != nil {
			return err
		}
	}
	return nil
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
	snap, err := m.Snapshot(ctx)
	if err == nil {
		err = m.write(ctx, snap, saved)
	}
	if err == nil {
		return saved, nil
	}
	// zuruecknehmen: IPAM64 und DNS64 auf den alten Stand
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
	if snap, serr := m.Snapshot(ctx); serr == nil {
		if werr := m.write(ctx, snap, *old); werr != nil {
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
	if err := m.unwrite(ctx, uid); err != nil {
		return nil, err
	}
	return m.DeleteAddress(ctx, uid)
}

// reconcile gleicht IPAM64 mit DNS64 ab (Hintergrundschleife): fehlende oder abweichende Eintraege von Adressen, die
// seit settleFor unveraendert sind, werden neu geschrieben; Eintraege ohne Adresse in IPAM64 erst im zweiten Lauf
// geloescht. Liefert die Zahl der Reparaturen.
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
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return 0, err
	}
	now := m.now()
	fixed := 0
	known := map[string]bool{}
	for _, a := range list {
		known[a.UID] = true
		if now.Sub(a.Updated) < settleFor {
			continue
		}
		w := desired(snap, a)
		if w.zoneErr || ownedFor(own, a.UID).matches(w) {
			continue
		}
		if err := m.write(ctx, snap, a); err != nil {
			m.log.Warn("ipam64: reconcile", "address", a.Address, "err", err)
			continue
		}
		fixed++
	}
	var orphans []string
	for _, r := range own.Reservations {
		orphans = append(orphans, r.Ref)
	}
	for _, x := range own.Excludes {
		orphans = append(orphans, x.Ref)
	}
	for _, r := range own.Records {
		orphans = append(orphans, r.Ref)
	}
	slices.Sort(orphans)
	orphans = slices.Compact(orphans)
	m.recMu.Lock()
	prev := m.orphans
	m.orphans = map[string]bool{}
	for _, ref := range orphans {
		if known[ref] {
			continue
		}
		if prev[ref] {
			if err := m.unwrite(ctx, ref); err != nil {
				m.log.Warn("ipam64: reconcile orphan", "ref", ref, "err", err)
			} else {
				fixed++
			}
			continue
		}
		m.orphans[ref] = true
	}
	m.recMu.Unlock()
	return fixed, nil
}

// Handover uebergibt alle Eintraege aus IPAM64 an DNS64: das Kennzeichen faellt weg, die Eintraege bleiben und sind
// in DNS64 frei bearbeitbar; an den Adressen in IPAM64 gehen die Schalter DNS und DHCP aus (sonst schriebe der Abgleich
// sie wieder). Liefert die Zahl der Eintraege in DNS64.
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
		if a.DNS || a.DHCP {
			a.DNS, a.DHCP = false, false
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
			return n.DNSZone
		}
	}
	return ""
}

// hostOK: Rechnername als DNS-Label (fuer die Vorbelegung aus Quellen).
func hostOK(s string) bool { return hostRe.MatchString(strings.ToLower(s)) }
