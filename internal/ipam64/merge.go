package ipam64

import (
	"context"
	"math"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Zusammenfuehrung (Grundlage: Entwurf von UlrichSchwarz). Praefixe aus IPAM64 und DHCP-Netze aus DNS64 bilden einen
// Baum (IPv4 vor IPv6, Eltern vor Kindern). Jede belegte Adresse gehoert zum kleinsten Praefix, in dem sie liegt.
// Quellen: feste Adressen in IPAM64, die Node selbst, die Quellen aus main (DHCP, lokaler DNS, Monitor64,
// Healthchecks, PROXY64; Rang = Reihenfolge) und die Sichtungen aus der Nachbartabelle.

// Net ist ein Praefix mit Belegung.
type Net struct {
	Prefix      netip.Prefix `json:"-"`
	CIDR        string       `json:"prefix"`
	UID         string       `json:"uid,omitempty"` // leer: nur DHCP-Netz aus DNS64 (noch nicht in IPAM64)
	Family      int          `json:"family"`
	Name        string       `json:"name"`
	Status      string       `json:"status"`
	Role        string       `json:"role,omitempty"`
	VLAN        int          `json:"vlan"`
	Tags        []string     `json:"tags"`
	Description string       `json:"description,omitempty"`
	MarkFull    bool         `json:"mark_full"`
	DNSZone     string       `json:"dns_zone,omitempty"`
	Scan        string       `json:"scan"`
	Dynamic     bool         `json:"dynamic"`             // IPv6 vom Provider, wechselt (Wurzel)
	DynIndex    string       `json:"dyn_index,omitempty"` // Praefix-ID unter einer dynamischen Wurzel
	DHCP        bool         `json:"dhcp"`                // DHCP-Netz in DNS64
	Iface       string       `json:"interface,omitempty"`
	Router      string       `json:"router,omitempty"`
	PoolStart   string       `json:"pool_start,omitempty"`
	PoolEnd     string       `json:"pool_end,omitempty"`
	Domain      string       `json:"domain,omitempty"`
	Parent      string       `json:"parent,omitempty"`
	Depth       int          `json:"depth"`
	Children    int          `json:"children"`
	Attached    bool         `json:"attached"` // die Node hat eine Adresse darin
	Size        int64        `json:"size"`     // nutzbare Adressen (IPv4; IPv6: 0 = nicht sinnvoll zaehlbar)
	Used        int          `json:"used"`     // belegte Adressen direkt in diesem Praefix
	Free        int64        `json:"free"`     // IPv4
	PoolFree    int          `json:"pool_free"`
	Conflicts   int          `json:"conflicts"`
	Pct         float64      `json:"used_pct"` // Container: Anteil der Kinder-Praefixe, sonst Anteil belegter Adressen

	start, end netip.Addr // DHCP-Adressbereich, im Kind-Praefix eines DHCP-Netzes dessen Teil im Kind
	zone       string     // geltende Zone: eigene bzw. die des naechsten Eltern-Praefixes/DHCP-Netzes mit Zone
	cover      float64    // Anteil, den die direkten Kinder abdecken
}

// Label ist der Name bzw. ersatzweise das Praefix.
func (n Net) Label() string {
	if n.Name != "" {
		return n.Name
	}
	return n.CIDR
}

// IsV4 meldet ein IPv4-Praefix.
func (n Net) IsV4() bool { return n.Family == 4 }

// Container meldet ein Praefix, das nur gliedert.
func (n Net) Container() bool { return n.Status == StatusContainer }

// inPool meldet, ob ip im DHCP-Adressbereich liegt.
func (n Net) inPool(ip netip.Addr) bool {
	return n.start.IsValid() && n.end.IsValid() && !ip.Less(n.start) && !n.end.Less(ip)
}

// Entry ist eine belegte Adresse.
type Entry struct {
	IP          string    `json:"ip"`
	Name        string    `json:"name"`
	Note        string    `json:"note,omitempty"`
	NoteKey     string    `json:"-"` // statt Note: i18n-Schluessel (diese Node, Router, Konflikt)
	NameKey     string    `json:"-"` // ohne Namen: i18n-Schluessel statt des Namens
	MAC         string    `json:"mac"`
	MACs        []string  `json:"macs,omitempty"` // Konflikt: alle beteiligten MAC-Adressen
	Kind        string    `json:"kind"`
	Sources     []string  `json:"sources"`
	Seen        time.Time `json:"last_seen,omitzero"`
	First       time.Time `json:"first_seen,omitzero"` // erste Sichtung in der Nachbartabelle (30 Tage)
	State       string    `json:"state"`               // online | offline | unknown | conflict
	Conflict    string    `json:"conflict,omitempty"`  // dup (zwei Geraete) | mac (fremde MAC) | lease (Lease gegen feste Adresse)
	Vendor      string    `json:"vendor,omitempty"`    // Hersteller aus der MAC (Herstellerliste) bzw. "random"
	UID         string    `json:"uid,omitempty"`       // feste Adresse in IPAM64
	Status      string    `json:"status,omitempty"`
	Role        string    `json:"role,omitempty"`
	Description string    `json:"description,omitempty"`
	Tags        []string  `json:"tags,omitempty"`

	ip netip.Addr
}

// Addr ist die Adresse als netip.Addr.
func (e Entry) Addr() netip.Addr { return e.ip }

// Snapshot ist die Belegung aller Praefixe zu einem Zeitpunkt (nicht veraendern: zwischengespeichert).
type Snapshot struct {
	Nets    []Net
	Ranges  []Range
	entries map[netip.Prefix][]Entry
	At      time.Time
}

// Entries liefert die belegten Adressen eines Praefixes, nach Adresse sortiert.
func (s *Snapshot) Entries(p netip.Prefix) []Entry { return s.entries[p] }

// Net sucht ein Praefix ueber seine Schreibweise.
func (s *Snapshot) Net(cidr string) *Net {
	p, err := ParsePrefix(cidr)
	if err != nil {
		return nil
	}
	for i := range s.Nets {
		if s.Nets[i].Prefix == p {
			return &s.Nets[i]
		}
	}
	return nil
}

// NetOf liefert das kleinste Praefix, in dem ip liegt (nil = keins).
func (s *Snapshot) NetOf(ip netip.Addr) *Net {
	var best *Net
	for i := range s.Nets {
		if s.Nets[i].Prefix.Contains(ip) && (best == nil || s.Nets[i].Prefix.Bits() > best.Prefix.Bits()) {
			best = &s.Nets[i]
		}
	}
	return best
}

// Entry sucht eine belegte Adresse (nil = frei).
func (s *Snapshot) Entry(ip netip.Addr) *Entry {
	n := s.NetOf(ip)
	if n == nil {
		return nil
	}
	list := s.entries[n.Prefix]
	if i, ok := slices.BinarySearchFunc(list, ip, func(e Entry, t netip.Addr) int { return e.ip.Compare(t) }); ok {
		return &list[i]
	}
	return nil
}

// RangesIn liefert die Adressbereiche, die in einem Praefix liegen (nach Anfang sortiert).
func (s *Snapshot) RangesIn(p netip.Prefix) []Range {
	var out []Range
	for _, r := range s.Ranges {
		if a, err := netip.ParseAddr(r.Start); err == nil && p.Contains(a) {
			out = append(out, r)
		}
	}
	return out
}

// vlanOf liest das VLAN aus dem Namen der Schnittstelle (eth0.20, vlan20, br-vlan20); 0 = keins.
func vlanOf(iface string) int {
	s := iface
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		s = s[i+1:]
	} else if i := strings.LastIndex(strings.ToLower(s), "vlan"); i >= 0 {
		s = s[i+4:]
	} else {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 4094 {
		return n
	}
	return 0
}

func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// hostCount: nutzbare Adressen eines IPv4-Praefixes (/31 und /32 ohne Abzug).
func hostCount(p netip.Prefix) int64 {
	if !p.Addr().Is4() {
		return 0
	}
	n := int64(1) << (32 - p.Bits())
	if p.Bits() <= 30 {
		n -= 2
	}
	return n
}

// nets fuehrt die Praefixe aus IPAM64 und die DHCP-Netze aus DNS64 zusammen (ohne Belegung) und baut den Baum. Ein
// Kind-Praefix in einem DHCP-Netz erbt dessen Adressbereich (soweit er im Kind liegt) und die Zone, falls es keine
// eigene hat: Ausnahmen, freie Adressen und Zaehler gelten auch dort.
func (m *Module) nets(ctx context.Context) ([]Net, error) {
	rows, err := m.Prefixes(ctx)
	if err != nil {
		return nil, err
	}
	var out []Net
	idx := map[netip.Prefix]int{}
	for _, r := range rows {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		idx[p] = len(out)
		out = append(out, Net{Prefix: p, CIDR: p.String(), UID: r.UID, Family: r.Family, Name: r.Name, Status: r.Status, Role: r.Role, VLAN: r.VLAN,
			Tags: r.Tags, Description: r.Description, MarkFull: r.MarkFull, DNSZone: r.DNSZone, Scan: r.Scan, Dynamic: r.DynSource == DynAuto, DynIndex: r.DynIndex})
	}
	for _, h := range m.hintList(ctx) {
		i, ok := idx[h.Subnet]
		if !ok {
			i, idx[h.Subnet] = len(out), len(out)
			out = append(out, Net{Prefix: h.Subnet, CIDR: h.Subnet.String(), Family: 4, Name: h.Name, Status: StatusActive, Scan: ScanPassive, Tags: []string{}})
		}
		n := &out[i]
		n.DHCP, n.Iface, n.Router, n.PoolStart, n.PoolEnd, n.Domain = true, h.Iface, addrText(h.Router), addrText(h.Start), addrText(h.End), h.Domain
		if n.Name == "" {
			n.Name = h.Name
		}
		if n.DNSZone == "" {
			n.DNSZone = h.Domain
		}
	}
	slices.SortFunc(out, func(a, b Net) int {
		if a.Family != b.Family {
			return a.Family - b.Family
		}
		if c := a.Prefix.Addr().Compare(b.Prefix.Addr()); c != 0 {
			return c
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	})
	locs := m.locals() // einmal, nicht je Praefix
	var stack []int    // Indizes der offenen Eltern
	for i := range out {
		n := &out[i]
		for len(stack) > 0 && !out[stack[len(stack)-1]].Prefix.Contains(n.Prefix.Addr()) {
			stack = stack[:len(stack)-1]
		}
		n.start, _ = netip.ParseAddr(n.PoolStart)
		n.end, _ = netip.ParseAddr(n.PoolEnd)
		n.zone = n.DNSZone
		if len(stack) > 0 {
			par := &out[stack[len(stack)-1]]
			n.Parent, n.Depth = par.CIDR, len(stack)
			par.Children++
			par.cover += math.Exp2(float64(par.Prefix.Bits() - n.Prefix.Bits()))
			if !n.start.IsValid() && par.start.IsValid() { // Pool des umgebenden DHCP-Netzes, auf das Kind zugeschnitten
				lo, hi := par.start, par.end
				if f := n.Prefix.Masked().Addr(); lo.Less(f) {
					lo = f
				}
				if l := lastAddr(n.Prefix); l.Less(hi) {
					hi = l
				}
				if !hi.Less(lo) {
					n.start, n.end = lo, hi
				}
			}
			if n.zone == "" {
				n.zone = par.zone
			}
		}
		stack = append(stack, i)
		if n.VLAN == 0 {
			n.VLAN = vlanOf(n.Iface)
		}
		n.Size = hostCount(n.Prefix)
		n.Attached = attachedIn(locs, n.Prefix)
		if n.Tags == nil {
			n.Tags = []string{}
		}
	}
	return out, nil
}

// hostOf liefert den Rechnernamen bzw. die IP aus einem Ziel (IP, Name, "host:port", URL).
func hostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if strings.Contains(t, "://") {
		if u, err := url.Parse(t); err == nil {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	if i := strings.IndexAny(t, "/?"); i >= 0 {
		t = t[:i]
	}
	if _, err := netip.ParseAddr(strings.Trim(t, "[]")); err == nil {
		return strings.Trim(t, "[]")
	}
	if h, _, err := net.SplitHostPort(t); err == nil {
		t = h
	}
	return strings.ToLower(strings.TrimSuffix(strings.Trim(t, "[]"), "."))
}

// acc sammelt die Hinweise zu einer Adresse.
type acc struct {
	e        Entry
	assigned []string        // der Adresse zugewiesene MAC-Adressen (DHCP, IPAM64)
	recent   []seenRow       // in den letzten conflictFor gesehene MAC-Adressen (mit erster/letzter Sichtung)
	lastMAC  string          // zuletzt gesehene MAC
	names    map[string]bool // alle bekannten Namen (klein)
	ipamMAC  string          // MAC der festen Adresse in IPAM64
	ipamDHCP bool            // feste Adresse mit DHCP-Reservierung
	leaseMAC string          // MAC einer aktiven Lease auf der Adresse
}

func (a *acc) source(key string) {
	if !slices.Contains(a.e.Sources, key) {
		a.e.Sources = append(a.e.Sources, key)
	}
}

func (a *acc) name(name, note string) {
	if name = strings.TrimSpace(name); name == "" {
		return
	}
	a.names[strings.ToLower(name)] = true
	if a.e.Name == "" {
		a.e.Name, a.e.Note = name, strings.TrimSpace(note)
	} else if a.e.Note == "" && a.e.NoteKey == "" {
		a.e.Note = strings.TrimSpace(note)
	}
}

func (a *acc) seen(t time.Time) {
	if t.After(a.e.Seen) {
		a.e.Seen = t
	}
}

func (a *acc) assign(mac string) {
	if mac = strings.ToLower(strings.TrimSpace(mac)); mac != "" && !slices.Contains(a.assigned, mac) {
		a.assigned = append(a.assigned, mac)
	}
}

// Snapshot fuehrt alle Quellen zusammen (hoechstens snapKeep alt; nach eigenen Aenderungen neu).
func (m *Module) Snapshot(ctx context.Context) (*Snapshot, error) {
	m.snapMu.Lock()
	defer m.snapMu.Unlock()
	if m.snap != nil && m.now().Sub(m.snapAt) < snapKeep {
		return m.snap, nil
	}
	s, err := m.build(ctx)
	if err != nil {
		return nil, err
	}
	m.snap, m.snapAt = s, m.now()
	return s, nil
}

func (m *Module) build(ctx context.Context) (*Snapshot, error) {
	now := m.now()
	nets, err := m.nets(ctx)
	if err != nil {
		return nil, err
	}
	ranges, err := m.Ranges(ctx)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ranges, func(a, b Range) int {
		x, _ := netip.ParseAddr(a.Start)
		y, _ := netip.ParseAddr(b.Start)
		return x.Compare(y)
	})
	snap := &Snapshot{Nets: nets, Ranges: ranges, entries: map[netip.Prefix][]Entry{}, At: now}
	all := map[netip.Addr]*acc{}
	get := func(ip netip.Addr) *acc { // nil: in keinem Praefix, im Container ohne Adressen egal, Netz-/Broadcast-Adresse
		ip = ip.Unmap()
		n := snap.NetOf(ip)
		if n == nil || (ip.Is4() && n.Prefix.Bits() <= 30 && (ip == n.Prefix.Addr() || ip == lastAddr(n.Prefix))) {
			return nil
		}
		a := all[ip]
		if a == nil {
			a = &acc{e: Entry{IP: ip.String(), ip: ip}, names: map[string]bool{}}
			all[ip] = a
		}
		return a
	}
	fixed, err := m.Addresses(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range fixed { // IPAM64: Name und Beschreibung gehen vor
		ip, err := netip.ParseAddr(r.Address)
		if err != nil {
			continue
		}
		if a := get(ip); a != nil {
			a.source(SrcIPAM)
			a.name(r.Name, r.Description)
			a.assign(r.MAC)
			a.e.UID, a.e.Status, a.e.Role, a.e.Description, a.e.Tags = r.UID, r.Status, r.Role, r.Description, r.Tags
			a.ipamMAC, a.ipamDHCP = r.MAC, r.DHCP
		}
	}
	for _, l := range m.locals() { // die Node selbst
		if a := get(l.Addr()); a != nil {
			a.source(SrcNode)
			a.seen(now)
			if a.e.Note == "" {
				a.e.NoteKey = "ipam64.note.self"
			}
		}
	}
	type later struct {
		key string
		s   Sighting
	}
	var byName []later
	for _, src := range m.sources {
		for _, s := range src.f(ctx) {
			h := hostOf(s.Addr)
			ip, err := netip.ParseAddr(h)
			if err != nil {
				if h != "" {
					byName = append(byName, later{src.key, s})
				}
				continue
			}
			a := get(ip)
			if a == nil {
				continue
			}
			a.source(src.key)
			a.name(s.Name, s.Note)
			if s.NoteKey != "" && a.e.Note == "" && a.e.NoteKey == "" {
				a.e.NoteKey = s.NoteKey
			}
			a.seen(s.Seen)
			a.assign(s.MAC)
			if s.Kind == KindFixed || (s.Kind == KindDHCP && a.e.Kind == "") {
				a.e.Kind = s.Kind
			}
			if s.Kind == KindDHCP {
				a.leaseMAC = strings.ToLower(s.MAC)
			}
		}
	}
	seen, err := m.seenRows(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range seen { // aufsteigend nach Zeit: die letzte MAC gewinnt
		a := get(s.IP)
		if a == nil {
			continue
		}
		a.source(SrcScan)
		a.seen(s.Last)
		a.lastMAC = s.MAC
		if a.e.First.IsZero() || s.First.Before(a.e.First) {
			a.e.First = s.First
		}
		if now.Sub(s.Last) <= conflictFor {
			a.recent = append(a.recent, s)
		}
	}
	// Name -> Adresse, auch der erste Teil eines vollen Namens (nas.home.lan -> nas). Nach Adresse sortiert, die erste
	// gewinnt (IPv4 vor IPv6): ein Ziel mit Namen haengt so immer an derselben Adresse.
	ips := make([]netip.Addr, 0, len(all))
	for ip := range all {
		ips = append(ips, ip)
	}
	slices.SortFunc(ips, netip.Addr.Compare)
	names := map[string]*acc{}
	for _, ip := range ips {
		a := all[ip]
		full := make([]string, 0, len(a.names))
		for n := range a.names {
			full = append(full, n)
		}
		slices.Sort(full)
		for _, n := range full {
			if names[n] == nil {
				names[n] = a
			}
		}
		for _, n := range full {
			if short, _, ok := strings.Cut(n, "."); ok && names[short] == nil {
				names[short] = a
			}
		}
	}
	for _, l := range byName { // Ziele mit Namen (Healthchecks, PROXY64): nur an bekannte Adressen haengen
		if a := names[hostOf(l.s.Addr)]; a != nil {
			a.source(l.key)
			a.seen(l.s.Seen)
			a.name(l.s.Name, l.s.Note)
		}
	}
	for ip, a := range all {
		n := snap.NetOf(ip)
		e := a.e
		e.MAC = a.lastMAC
		if len(a.assigned) > 0 && !slices.Contains(a.assigned, a.lastMAC) { // zugewiesen geht vor gesehen
			e.MAC = a.assigned[0]
		}
		e.Conflict = a.conflict()
		e.Vendor = vendorOf(e.MAC)
		conflict := e.Conflict != ""
		switch {
		case conflict:
			e.Kind, e.State, e.NoteKey = KindConflict, "conflict", "ipam64.note.conflict_"+e.Conflict
			e.MACs = slices.Clone(a.assigned)
			for _, r := range a.recent {
				e.MACs = append(e.MACs, r.MAC)
			}
			if a.leaseMAC != "" {
				e.MACs = append(e.MACs, a.leaseMAC)
			}
			slices.Sort(e.MACs)
			e.MACs = slices.Compact(e.MACs)
			n.Conflicts++
		case e.Seen.IsZero():
			e.State = "unknown"
		case now.Sub(e.Seen) <= onlineFor:
			e.State = "online"
		default:
			e.State = "offline"
		}
		if e.Kind == "" {
			e.Kind = KindStatic
		}
		if e.Note == "" && e.NoteKey == "" && e.IP == n.Router {
			e.NoteKey = "ipam64.note.router"
		}
		if e.Name == "" && e.NoteKey != "" && !conflict { // ohne Namen: der Hinweis ist der Name
			e.NameKey, e.NoteKey = e.NoteKey, ""
		}
		if e.Tags == nil {
			e.Tags = []string{}
		}
		n.Used++
		snap.entries[n.Prefix] = append(snap.entries[n.Prefix], e)
	}
	for i := range nets {
		n := &nets[i]
		list := snap.entries[n.Prefix]
		slices.SortFunc(list, func(a, b Entry) int { return a.ip.Compare(b.ip) })
		switch {
		case n.MarkFull:
			n.Pct = 100
		case n.Container() || (n.Children > 0 && n.Used == 0):
			n.Pct = min(100, n.cover*100)
		case n.Size > 0:
			n.Pct = float64(n.Used) * 100 / float64(n.Size)
		}
		if n.Size > 0 {
			n.Free = max(0, n.Size-int64(n.Used))
		}
		if n.start.IsValid() && n.end.IsValid() {
			used := 0
			for _, e := range list {
				if n.inPool(e.ip) {
					used++
				}
			}
			n.PoolFree = max(0, poolSize(n.start, n.end)-used)
		}
	}
	return snap, nil
}

// conflictMin: so lange muss eine fremde MAC an einer festen Adresse gesehen werden (zwei Sichtungen), bevor es ein
// Konflikt ist.
const conflictMin = 5 * time.Minute

// conflict bewertet die Hinweise einer Adresse (Daempfung gegen Fehlalarme):
//   - dup: zwei MAC-Adressen, deren Sichtungen sich laenger als conflictMin ueberschneiden (abwechselnd erreichbar).
//     Ein Geraetetausch (die alte MAC verschwindet, bevor die neue auftaucht) und ein DHCP-Wechsel sind kein Konflikt,
//     auch wenn sich die Zeitraeume beruehren oder die erste Sichtung der neuen MAC aus dem Alter des Eintrags in der
//     Nachbartabelle etwas zurueckdatiert ist.
//   - mac: eine MAC, die nicht zur Zuweisung (IPAM64, Reservierung, Lease) passt, seit mindestens conflictMin.
//   - lease: feste Adresse in IPAM64 ohne Reservierung, aber der DHCP-Server hat sie an eine andere MAC vergeben.
func (a *acc) conflict() string {
	for i := range a.recent {
		for j := i + 1; j < len(a.recent); j++ {
			x, y := a.recent[i], a.recent[j]
			if x.MAC != y.MAC && minTime(x.Last, y.Last).Sub(maxTime(x.First, y.First)) > conflictMin {
				return "dup"
			}
		}
	}
	if len(a.assigned) > 0 {
		for _, r := range a.recent {
			if !slices.Contains(a.assigned, r.MAC) && r.Last.Sub(r.First) >= conflictMin {
				return "mac"
			}
		}
	}
	if a.e.UID != "" && !a.ipamDHCP && a.leaseMAC != "" && a.leaseMAC != a.ipamMAC {
		return "lease"
	}
	return ""
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func poolSize(a, b netip.Addr) int {
	if !a.Is4() || !b.Is4() {
		return 0
	}
	return int(u32(b)-u32(a)) + 1
}

// netView liefert nur die Praefixe ohne Belegung (fuer den Schreibweg nach DNS64 und den Abgleich): so wird nicht bei
// jeder gespeicherten Adresse alles neu zusammengefuehrt (Import Tausender Zeilen). Im Stapel (withView) gilt der dort
// gemerkte Stand.
func (m *Module) netView(ctx context.Context) (*Snapshot, error) {
	if s, ok := ctx.Value(viewKey{}).(*Snapshot); ok {
		return s, nil
	}
	nets, err := m.nets(ctx)
	if err != nil {
		return nil, err
	}
	return &Snapshot{Nets: nets, entries: map[netip.Prefix][]Entry{}, At: m.now()}, nil
}

type viewKey struct{}

// withView merkt die Praefixe fuer einen Stapel (Import, Assistent): netView und containing lesen sie dann nicht fuer
// jede Adresse neu. Nur fuer Stapel, in denen keine Praefixe mehr geaendert werden.
func (m *Module) withView(ctx context.Context) (context.Context, error) {
	s, err := m.netView(ctx)
	if err != nil {
		return ctx, err
	}
	return context.WithValue(ctx, viewKey{}, s), nil
}
