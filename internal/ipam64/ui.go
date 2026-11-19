package ipam64

import (
	"context"
	"embed"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/module"
)

//go:embed templates
var templateFS embed.FS

// Templates liefert die Seiten des Moduls (module.Templater).
func (m *Module) Templates() fs.FS {
	sub, _ := fs.Sub(templateFS, "templates")
	return sub
}

func (m *Module) uiRoutes(mux *http.ServeMux, g module.Guards) {
	page := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /ipam64", page(m.pageOverview))
	mux.Handle("GET /ipam64/prefix", page(m.pagePrefix))
	mux.Handle("GET /ipam64/address", page(m.pageAddress))
	mux.Handle("GET /ipam64/export.csv", page(m.pageExport))
	mux.Handle("POST /ipam64/prefix", page(m.postPrefix))
	mux.Handle("POST /ipam64/prefix/delete", page(m.postPrefixDelete))
	mux.Handle("POST /ipam64/range", page(m.postRange))
	mux.Handle("POST /ipam64/range/delete", page(m.postRangeDelete))
	mux.Handle("POST /ipam64/address", page(m.postAddress))
	mux.Handle("POST /ipam64/address/delete", page(m.postAddressDelete))
	mux.Handle("POST /ipam64/scan", page(m.postScan))
	mux.Handle("POST /ipam64/autoscan", page(m.postAutoScan))
	mux.Handle("POST /ipam64/handover", page(m.postHandover))
	mux.Handle("GET /ipam64/setup", page(m.pageSetup))
	mux.Handle("POST /ipam64/setup", page(m.postSetup))
	mux.Handle("POST /ipam64/dyncheck", page(m.postDynCheck))
	mux.Handle("GET /ipam64/conflicts", page(m.pageConflicts))
	mux.Handle("POST /ipam64/ignore", page(m.postIgnore))
	mux.Handle("POST /ipam64/notify", page(m.postNotify))
	mux.Handle("GET /ipam64/import", page(m.pageImport))
	mux.Handle("POST /ipam64/import", page(m.postImport))
}

const (
	mapRow   = 32  // Kaestchen je Zeile im Raster
	listPage = 250 // Zeilen je Seite der Liste
)

// errKey liefert den i18n-Schluessel zu einem Fehler der Eingaben ("" = unbekannt).
func errKey(err error) string {
	for e, k := range map[error]string{ErrPrefix: "prefix", ErrSize: "size", ErrDup: "dup", ErrName: "name", ErrHost: "host", ErrStatus: "status",
		ErrVLAN: "vlan", ErrTags: "tags", ErrRange: "range", ErrRangeNet: "range_net", ErrOverlap: "overlap", ErrIP: "ip", ErrNoNet: "no_net",
		ErrNetAddr: "net_addr", ErrMAC: "mac", ErrTaken: "taken", ErrRole: "role", ErrNotFound: "not_found", ErrBusy: "busy",
		ErrNotAttached: "not_attached", ErrNoScan: "no_scan", ErrNoZone: "no_zone", ErrNoDNS64: "no_dns64", ErrDyn: "dyn", ErrImport: "import", ErrCSVLine: "csv_line"} {
		if errors.Is(err, e) {
			return "ipam64.err." + k
		}
	}
	return ""
}

func (m *Module) errText(r *http.Request, err error) string {
	if k := errKey(err); k != "" {
		return m.g.T(r, k)
	}
	if k := m.dnsErrKey(err); k != "" { // aus DNS64 (z. B. MAC schon vergeben, CNAME auf dem Namen)
		return m.g.T(r, "ipam64.err.dns64", "text", m.g.T(r, k))
	}
	m.log.Error("ipam64: request failed", "err", err)
	return m.g.T(r, "ipam64.err.internal")
}

func (m *Module) fail(w http.ResponseWriter, r *http.Request, err error) {
	m.log.Error("ipam64: page", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func prefixURL(cidr string, kv ...string) string {
	q := url.Values{"p": {cidr}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			q.Set(kv[i], kv[i+1])
		}
	}
	return "/ipam64/prefix?" + q.Encode()
}

// ---- Uebersicht ----

type overviewData struct {
	Nets      []Net
	Used      int
	Conflicts int
	V4, V6    int
	VLANs     int
	Suggest   []Net    // DHCP-Netze aus DNS64, die noch nicht in IPAM64 stehen
	Local     []string // Netze an den Schnittstellen der Node, die IPAM64 nicht kennt
	Form      Prefix
	FormOpen  bool
	Err       string
	AutoScan  int
	AutoOpts  []int
	TagList   []string // vorhandene Tags (Vorschlaege beim Eingeben, #193)
	LastScan  time.Time
	Scan      ScanStatus
	DNS64     bool       // DNS64 laeuft (Uebergabe moeglich)
	Dyn       *DynChange // letzter Wechsel eines dynamischen IPv6-Praefixes
	Stale     []string   // Ziele anderer Module, die noch auf das alte Praefix zeigen
	HasDyn    bool       // es gibt ein dynamisches Praefix
}

func (m *Module) overview(r *http.Request) (*overviewData, error) {
	ctx := r.Context()
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	d := &overviewData{TagList: m.allTags(ctx), Nets: snap.Nets, AutoScan: m.AutoScan(ctx), AutoOpts: AutoScans, LastScan: m.LastScan(ctx), Scan: m.Scanning(), DNS64: m.DNS64Running(),
		Form: Prefix{Status: StatusActive, Scan: ScanPassive}}
	vlans := map[int]bool{}
	for _, n := range snap.Nets {
		d.Used, d.Conflicts = d.Used+n.Used, d.Conflicts+n.Conflicts
		if n.IsV4() {
			d.V4++
		} else {
			d.V6++
		}
		if n.VLAN > 0 {
			vlans[n.VLAN] = true
		}
		if n.UID == "" {
			d.Suggest = append(d.Suggest, n)
		}
	}
	d.VLANs = len(vlans)
	for _, n := range snap.Nets {
		d.HasDyn = d.HasDyn || n.Dynamic
	}
	if d.Dyn = m.LastDynChange(ctx); d.Dyn != nil && m.now().Sub(d.Dyn.At) < 7*24*time.Hour {
		d.Stale = m.StaleTargets(ctx, d.Dyn.From)
	}
	for _, l := range m.locals() {
		p := l.Masked()
		if snap.Net(p.String()) == nil && (p.Addr().IsPrivate() || p.Addr().Is6()) && !slices.Contains(d.Local, p.String()) {
			d.Local = append(d.Local, p.String())
		}
	}
	return d, nil
}

func (m *Module) renderOverview(w http.ResponseWriter, r *http.Request, status int, patch func(*overviewData)) {
	d, err := m.overview(r)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if patch != nil {
		patch(d)
	}
	m.g.Render(w, r, status, "ipam64/overview", "ipam64.title", d)
}

func (m *Module) pageOverview(w http.ResponseWriter, r *http.Request) {
	m.renderOverview(w, r, http.StatusOK, func(d *overviewData) {
		if p := r.URL.Query().Get("new"); p != "" { // Vorschlag uebernehmen: Formular vorbelegt
			d.FormOpen, d.Form.Prefix, d.Form.Name = true, p, r.URL.Query().Get("name")
		}
	})
}

// ---- Praefix ----

// Cell ist ein Kaestchen im Raster.
type Cell struct {
	IP    string
	Last  string // letzte Stelle(n) als Beschriftung
	Class string // dhcp | fixed | static | conflict | pool | reserved | free | na
	Name  string
	Match bool // Treffer von Filter/Suche der Liste
}

// MapCell ist ein Feld der Blockuebersicht grosser Praefixe (ein Teilnetz, hoechstens 256 Felder).
type MapCell struct {
	CIDR   string
	Label  string
	Count  int    // Eintraege im Teilnetz
	Level  string // empty | low | mid | high | full (IPv4) bzw. empty | used (IPv6) | child (eigenes Praefix)
	Hits   int    // Treffer von Filter/Suche
	Active bool   // Liste zeigt nur dieses Teilnetz
}

type prefixData struct {
	TagList   []string // vorhandene Tags (Vorschlaege, #193)
	Net       *Net
	Prefix    *Prefix // Eintrag in IPAM64 (nil = nur DHCP-Netz)
	View      string  // addresses (Raster und Liste) | ranges
	Rows      []listRow
	Total     int
	Page      int
	Pages     int
	Counts    map[string]int
	Filter    string
	Query     string
	Grid      [][]Cell
	Blocks    []string // Abschnitte des Rasters (/22, /23)
	Block     int
	MapRows   [][]MapCell // Blockuebersicht (IPv4 groesser /22, IPv6) in Zeilen zu 32 Feldern
	MapBits   int         // Laenge der Teilnetze der Blockuebersicht
	Part      string      // gewaehltes Teilnetz der Blockuebersicht ("" = ganzes Praefix)
	Marking   bool        // Filter oder Suche aktiv: Treffer im Raster hervorheben
	Ranges    []Range
	Children  []Net
	Next      string // naechste freie Adresse
	ScanOK    bool   // Scan erlaubt
	Scan      ScanStatus
	RangeForm Range
	Err       string
	ErrForm   string // prefix | range
}

// Crumb ist die letzte Stufe der Brotkrumen (Praefix).
func (d *prefixData) Crumb() string { return d.Net.CIDR }

// listRow ist eine Zeile der Liste: belegte Adresse oder Luecke.
type listRow struct {
	E    *Entry
	Free *FreeBlock
}

// URL baut den Link der Seite mit geaenderten Parametern.
func (d *prefixData) URL(kv ...string) string {
	q := []string{"view", d.View, "kind", d.Filter, "q", d.Query}
	if d.View == "addresses" {
		q[1] = "" // Standard
	}
	if d.Block > 0 {
		q = append(q, "block", strconv.Itoa(d.Block))
	}
	if d.Part != "" {
		q = append(q, "part", d.Part)
	}
	for i := 0; i+1 < len(kv); i += 2 {
		found := false
		for j := 0; j+1 < len(q); j += 2 {
			if q[j] == kv[i] {
				q[j+1], found = kv[i+1], true
			}
		}
		if !found {
			q = append(q, kv[i], kv[i+1])
		}
	}
	return prefixURL(d.Net.CIDR, q...)
}

func matches(e Entry, q string) bool {
	if q == "" {
		return true
	}
	for _, v := range []string{e.IP, e.Name, e.Note, e.MAC, e.Description} {
		if strings.Contains(strings.ToLower(v), q) {
			return true
		}
	}
	return false
}

// gridable: Raster fuer IPv4 bis /22 (in Abschnitten zu 256 Adressen).
func gridable(n *Net) bool { return n.IsV4() && n.Prefix.Bits() >= 22 && !n.Container() }

// mapBits liefert die Laenge der Teilnetze der Blockuebersicht: IPv4 ab /16 je /24, sonst 8 Bit tiefer (256 Felder).
func mapBits(n *Net) int {
	if n.IsV4() && n.Prefix.Bits() >= 16 {
		return 24
	}
	return min(n.Prefix.Addr().BitLen(), n.Prefix.Bits()+8)
}

// bitsAt liefert die Bits [from, to) einer Adresse als Zahl (hoechstens 8 Bit).
func bitsAt(a netip.Addr, from, to int) int {
	b := a.AsSlice()
	v := 0
	for i := from; i < to; i++ {
		v = v<<1 | int(b[i/8]>>(7-i%8)&1)
	}
	return v
}

// blockMap baut die Blockuebersicht eines grossen Praefixes; hit meldet Treffer von Filter/Suche (nil = keine).
func (s *Snapshot) blockMap(n *Net, mb int, hit func(*Entry) bool) []MapCell {
	sub := mb - n.Prefix.Bits()
	cells := make([]MapCell, 1<<sub)
	base := n.Prefix.Masked().Addr().AsSlice()
	for i := range cells {
		a := make([]byte, len(base))
		copy(a, base)
		for k := 0; k < sub; k++ { // Index in die Bits hinter dem Praefix schreiben
			if bit := n.Prefix.Bits() + k; i>>(sub-1-k)&1 == 1 {
				a[bit/8] |= 1 << (7 - bit%8)
			}
		}
		addr, _ := netip.AddrFromSlice(a)
		c := MapCell{CIDR: netip.PrefixFrom(addr, mb).String(), Level: "empty"}
		if n.IsV4() {
			c.Label = strconv.Itoa(int(a[(mb-1)/8]))
		} else {
			c.Label = fmt.Sprintf("%02x", i)
		}
		for _, k := range s.Nets {
			if k.Parent == n.CIDR && k.Prefix.Bits() <= mb && k.Prefix.Contains(addr) {
				c.Level = "child"
			}
		}
		cells[i] = c
	}
	list := s.entries[n.Prefix]
	for i := range list {
		c := &cells[bitsAt(list[i].ip, n.Prefix.Bits(), mb)]
		c.Count++
		if hit != nil && hit(&list[i]) {
			c.Hits++
		}
	}
	size := 1 << max(0, min(30, n.Prefix.Addr().BitLen()-mb))
	if size >= 4 {
		size -= 2 // wie gewohnt: ein /24 ist mit 254 Adressen voll
	}
	for i := range cells {
		c := &cells[i]
		switch pct := c.Count * 100 / size; {
		case c.Level == "child" || c.Count == 0:
		case !n.IsV4():
			c.Level = "used"
		case pct >= 100:
			c.Level = "full"
		case pct >= 80:
			c.Level = "high"
		case pct >= 50:
			c.Level = "mid"
		default:
			c.Level = "low"
		}
	}
	return cells
}

func addrAt(p netip.Prefix, i int) netip.Addr {
	v := u32(p.Masked().Addr()) + uint32(i)
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func (s *Snapshot) grid(n *Net, block int) [][]Cell {
	by := map[netip.Addr]*Entry{}
	list := s.entries[n.Prefix]
	for i := range list {
		by[list[i].ip] = &list[i]
	}
	var reserved [][2]netip.Addr
	for _, r := range s.RangesIn(n.Prefix) {
		if r.Kind == RangeReserved {
			reserved = append(reserved, [2]netip.Addr{netip.MustParseAddr(r.Start), netip.MustParseAddr(r.End)})
		}
	}
	total := 1 << (32 - n.Prefix.Bits())
	last := lastAddr(n.Prefix)
	var rows [][]Cell
	for i := block * 256; i < min(total, block*256+256); i++ {
		ip := addrAt(n.Prefix, i)
		b := ip.As4()
		c := Cell{IP: ip.String(), Last: strconv.Itoa(int(b[3])), Class: "free"}
		switch e := by[ip]; {
		case n.Prefix.Bits() <= 30 && (ip == n.Prefix.Addr() || ip == last):
			c.Class = "na"
		case e != nil:
			c.Class, c.Name = e.Kind, e.Name
		case s.NetOf(ip) != n:
			c.Class = "na" // in einem Kind-Praefix
		case n.inPool(ip):
			c.Class = "pool"
		default:
			for _, r := range reserved {
				if !ip.Less(r[0]) && !r[1].Less(ip) {
					c.Class = "reserved"
				}
			}
		}
		if (i-block*256)%mapRow == 0 {
			rows = append(rows, nil)
		}
		rows[len(rows)-1] = append(rows[len(rows)-1], c)
	}
	return rows
}

func (m *Module) prefixPage(r *http.Request) (*prefixData, error) {
	ctx := r.Context()
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	n := snap.Net(q.Get("p"))
	if n == nil {
		return nil, ErrNotFound
	}
	d := &prefixData{TagList: m.allTags(ctx), Net: n, Counts: map[string]int{}, Query: strings.TrimSpace(q.Get("q")), Scan: m.Scanning(), Ranges: snap.RangesIn(n.Prefix)}
	if n.UID != "" {
		if d.Prefix, err = m.prefixByUID(ctx, n.UID); err != nil {
			return nil, err
		}
	}
	for _, c := range snap.Nets {
		if c.Parent == n.CIDR {
			d.Children = append(d.Children, c)
		}
	}
	d.ScanOK = m.checkScan(ctx, n.Prefix) == nil
	if free, _ := snap.free(n, "", 1); len(free) > 0 {
		d.Next = free[0].String()
	}
	d.View = "addresses" // Raster und Liste auf einer Seite (frueher view=grid bzw. list)
	if q.Get("view") == "ranges" {
		d.View = "ranges"
	}
	all := snap.Entries(n.Prefix)
	d.Total = len(all)
	switch f := q.Get("kind"); f {
	case KindDHCP, KindFixed, KindStatic, KindConflict:
		d.Filter = f
	}
	lq := strings.ToLower(d.Query)
	d.Marking = d.Filter != "" || d.Query != ""
	hit := func(e *Entry) bool { return (d.Filter == "" || e.Kind == d.Filter) && matches(*e, lq) }
	var lo, hi netip.Addr // Ausschnitt der Liste: Abschnitt des Rasters bzw. Feld der Blockuebersicht (leer = alles)
	switch {
	case n.Container():
	case gridable(n):
		blocks := max(1, (1<<(32-n.Prefix.Bits()))/256)
		if b, _ := strconv.Atoi(q.Get("block")); b > 0 && b < blocks {
			d.Block = b
		}
		if blocks > 1 {
			for i := range blocks {
				a := addrAt(n.Prefix, i*256).As4()
				d.Blocks = append(d.Blocks, strconv.Itoa(int(a[0]))+"."+strconv.Itoa(int(a[1]))+"."+strconv.Itoa(int(a[2]))+".x")
			}
			lo, hi = addrAt(n.Prefix, d.Block*256), addrAt(n.Prefix, d.Block*256+255)
		}
		d.Grid = snap.grid(n, d.Block) // Treffer markiert die Schleife ueber die Liste unten (das Raster liegt im Ausschnitt)
	default:
		d.MapBits = mapBits(n)
		var h func(*Entry) bool
		if d.Marking {
			h = hit
		}
		cells := snap.blockMap(n, d.MapBits, h)
		if p, err := netip.ParsePrefix(q.Get("part")); err == nil && p.Bits() == d.MapBits && p == p.Masked() && n.Prefix.Contains(p.Addr()) {
			d.Part, lo, hi = p.String(), p.Addr(), lastAddr(p)
			cells[bitsAt(p.Addr(), n.Prefix.Bits(), d.MapBits)].Active = true
		}
		for i := 0; i < len(cells); i += mapRow {
			d.MapRows = append(d.MapRows, cells[i:min(i+mapRow, len(cells))])
		}
	}
	in := func(ip netip.Addr) bool { return !lo.IsValid() || (!ip.Less(lo) && !hi.Less(ip)) }
	var hits []Entry // Eintraege der Liste (Filter und Suche)
	for i := range all {
		if !in(all[i].ip) {
			continue
		}
		d.Counts[all[i].Kind]++
		if hit(&all[i]) {
			hits = append(hits, all[i])
		}
	}
	if d.Marking && d.Grid != nil {
		matched := make(map[string]bool, len(hits))
		for _, e := range hits {
			matched[e.IP] = true
		}
		for i := range d.Grid {
			for j := range d.Grid[i] {
				d.Grid[i][j].Match = matched[d.Grid[i][j].IP]
			}
		}
	}
	if d.View == "addresses" {
		var rows []listRow
		if d.Filter == "" && d.Query == "" { // Luecken nur in der vollstaendigen Liste
			var free []FreeBlock
			for _, b := range snap.FreeBlocks(n) { // auf den Ausschnitt zuschneiden
				if lo.IsValid() {
					if b.Last.Less(lo) || hi.Less(b.First) {
						continue
					}
					if b.First.Less(lo) {
						b.First = lo
					}
					if hi.Less(b.Last) {
						b.Last = hi
					}
					b.Count = int64(u32(b.Last)-u32(b.First)) + 1
					b.Pool = n.inPool(b.First) && n.inPool(b.Last)
				}
				free = append(free, b)
			}
			fi := 0
			for i := range hits {
				for fi < len(free) && free[fi].First.Less(hits[i].ip) {
					rows = append(rows, listRow{Free: &free[fi]})
					fi++
				}
				rows = append(rows, listRow{E: &hits[i]})
			}
			for ; fi < len(free); fi++ {
				rows = append(rows, listRow{Free: &free[fi]})
			}
		} else {
			for i := range hits {
				rows = append(rows, listRow{E: &hits[i]})
			}
		}
		d.Pages = max(1, (len(rows)+listPage-1)/listPage)
		d.Page, _ = strconv.Atoi(q.Get("page"))
		d.Page = min(max(d.Page, 1), d.Pages)
		d.Rows = rows[min((d.Page-1)*listPage, len(rows)):min(d.Page*listPage, len(rows))]
	}
	return d, nil
}

func (m *Module) renderPrefix(w http.ResponseWriter, r *http.Request, status int, patch func(*prefixData)) {
	d, err := m.prefixPage(r)
	if errors.Is(err, ErrNotFound) {
		m.g.Flash(w, r, "warning", m.g.T(r, "ipam64.err.not_found"))
		http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
		return
	}
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if patch != nil {
		patch(d)
	}
	m.g.Render(w, r, status, "ipam64/prefix", "ipam64.title", d)
}

func (m *Module) pagePrefix(w http.ResponseWriter, r *http.Request) {
	m.renderPrefix(w, r, http.StatusOK, nil)
}

// ---- Adresse ----

type addressData struct {
	TagList []string // vorhandene Tags (Vorschlaege, #193)
	Form    Address
	New     bool
	Entry   *Entry // was die Quellen ueber die Adresse wissen (nil = frei)
	Net     *Net
	Err     string
	Roles   []string
	Prefix  string   // Ruecksprung
	Zone    string   // Zone vom Praefix bzw. DHCP-Netz (gilt, wenn an der Adresse keine steht)
	InPool  bool     // liegt im DHCP-Adressbereich
	DNS64   bool     // DNS64 laeuft
	Effects []Effect // Wirkung in DNS64 (gespeicherter Stand, mit Abgleich)
	ZoneErr bool     // DNS an, aber keine Zone
}

// Crumb ist die letzte Stufe der Brotkrumen (Adresse).
func (d *addressData) Crumb() string { return d.Form.Address }

func (m *Module) addressPage(r *http.Request, ip string) (*addressData, error) {
	ctx := r.Context()
	a, err := ParseAddr(ip)
	if err != nil {
		return nil, ErrIP
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	d := &addressData{TagList: m.allTags(ctx), Net: snap.NetOf(a), Entry: snap.Entry(a), Roles: addrRoles, DNS64: m.DNS64Running()}
	if d.Net == nil {
		return nil, ErrNoNet
	}
	d.Prefix, d.Zone, d.InPool = d.Net.CIDR, d.Net.DNSZone, a.Is4() && d.Net.inPool(a)
	cur, err := m.addressWhere(ctx, `address = ?`, a.String())
	if err != nil {
		return nil, err
	}
	if cur != nil {
		d.Form = *cur
		if d.Effects, d.ZoneErr, err = m.Effects(ctx, *cur); err != nil {
			return nil, err
		}
	} else {
		d.New = true
		d.Form = Address{Address: a.String(), Status: StatusActive, PTR: true}
		if e := d.Entry; e != nil { // bekannte Adresse (z. B. Lease) uebernehmen: Name und MAC vorbelegen
			d.Form.MAC = e.MAC
			if name, _, _ := strings.Cut(strings.ToLower(e.Name), "."); hostOK(name) {
				d.Form.Name = name
			}
		}
		// Vorschlag: DNS-Eintrag, wenn es eine Zone gibt; Reservierung, wenn MAC und DHCP-Netz bekannt sind
		d.Form.DNS = d.Zone != "" && d.Form.Name != ""
		d.Form.DHCP = d.Form.MAC != "" && d.Net.DHCP && a.Is4()
		w := desired(snap, d.Form)
		d.Effects, d.ZoneErr = w.effects(), w.zoneErr
		for i := range d.Effects {
			d.Effects[i].State = "planned"
		}
	}
	return d, nil
}

func (m *Module) pageAddress(w http.ResponseWriter, r *http.Request) {
	d, err := m.addressPage(r, r.URL.Query().Get("ip"))
	if err != nil {
		if errKey(err) == "" {
			m.fail(w, r, err)
			return
		}
		m.g.Flash(w, r, "warning", m.errText(r, err))
		http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
		return
	}
	m.g.Render(w, r, http.StatusOK, "ipam64/address", "ipam64.title", d)
}

// ---- Formulare ----

func formInt(r *http.Request, key string) (int, bool) {
	v := strings.TrimSpace(r.PostFormValue(key))
	if v == "" {
		return 0, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil
}

func (m *Module) postPrefix(w http.ResponseWriter, r *http.Request) {
	vlan, ok := formInt(r, "vlan")
	in := Prefix{UID: r.PostFormValue("uid"), Prefix: r.PostFormValue("prefix"), Name: r.PostFormValue("name"), Status: r.PostFormValue("status"),
		Role: r.PostFormValue("role"), VLAN: vlan, Tags: []string{r.PostFormValue("tags")}, Description: r.PostFormValue("description"),
		MarkFull: r.PostFormValue("mark_full") == "1", DNSZone: r.PostFormValue("dns_zone"), Scan: r.PostFormValue("scan")}
	if r.PostFormValue("dynamic") == "1" {
		in.DynSource = DynAuto
	}
	var out Prefix
	var err error
	if !ok {
		err = ErrVLAN
	} else {
		out, err = m.SavePrefix(r.Context(), in, m.g.Actor(r))
	}
	if err != nil {
		text := m.errText(r, err)
		if in.UID == "" { // neu: auf der Uebersicht mit offenem Formular
			m.renderOverview(w, r, http.StatusUnprocessableEntity, func(d *overviewData) { d.Form, d.FormOpen, d.Err = in, true, text })
			return
		}
		m.g.Flash(w, r, "danger", text)
		http.Redirect(w, r, prefixURL(r.PostFormValue("back")), http.StatusSeeOther)
		return
	}
	m.g.Audit(r, "ipam64.prefix.save", out.Prefix, out.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.prefix_saved"))
	http.Redirect(w, r, prefixURL(out.Prefix), http.StatusSeeOther)
}

func (m *Module) postPrefixDelete(w http.ResponseWriter, r *http.Request) {
	p, err := m.DeletePrefix(r.Context(), r.PostFormValue("uid"))
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
		http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
		return
	}
	m.g.Audit(r, "ipam64.prefix.delete", p.Prefix, p.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.prefix_deleted"))
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

func (m *Module) postRange(w http.ResponseWriter, r *http.Request) {
	in := Range{UID: r.PostFormValue("uid"), Start: r.PostFormValue("start"), End: r.PostFormValue("end"), Kind: r.PostFormValue("kind"),
		Name: r.PostFormValue("name"), Description: r.PostFormValue("description")}
	back := r.PostFormValue("back")
	out, err := m.SaveRange(r.Context(), in, m.g.Actor(r))
	if err != nil {
		text := m.errText(r, err)
		r.URL.RawQuery = url.Values{"p": {back}, "view": {"ranges"}}.Encode()
		m.renderPrefix(w, r, http.StatusUnprocessableEntity, func(d *prefixData) { d.RangeForm, d.Err, d.ErrForm = in, text, "range" })
		return
	}
	m.g.Audit(r, "ipam64.range.save", out.Start+"-"+out.End, out.Name)
	m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.range_saved"))
	http.Redirect(w, r, prefixURL(back, "view", "ranges"), http.StatusSeeOther)
}

func (m *Module) postRangeDelete(w http.ResponseWriter, r *http.Request) {
	back := r.PostFormValue("back")
	if rg, err := m.DeleteRange(r.Context(), r.PostFormValue("uid")); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.range.delete", rg.Start+"-"+rg.End, rg.Name)
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.range_deleted"))
	}
	http.Redirect(w, r, prefixURL(back, "view", "ranges"), http.StatusSeeOther)
}

func (m *Module) postAddress(w http.ResponseWriter, r *http.Request) {
	in := Address{UID: r.PostFormValue("uid"), Address: r.PostFormValue("address"), Status: r.PostFormValue("status"), Role: r.PostFormValue("role"),
		Name: r.PostFormValue("name"), MAC: r.PostFormValue("mac"), Description: r.PostFormValue("description"), Tags: []string{r.PostFormValue("tags")},
		DNS: r.PostFormValue("dns") == "1", DNSZone: r.PostFormValue("dns_zone"), PTR: r.PostFormValue("ptr") == "1", DHCP: r.PostFormValue("dhcp") == "1"}
	out, err := m.ApplyAddress(r.Context(), in, m.g.Actor(r))
	if err != nil {
		text := m.errText(r, err)
		d, perr := m.addressPage(r, in.Address)
		if perr != nil {
			m.g.Flash(w, r, "danger", text)
			http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
			return
		}
		d.Form, d.Err, d.New = in, text, in.UID == ""
		m.g.Render(w, r, http.StatusUnprocessableEntity, "ipam64/address", "ipam64.title", d)
		return
	}
	m.g.Audit(r, "ipam64.address.save", out.Address, m.effectText(r.Context(), out))
	m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.address_saved"))
	if snap, err := m.Snapshot(r.Context()); err == nil {
		if n := snap.NetOf(netip.MustParseAddr(out.Address)); n != nil {
			http.Redirect(w, r, prefixURL(n.CIDR, "view", r.PostFormValue("view")), http.StatusSeeOther)
			return
		}
	}
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

func (m *Module) postAddressDelete(w http.ResponseWriter, r *http.Request) {
	back := r.PostFormValue("back")
	if a, err := m.RemoveAddress(r.Context(), r.PostFormValue("uid")); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.address.delete", a.Address, a.Name)
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.address_deleted"))
	}
	if back == "" {
		http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, prefixURL(back), http.StatusSeeOther)
}

func (m *Module) postScan(w http.ResponseWriter, r *http.Request) {
	p := r.PostFormValue("prefix")
	if err := m.StartScan(r.Context(), p); err != nil {
		m.g.Flash(w, r, "warning", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.scan", p, "")
		m.g.Flash(w, r, "info", m.g.T(r, "ipam64.flash.scan_started"))
	}
	http.Redirect(w, r, prefixURL(p), http.StatusSeeOther)
}

func (m *Module) postAutoScan(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.PostFormValue("minutes"))
	if err := m.SetAutoScan(r.Context(), n); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.autoscan", Name, strconv.Itoa(n))
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.autoscan_saved"))
	}
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

func (m *Module) postHandover(w http.ResponseWriter, r *http.Request) {
	n, err := m.Handover(r.Context(), m.g.Actor(r))
	if err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.handover", Name, strconv.FormatInt(n, 10))
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.handover", "n", n))
	}
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

func (m *Module) pageSetup(w http.ResponseWriter, r *http.Request) {
	plan, err := m.SetupPlan(r.Context())
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.g.Render(w, r, http.StatusOK, "ipam64/setup", "ipam64.setup.title", plan)
}

func (m *Module) postSetup(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	res, err := m.ApplySetup(r.Context(), r.PostForm["take"], m.g.Actor(r), func(e error) string { return m.errText(r, e) })
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.g.Audit(r, "ipam64.setup", Name, strconv.Itoa(res.Prefixes)+" prefixes, "+strconv.Itoa(res.Addresses)+" addresses")
	kind := "success"
	text := m.g.T(r, "ipam64.flash.setup", "p", res.Prefixes, "a", res.Addresses)
	if len(res.Failed) > 0 {
		kind = "warning"
		var parts []string
		for _, f := range res.Failed {
			parts = append(parts, f.What+": "+f.Reason)
		}
		text += " " + m.g.T(r, "ipam64.flash.setup_failed", "list", strings.Join(parts, "; "))
	}
	m.g.Flash(w, r, kind, text)
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

func (m *Module) postDynCheck(w http.ResponseWriter, r *http.Request) {
	list, err := m.CheckDynamic(r.Context())
	switch {
	case err != nil:
		m.g.Flash(w, r, "danger", m.errText(r, err))
	case len(list) == 0:
		m.g.Flash(w, r, "info", m.g.T(r, "ipam64.flash.dyn_none"))
	default:
		for _, c := range list {
			m.g.Audit(r, "ipam64.prefix.renumber", c.From, c.To)
		}
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.dyn_changed", "from", list[0].From, "to", list[0].To))
	}
	http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
}

type conflictsData struct {
	Findings   []Finding
	Unknown    []Entry
	Ignored    []string
	NotifyConf bool
	NotifyNew  bool
	Scan       ScanStatus
	LastScan   time.Time
	OUI        int
}

// Crumb ist die letzte Stufe der Brotkrumen.
func (d *conflictsData) Crumb() string { return "" }

func (m *Module) pageConflicts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d := &conflictsData{Ignored: m.Ignored(ctx), Scan: m.Scanning(), LastScan: m.LastScan(ctx), OUI: ouiSize()}
	var err error
	if d.Findings, err = m.Findings(ctx); err == nil {
		d.Unknown, err = m.Unknown(ctx)
	}
	if err != nil {
		m.fail(w, r, err)
		return
	}
	d.NotifyConf, d.NotifyNew = m.NotifyFlags(ctx)
	m.g.Render(w, r, http.StatusOK, "ipam64/conflicts", "ipam64.conflicts.title", d)
}

func (m *Module) postIgnore(w http.ResponseWriter, r *http.Request) {
	mac, on := r.PostFormValue("mac"), r.PostFormValue("on") != "0"
	if err := m.SetIgnored(r.Context(), mac, on); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.ignore", mac, boolText(on))
	}
	http.Redirect(w, r, "/ipam64/conflicts", http.StatusSeeOther)
}

func (m *Module) postNotify(w http.ResponseWriter, r *http.Request) {
	conf, dev := r.PostFormValue("conflicts") == "1", r.PostFormValue("devices") == "1"
	if err := m.SetNotifyFlags(r.Context(), conf, dev); err != nil {
		m.g.Flash(w, r, "danger", m.errText(r, err))
	} else {
		m.g.Audit(r, "ipam64.notify", Name, "conflicts="+boolText(conf)+" devices="+boolText(dev))
		m.g.Flash(w, r, "success", m.g.T(r, "ipam64.flash.notify_saved"))
	}
	http.Redirect(w, r, "/ipam64/conflicts", http.StatusSeeOther)
}

type importData struct {
	Rows    []importView
	CSV     string
	Valid   int
	Invalid int
	Err     string
}

type importView struct {
	ImportRow
	ErrText string
}

func (m *Module) pageImport(w http.ResponseWriter, r *http.Request) {
	m.g.Render(w, r, http.StatusOK, "ipam64/import", "ipam64.import.title", &importData{})
}

func (m *Module) postImport(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxImportBytes+64<<10)
	_ = r.ParseMultipartForm(maxImportBytes)
	text := r.PostFormValue("csv")
	if f, _, err := r.FormFile("file"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, maxImportBytes+1))
		f.Close()
		if len(b) > 0 {
			text = string(b)
		}
	}
	d := &importData{CSV: text}
	rows, err := m.ParseImport(r.Context(), []byte(text))
	if err != nil {
		d.Err = m.errText(r, err)
		m.g.Render(w, r, http.StatusUnprocessableEntity, "ipam64/import", "ipam64.import.title", d)
		return
	}
	if r.PostFormValue("action") == "apply" {
		// tausende Zeilen brauchen laenger als das Zeitlimit des Servers fuer die Antwort
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
		n, failed := m.ApplyImport(r.Context(), rows, m.g.Actor(r), func(e error) string { return m.errText(r, e) })
		m.g.Audit(r, "ipam64.import", Name, strconv.Itoa(n))
		kind, msg := "success", m.g.T(r, "ipam64.flash.imported", "n", n)
		if len(failed) > 0 {
			var parts []string
			for _, f := range failed {
				parts = append(parts, f.What+": "+f.Reason)
			}
			kind, msg = "warning", msg+" "+m.g.T(r, "ipam64.flash.setup_failed", "list", strings.Join(parts, "; "))
		}
		m.g.Flash(w, r, kind, msg)
		http.Redirect(w, r, "/ipam64", http.StatusSeeOther)
		return
	}
	for _, row := range rows {
		v := importView{ImportRow: row}
		if row.Err != nil {
			v.ErrText = m.errText(r, row.Err)
			d.Invalid++
		} else {
			d.Valid++
		}
		d.Rows = append(d.Rows, v)
	}
	m.g.Render(w, r, http.StatusOK, "ipam64/import", "ipam64.import.title", d)
}

// effectText beschreibt die Wirkung einer Adresse in DNS64 fuer das Audit-Log.
func (m *Module) effectText(ctx context.Context, a Address) string {
	snap, err := m.netView(ctx)
	if err != nil {
		return a.Name
	}
	var parts []string
	if a.Name != "" {
		parts = append(parts, a.Name)
	}
	for _, e := range desired(snap, a).effects() {
		parts = append(parts, e.Kind+": "+e.Text)
	}
	return strings.Join(parts, "; ")
}

// ---- CSV ----

// csvRow schuetzt alle Zellen einer Zeile.
func csvRow(cells ...string) []string {
	for i := range cells {
		cells[i] = module.CSVCell(cells[i])
	}
	return cells
}

// pageExport liefert die Belegung als CSV: das gewaehlte Praefix (p=) bzw. alle.
func (m *Module) pageExport(w http.ResponseWriter, r *http.Request) {
	snap, err := m.Snapshot(r.Context())
	if err != nil {
		m.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="ipam64.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"prefix", "ip", "name", "note", "mac", "kind", "status", "role", "tags", "sources", "last_seen", "state"})
	only := snap.Net(r.URL.Query().Get("p"))
	for _, n := range snap.Nets {
		if only != nil && n.Prefix != only.Prefix {
			continue
		}
		for _, e := range snap.Entries(n.Prefix) {
			seen := ""
			if !e.Seen.IsZero() {
				seen = e.Seen.UTC().Format(time.RFC3339)
			}
			name, note := e.Name, e.Note
			if name == "" && e.NameKey != "" {
				name = m.g.T(r, e.NameKey)
			}
			if note == "" && e.NoteKey != "" {
				note = m.g.T(r, e.NoteKey)
			}
			_ = cw.Write(csvRow(n.CIDR, e.IP, name, note, e.MAC, e.Kind, e.Status, e.Role, strings.Join(e.Tags, " "),
				strings.Join(e.Sources, " "), seen, e.State))
		}
	}
	cw.Flush()
}
