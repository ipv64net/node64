// Package groups ordnet anfragende Geraete Gruppen zu (Kinder, Gaeste, Smart-TV ...): zuerst ueber die
// MAC-Adresse aus der Nachbartabelle des Hosts (ARP fuer IPv4, NDP fuer IPv6), sonst ueber IP-Adresse oder Netz.
// So bleibt ein Geraet in seiner Gruppe, auch wenn es die IPv6-Adresse wechselt (Privacy Extensions) oder per
// DHCP eine neue IPv4 bekommt. Die MAC sieht DNS64 nur im selben Netzsegment und im Host-Netzwerk.
package groups

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Arten eines Mitglieds.
const (
	KindMAC = "mac"
	KindIP  = "ip"
	KindNet = "net"
)

// Group ist eine Gruppe mit ihren Mitgliedern (Reihenfolge = Vorrang: passt ein Geraet auf mehrere, gilt die erste)
// und ihren Regeln.
type Group struct {
	ID        int64    `json:"id"`
	UID       string   `json:"uid,omitempty"` // Kennung im Cluster (auf allen Nodes gleich)
	Name      string   `json:"name"`
	Position  int      `json:"position"`
	Members   []Member `json:"members"`
	ListsMode string   `json:"lists_mode"` // global = Auswahl wie fuer alle, custom = eigene Auswahl (Lists)
	Lists     []string `json:"lists"`      // URLs der Blocklisten bei custom
	Cats      []string `json:"categories"` // gesperrte Kategorien (social, games, streaming, gambling, adult)
	Domains   []Domain `json:"domains"`    // Freigaben und Sperren der Gruppe

	SafeSearch bool   `json:"safesearch"` // Google, Bing, DuckDuckGo, YouTube kinderfreundlich
	YouTube    string `json:"youtube"`    // strict (Standard), moderate, off
	Bypass     bool   `json:"bypass"`     // Schutz gegen Umgehen

	Hold      string     `json:"hold"`       // "" = normal, block = Internet aus, free = Zeitplaene/Kategorien ausgesetzt
	HoldUntil string     `json:"hold_until"` // RFC 3339, "" = bis zum Aufheben
	Schedules []Schedule `json:"schedules"`
}

// Sofort-Knoepfe einer Gruppe.
const (
	HoldBlock = "block"
	HoldFree  = "free"
)

// Schedule ist ein Zeitplan einer Gruppe: an den Tagen (1 = Montag ... 7 = Sonntag) von Start bis Ende (HH:MM,
// Ende vor Start = ueber Mitternacht, gleich = ganzer Tag) gilt die Aktion.
type Schedule struct {
	ID      int64    `json:"id"`
	GroupID int64    `json:"group_id"`
	Label   string   `json:"label"`
	Days    []int    `json:"days"`
	Start   string   `json:"start"`
	End     string   `json:"end"`
	Action  string   `json:"action"`     // off = Internet aus, cats = Kategorien sperren
	Cats    []string `json:"categories"` // bei cats
	Enabled bool     `json:"enabled"`
}

// Aktionen eines Zeitplans.
const (
	ScheduleOff  = "off"
	ScheduleCats = "cats"
)

// HasDay: der Zeitplan gilt an diesem Tag (1 = Montag).
func (s Schedule) HasDay(d int) bool {
	for _, x := range s.Days {
		if x == d {
			return true
		}
	}
	return false
}

// Rules sind die einstellbaren Regeln einer Gruppe (Seite und API).
type Rules struct {
	ListsMode  string   `json:"lists_mode"`
	Lists      []string `json:"lists"`
	Cats       []string `json:"categories"`
	SafeSearch bool     `json:"safesearch"`
	YouTube    string   `json:"youtube"`
	Bypass     bool     `json:"bypass"`
}

// Listenauswahl einer Gruppe.
const (
	ListsGlobal = "global"
	ListsCustom = "custom"
)

// Domain ist eine Freigabe oder Sperre einer Gruppe (gilt samt Subdomains).
type Domain struct {
	ID      int64  `json:"id"`
	GroupID int64  `json:"group_id"`
	Domain  string `json:"domain"`
	Action  string `json:"action"` // allow, block
}

// Aktionen einer Domain.
const (
	ActionAllow = "allow"
	ActionBlock = "block"
)

// Member ist ein Geraet bzw. Netz einer Gruppe.
type Member struct {
	ID      int64  `json:"id"`
	GroupID int64  `json:"group_id"`
	Kind    string `json:"kind"`  // mac, ip, net
	Value   string `json:"value"` // aa:bb:cc:dd:ee:ff, 192.168.1.5, fd00::/64
	Label   string `json:"label"` // Name fuer die Seite (optional)
}

// Normalize prueft und vereinheitlicht ein Mitglied; false = ungueltig.
func Normalize(m *Member) bool {
	v := strings.TrimSpace(m.Value)
	m.Label = strings.TrimSpace(m.Label)
	switch m.Kind {
	case KindMAC:
		hw, err := net.ParseMAC(v)
		if err != nil || len(hw) != 6 {
			return false
		}
		m.Value = hw.String()
	case KindIP:
		a, err := netip.ParseAddr(strings.Trim(v, "[]"))
		if err != nil {
			return false
		}
		m.Value = a.Unmap().WithZone("").String()
	case KindNet:
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return false
		}
		if p = p.Masked(); p.Addr().Is4In6() { // ::ffff:192.168.1.0/120 -> 192.168.1.0/24 (Clients kommen ohne ::ffff:)
			if p.Bits() < 96 {
				return false
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		if p.Bits() == 0 {
			return false
		}
		m.Value = p.String()
	default:
		return false
	}
	return true
}

// compiled ist der Stand fuer schnelle Abfragen.
type compiled struct {
	groups []compiledGroup
	macs   bool // es gibt MAC-Regeln (sonst keine Nachbartabelle noetig)
}

type compiledGroup struct {
	id   int64
	name string
	macs map[string]bool
	ips  map[netip.Addr]bool
	nets []netip.Prefix
}

// Resolver liefert zu einer Client-IP die Gruppe.
type Resolver struct {
	log   *slog.Logger
	cur   atomic.Pointer[compiled]
	neigh atomic.Pointer[map[netip.Addr]string] // IP -> MAC aus der Nachbartabelle

	mu        sync.Mutex
	refreshed time.Time
	read      func() (map[netip.Addr]string, error) // Nachbartabelle (Tests ersetzen sie)
}

// NewResolver legt einen leeren Resolver an.
func NewResolver(log *slog.Logger) *Resolver {
	r := &Resolver{log: log, read: Neighbors}
	r.cur.Store(&compiled{})
	empty := map[netip.Addr]string{}
	r.neigh.Store(&empty)
	return r
}

// Set uebernimmt die Gruppen (sortiert nach Position).
func (r *Resolver) Set(list []Group) {
	c := &compiled{}
	for _, g := range list {
		cg := compiledGroup{id: g.ID, name: g.Name, macs: map[string]bool{}, ips: map[netip.Addr]bool{}}
		for _, m := range g.Members {
			switch m.Kind {
			case KindMAC:
				cg.macs[m.Value] = true
				c.macs = true
			case KindIP:
				if a, err := netip.ParseAddr(m.Value); err == nil {
					cg.ips[a] = true
				}
			case KindNet:
				if p, err := netip.ParsePrefix(m.Value); err == nil {
					cg.nets = append(cg.nets, p)
				}
			}
		}
		c.groups = append(c.groups, cg)
	}
	r.cur.Store(c)
	if c.macs {
		r.refresh(false)
	}
}

// Match ist das Ergebnis fuer eine Client-IP.
type Match struct {
	ID   int64  // 0 = keine Gruppe
	Name string // Gruppenname
	MAC  string // MAC aus der Nachbartabelle ("" = unbekannt)
}

// For liefert Gruppe und MAC einer Client-IP. Reihenfolge der Gruppen = Vorrang; in einer Gruppe zaehlt MAC, IP
// oder Netz gleich.
func (r *Resolver) For(ip netip.Addr) Match {
	ip = ip.Unmap().WithZone("")
	c := r.cur.Load()
	var mac string
	if c.macs {
		mac = (*r.neigh.Load())[ip]
		if mac == "" && ip.IsValid() && !ip.IsLoopback() {
			r.refresh(true) // neues Geraet: Tabelle neu lesen (hoechstens alle 5 s)
			mac = (*r.neigh.Load())[ip]
		}
	}
	for _, g := range c.groups {
		if (mac != "" && g.macs[mac]) || g.ips[ip] {
			return Match{ID: g.id, Name: g.name, MAC: mac}
		}
		for _, p := range g.nets {
			if p.Contains(ip) {
				return Match{ID: g.id, Name: g.name, MAC: mac}
			}
		}
	}
	return Match{MAC: mac}
}

// MAC liefert die MAC einer IP aus der Nachbartabelle ("" = unbekannt), ohne die Tabelle neu zu lesen.
func (r *Resolver) MAC(ip netip.Addr) string {
	return (*r.neigh.Load())[ip.Unmap().WithZone("")]
}

// IPs liefert die Adressen einer MAC aus der Nachbartabelle (ohne Link-Local), sortiert.
func (r *Resolver) IPs(mac string) []netip.Addr {
	var out []netip.Addr
	for ip, m := range *r.neigh.Load() {
		if m == mac && !ip.IsLinkLocalUnicast() {
			out = append(out, ip)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}

// refresh liest die Nachbartabelle; soon = auf Anfrage (hoechstens alle 5 s), sonst sofort.
func (r *Resolver) refresh(soon bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if soon && time.Since(r.refreshed) < 5*time.Second {
		return
	}
	r.refreshed = time.Now()
	m, err := r.read()
	if err != nil {
		if r.log != nil {
			r.log.Debug("neighbor table", "err", err)
		}
		return
	}
	if m == nil {
		m = map[netip.Addr]string{}
	}
	r.neigh.Store(&m)
}

// Run liest die Nachbartabelle alle 30 s neu, bis ctx endet.
func (r *Resolver) Run(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	r.refresh(false)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refresh(false) // auch ohne MAC-Regeln: die Seite Gruppen zeigt die MAC der Geraete
		}
	}
}

// HasList: die Gruppe hat diese Liste in ihrer eigenen Auswahl (Seite Gruppen).
func (g Group) HasList(url string) bool {
	for _, u := range g.Lists {
		if u == url {
			return true
		}
	}
	return false
}

// HasCat: die Kategorie ist fuer die Gruppe gesperrt.
func (g Group) HasCat(key string) bool {
	for _, c := range g.Cats {
		if c == key {
			return true
		}
	}
	return false
}
