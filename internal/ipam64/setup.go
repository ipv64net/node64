package ipam64

import (
	"context"
	"net/netip"
	"slices"
	"strings"
)

// Assistent (Plan Stufe I4, Entscheidung E5): richtet IPAM64 aus dem Bestand ein. Vorschlaege:
//   - Praefixe: DHCP-Netze aus DNS64, die noch nicht in IPAM64 stehen, und die Netze an den Schnittstellen der Node
//     (private IPv4, ULA, globale IPv6 - diese als dynamisch, das Praefix des Providers wechselt).
//   - Adressen: feste Adressen (DHCP-Reservierungen) und A/AAAA-Eintraege, die in DNS64 von Hand stehen. Je IP eine
//     Adresse mit passend gesetzten Schaltern (DHCP an mit MAC, DNS an mit Rechnername und Zone); beim Speichern
//     kennzeichnet DNS64 die gleichen Eintraege, statt sie doppelt anzulegen (ApplyAddress). Was nicht passt (zweiter
//     Name fuer dieselbe IP, Name kein DNS-Label, andere MAC als in IPAM64), bleibt in DNS64 von Hand und steht mit Grund
//     in der Liste.

// SetupPrefix ist ein vorgeschlagenes Praefix.
type SetupPrefix struct {
	Key    string
	Prefix Prefix
	Source string // dhcp | local
}

// SetupAddress ist eine vorgeschlagene Adresse (neu oder Ergaenzung einer vorhandenen).
type SetupAddress struct {
	Key     string
	Address Address
	Exists  bool
	Claims  []string // was in DNS64 gekennzeichnet wird
}

// SetupSkip ist ein Eintrag aus DNS64, den der Assistent nicht uebernimmt.
type SetupSkip struct {
	What   string
	Reason string // i18n-Schluessel ipam64.setup.skip.*
}

// SetupPlan ist der Vorschlag des Assistenten.
type SetupPlan struct {
	Prefixes  []SetupPrefix
	Addresses []SetupAddress
	Skipped   []SetupSkip
	DNS64     bool
}

var (
	globalV6 = netip.MustParsePrefix("2000::/3")
	ulaV6    = netip.MustParsePrefix("fc00::/7")
)

// SetupPlan baut den Vorschlag aus dem aktuellen Stand.
func (m *Module) SetupPlan(ctx context.Context) (*SetupPlan, error) {
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	plan := &SetupPlan{DNS64: m.DNS64Running()}
	var proposed []netip.Prefix
	for _, n := range snap.Nets {
		if n.UID == "" {
			plan.Prefixes = append(plan.Prefixes, SetupPrefix{Key: "p:" + n.CIDR, Source: "dhcp",
				Prefix: Prefix{Prefix: n.CIDR, Name: n.Name, VLAN: n.VLAN, DNSZone: n.DNSZone, Status: StatusActive, Scan: ScanPassive}})
		}
	}
	for _, l := range m.locals() {
		p := l.Masked()
		a := p.Addr()
		if snap.Net(p.String()) != nil || slices.Contains(proposed, p) || !(a.IsPrivate() || globalV6.Contains(a)) {
			continue
		}
		proposed = append(proposed, p)
		sp := SetupPrefix{Key: "p:" + p.String(), Source: "local", Prefix: Prefix{Prefix: p.String(), Status: StatusActive, Scan: ScanPassive}}
		if globalV6.Contains(a) {
			sp.Prefix.DynSource = DynAuto
		}
		plan.Prefixes = append(plan.Prefixes, sp)
	}
	if !plan.DNS64 || m.dns.Unowned == nil {
		return plan, nil
	}
	hand, err := m.dns.Unowned(ctx)
	if err != nil {
		return nil, err
	}
	inPlan := func(ip netip.Addr) bool {
		if snap.NetOf(ip) != nil {
			return true
		}
		for _, sp := range plan.Prefixes {
			if pp, err := netip.ParsePrefix(sp.Prefix.Prefix); err == nil && pp.Contains(ip) {
				return true
			}
		}
		return false
	}
	byIP := map[string]*SetupAddress{}
	var order []string
	get := func(ip netip.Addr) (*SetupAddress, error) {
		k := ip.String()
		if s := byIP[k]; s != nil {
			return s, nil
		}
		s := &SetupAddress{Key: "a:" + k, Address: Address{Address: k, Status: StatusActive, PTR: true}}
		cur, err := m.addressWhere(ctx, `address = ?`, k)
		if err != nil {
			return nil, err
		}
		if cur != nil {
			s.Address, s.Exists = *cur, true
		}
		byIP[k] = s
		order = append(order, k)
		return s, nil
	}
	for _, r := range hand.Reservations {
		ip, err := netip.ParseAddr(r.IP)
		if err != nil || !inPlan(ip) {
			plan.Skipped = append(plan.Skipped, SetupSkip{What: r.MAC + " → " + r.IP, Reason: "ipam64.setup.skip.no_prefix"})
			continue
		}
		s, err := get(ip)
		if err != nil {
			return nil, err
		}
		if s.Address.MAC != "" && s.Address.MAC != r.MAC {
			plan.Skipped = append(plan.Skipped, SetupSkip{What: r.MAC + " → " + r.IP, Reason: "ipam64.setup.skip.mac_differs"})
			continue
		}
		s.Address.MAC, s.Address.DHCP = r.MAC, true
		if name := strings.ToLower(r.Name); s.Address.Name == "" && hostOK(name) {
			s.Address.Name = name
		}
		s.Claims = append(s.Claims, r.MAC+" → "+r.IP)
	}
	for _, r := range hand.Records {
		ip, err := netip.ParseAddr(r.Value)
		what := r.Name + " " + r.Type + " " + r.Value
		if err != nil || !inPlan(ip) {
			plan.Skipped = append(plan.Skipped, SetupSkip{What: what, Reason: "ipam64.setup.skip.no_prefix"})
			continue
		}
		label, zone, _ := strings.Cut(r.Name, ".")
		if !hostOK(label) || zone == "" {
			plan.Skipped = append(plan.Skipped, SetupSkip{What: what, Reason: "ipam64.setup.skip.name"})
			continue
		}
		s, err := get(ip)
		if err != nil {
			return nil, err
		}
		if s.Address.DNS && (s.Address.Name != label || zoneOf(snap, s.Address) != zone) || (s.Address.Name != "" && s.Address.Name != label) {
			plan.Skipped = append(plan.Skipped, SetupSkip{What: what, Reason: "ipam64.setup.skip.second_name"})
			continue
		}
		s.Address.Name, s.Address.DNS, s.Address.PTR = label, true, !r.NoPTR
		inherit := ""
		if n := snap.NetOf(ip); n != nil {
			inherit = n.DNSZone
		}
		for _, sp := range plan.Prefixes { // Zone eines vorgeschlagenen Praefixes (DHCP-Netz)
			if pp, err := netip.ParsePrefix(sp.Prefix.Prefix); err == nil && pp.Contains(ip) && inherit == "" {
				inherit = sp.Prefix.DNSZone
			}
		}
		if zone == inherit {
			s.Address.DNSZone = ""
		} else {
			s.Address.DNSZone = zone
		}
		s.Claims = append(s.Claims, what)
	}
	for _, k := range order {
		plan.Addresses = append(plan.Addresses, *byIP[k])
	}
	slices.SortFunc(plan.Addresses, func(a, b SetupAddress) int {
		return netip.MustParseAddr(a.Address.Address).Compare(netip.MustParseAddr(b.Address.Address))
	})
	return plan, nil
}

// SetupResult ist das Ergebnis des Assistenten.
type SetupResult struct {
	Prefixes, Addresses int
	Failed              []SetupSkip // Reason: uebersetzter Text
}

// ApplySetup legt die ausgewaehlten Vorschlaege an (keys: "p:<Praefix>", "a:<IP>"); errText uebersetzt Fehler.
func (m *Module) ApplySetup(ctx context.Context, keys []string, actor string, errText func(error) string) (SetupResult, error) {
	var res SetupResult
	plan, err := m.SetupPlan(ctx)
	if err != nil {
		return res, err
	}
	for _, sp := range plan.Prefixes {
		if !slices.Contains(keys, sp.Key) {
			continue
		}
		if _, err := m.SavePrefix(ctx, sp.Prefix, actor); err != nil {
			res.Failed = append(res.Failed, SetupSkip{What: sp.Prefix.Prefix, Reason: errText(err)})
			continue
		}
		res.Prefixes++
	}
	if res.Prefixes > 0 { // Adressen in den neuen Praefixen: Plan mit dem neuen Stand
		if plan, err = m.SetupPlan(ctx); err != nil {
			return res, err
		}
	}
	_ = m.batch(ctx, func(ctx context.Context) error {
		for _, sa := range plan.Addresses {
			if !slices.Contains(keys, sa.Key) {
				continue
			}
			if _, err := m.ApplyAddress(ctx, sa.Address, actor); err != nil {
				res.Failed = append(res.Failed, SetupSkip{What: sa.Address.Address, Reason: errText(err)})
				continue
			}
			res.Addresses++
		}
		return nil
	})
	return res, nil
}
