package main

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/ipam64"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
)

// newIPAM legt IPAM64 an (standardmaessig aus) und haengt die Quellen an (Verdrahtung aus dem Entwurf von
// UlrichSchwarz). Jede Quelle liefert nichts, solange ihr Modul nicht laeuft. Die Reihenfolge bestimmt, wessen Name
// gewinnt (DHCP vor lokalem DNS vor Monitor64, Healthchecks, PROXY64); feste Adressen in IPAM64 gehen allen vor.
func newIPAM(st *store.Store, log *slog.Logger, modules *module.Registry, dns *dns64.Module, hc *healthchecks.Module, m64 *monitor64.Module, cdn *cdn64.Module) *ipam64.Module {
	m := ipam64.New(st, log)
	running := func() bool { return modules.IsRunning(dns64.Name) }
	m.SetDNS64(ipam64.DNS64{ // Schreibweg nach DNS64 (Plan E1): gekennzeichnete Reservierungen, Ausnahmen, Eintraege
		Running:           running,
		PutReservation:    dns.PutIPAMReservation,
		DeleteReservation: dns.DeleteIPAMReservation,
		PutExclude:        dns.PutIPAMExclude,
		DeleteExclude:     dns.DeleteIPAMExclude,
		PutRecords:        dns.PutIPAMRecords,
		DeleteRecords:     dns.DeleteIPAMRecords,
		Release:           dns.ReleaseIPAM,
		Batch:             dns.IPAMBatch,
		Check:             dns64.IPAMCheck,
		Names:             dns.ClientNames, // Rechnernamen vom Router fuer Adressen ohne Namen (Forum 5228)
		Entries: func(ctx context.Context) (ipam64.Owned, error) {
			st, err := dns.IPAMEntries(ctx)
			var o ipam64.Owned
			for _, r := range st.Reservations {
				o.Reservations = append(o.Reservations, ipam64.OwnedRes{Ref: r.Ref, MAC: r.MAC, IP: r.IP, Name: r.Name})
			}
			for _, x := range st.Excludes {
				o.Excludes = append(o.Excludes, ipam64.OwnedExcl{Ref: x.Ref, IP: x.IP})
			}
			for _, r := range st.Records {
				o.Records = append(o.Records, ipam64.OwnedRec{Ref: r.Ref, Name: r.Name, Type: r.Type, Value: r.Value, NoPTR: r.NoPTR})
			}
			return o, err
		},
		Unowned: func(ctx context.Context) (ipam64.Owned, error) { // Hand-Eintraege fuer den Assistenten (ohne Docker, Platzhalter)
			var o ipam64.Owned
			res, err := dns.DHCPReservations(ctx)
			if err != nil {
				return o, err
			}
			for _, r := range res {
				if r.Origin == "" {
					o.Reservations = append(o.Reservations, ipam64.OwnedRes{MAC: r.MAC, IP: r.IP, Name: r.Name})
				}
			}
			recs, err := dns.Records(ctx)
			for _, r := range recs {
				if r.Origin == "" && r.Enabled && !r.LocalOnly && (r.Type == "A" || r.Type == "AAAA") && !strings.HasPrefix(r.Name, "*") {
					o.Records = append(o.Records, ipam64.OwnedRec{Name: r.Name, Type: r.Type, Value: r.Value, NoPTR: r.NoPTR})
				}
			}
			return o, err
		},
		ErrKey: dns64.ErrKey,
	})
	scopes := func(ctx context.Context) []dns64.DHCPScope {
		if !modules.IsRunning(dns64.Name) {
			return nil
		}
		list, _ := dns.DHCPScopes(ctx)
		return list
	}
	m.SetForeign(func(ctx context.Context) []ipam64.ForeignDHCP { // fremde DHCP-Server (Hinweis in Scan & Konflikte)
		if !running() {
			return nil
		}
		var out []ipam64.ForeignDHCP
		for n, list := range dns.DHCPForeign(ctx) {
			for _, s := range list {
				out = append(out, ipam64.ForeignDHCP{Net: n, Server: s.String()})
			}
		}
		return out
	})
	m.SetNetworks(func(ctx context.Context) []ipam64.NetHint {
		var out []ipam64.NetHint
		for _, s := range scopes(ctx) {
			p, err := netip.ParsePrefix(s.Subnet)
			if err != nil {
				continue
			}
			// ausgeschaltete Netze (Standard fuer Netze aus dem Cluster) nur fuer die Ausnahmen fester Adressen im Pool
			h := ipam64.NetHint{Name: s.Name, Iface: s.Iface, Subnet: p, Domain: s.Domain, Off: !s.Enabled}
			h.Router, _ = netip.ParseAddr(s.Router)
			h.Start, _ = netip.ParseAddr(s.Start)
			h.End, _ = netip.ParseAddr(s.End)
			out = append(out, h)
		}
		return out
	})
	m.SetSource(ipam64.SrcDHCP, func(ctx context.Context) []ipam64.Sighting {
		list := scopes(ctx)
		if list == nil {
			return nil
		}
		lease := map[int64]time.Duration{}
		for _, s := range list {
			lease[s.ID] = time.Duration(s.LeaseHours) * time.Hour
		}
		var out []ipam64.Sighting
		res, _ := dns.DHCPReservations(ctx)
		for _, r := range res {
			out = append(out, ipam64.Sighting{Addr: r.IP, MAC: r.MAC, Name: r.Name, Note: r.Comment, Kind: ipam64.KindFixed})
		}
		now := time.Now()
		for _, l := range dns.DHCPLeases(ctx) {
			if !l.Active(now) {
				continue
			}
			s := ipam64.Sighting{Addr: l.IP.String(), MAC: l.MAC, Name: l.Hostname, Kind: ipam64.KindDHCP}
			if d := lease[l.Scope]; d > 0 { // letzte Verlaengerung = Ablauf minus Laufzeit
				s.Seen = l.Expires.Add(-d)
			}
			out = append(out, s)
		}
		return out
	})
	m.SetSource(ipam64.SrcDNS, func(ctx context.Context) []ipam64.Sighting {
		if !modules.IsRunning(dns64.Name) {
			return nil
		}
		list, _ := dns.Records(ctx)
		var out []ipam64.Sighting
		for _, r := range list {
			if (r.Type == "A" || r.Type == "AAAA") && r.Enabled && !strings.HasPrefix(r.Name, "*") {
				out = append(out, ipam64.Sighting{Addr: r.Value, Name: r.Name, Note: r.Comment})
			}
		}
		return out
	})
	m.SetSource(ipam64.SrcMonitor64, func(ctx context.Context) []ipam64.Sighting {
		if !modules.IsRunning(monitor64.Name) {
			return nil
		}
		var out []ipam64.Sighting
		for _, v := range m64.Views() {
			if v.Host == nil || v.Host.Address == "" {
				continue
			}
			s := ipam64.Sighting{Addr: v.Host.Address, Name: v.Host.Name, Note: v.Host.Kind}
			for _, a := range v.Accesses {
				if a.OK {
					s.Seen = v.Checked
				}
			}
			out = append(out, s)
		}
		return out
	})
	m.SetSource(ipam64.SrcHealthchecks, func(ctx context.Context) []ipam64.Sighting {
		if !modules.IsRunning(healthchecks.Name) {
			return nil
		}
		list, _ := hc.Store().Checks(ctx)
		var out []ipam64.Sighting
		for _, c := range list {
			if c.Target == "" || c.Owner == "online" || c.Owner == "other" || c.Execution == "online" { // nur hier gemessen
				continue
			}
			s := ipam64.Sighting{Addr: c.Target, Name: c.Name}
			if c.Runtime.State == scheduler.StateUp && !c.Invert {
				s.Seen = c.Runtime.LastCheck
			}
			out = append(out, s)
		}
		return out
	})
	m.SetSource(ipam64.SrcProxy, func(ctx context.Context) []ipam64.Sighting {
		if !modules.IsRunning(cdn64.Name) {
			return nil
		}
		var out []ipam64.Sighting
		for _, t := range cdn.ProxyTargets(ctx) {
			out = append(out, ipam64.Sighting{Addr: t.Host, Note: t.Name})
		}
		return out
	})
	return m
}
