package cdn64

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Lokaler DNS (DNS64): Die Namen eines Hosts als eigene Eintraege (ohne Zone) auf die Adresse des Reverse-Proxys,
// damit das Heimnetz direkt zugreift statt ueber das Internet. Vorhandene Eintraege bleiben unberuehrt.

// LocalRecord ist ein eigener DNS64-Eintrag (Ausschnitt).
type LocalRecord struct {
	Name, Type, Value string
}

// LocalDNS ist der Zugriff auf die eigenen Eintraege von DNS64.
type LocalDNS interface {
	Records(ctx context.Context) ([]LocalRecord, error)
	Add(ctx context.Context, r LocalRecord, comment string) error
}

// SetLocalDNS haengt DNS64 an (f liefert nil, solange DNS64 aus ist).
func (m *Module) SetLocalDNS(f func() LocalDNS) { m.localDNS = f }

func (m *Module) ldns() LocalDNS {
	if m.localDNS == nil {
		return nil
	}
	return m.localDNS()
}

// localIndex: Name -> vorhandene Typen (A, AAAA, CNAME) in DNS64; nil = DNS64 aus.
func (m *Module) localIndex(ctx context.Context) map[string]map[string]bool {
	l := m.ldns()
	if l == nil {
		return nil
	}
	list, err := l.Records(ctx)
	if err != nil {
		return nil
	}
	idx := map[string]map[string]bool{}
	for _, r := range list {
		if idx[r.Name] == nil {
			idx[r.Name] = map[string]bool{}
		}
		idx[r.Name][r.Type] = true
	}
	return idx
}

// localCount: wie viele Namen des Hosts schon in DNS64 stehen (A, AAAA oder CNAME).
func localCount(idx map[string]map[string]bool, names []string) int {
	n := 0
	for _, name := range names {
		t := idx[strings.ToLower(name)]
		if t["A"] || t["AAAA"] || t["CNAME"] {
			n++
		}
	}
	return n
}

// localAddrs schlaegt die Adressen des Reverse-Proxys vor: die Adresse, ueber die die Oberflaeche gerade aufgerufen
// wird, sonst die der Node im LAN (nicht im Docker-Bridge-Netz, dort kennt nur der Aufruf die Adresse des Hosts).
func (m *Module) localAddrs(r *http.Request) (v4, v6 string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !a.IsLoopback() {
		if a = a.Unmap(); a.Is4() {
			v4 = a.String()
		} else {
			v6 = a.WithZone("").String()
		}
	}
	if m.published(r.Context()).Bridge {
		return v4, v6
	}
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || virtualIf(ifc.Name) {
			continue
		}
		list, _ := ifc.Addrs()
		for _, x := range list {
			n, ok := x.(*net.IPNet)
			if !ok {
				continue
			}
			a, ok := netip.AddrFromSlice(n.IP)
			if !ok {
				continue
			}
			a = a.Unmap()
			switch {
			case v4 == "" && a.Is4() && a.IsPrivate():
				v4 = a.String()
			case v6 == "" && a.Is6() && a.IsGlobalUnicast():
				v6 = a.String()
			}
		}
	}
	return v4, v6
}

// virtualIf: Schnittstellen von Docker, Bruecken und VMs (deren Adressen erreicht im Heimnetz niemand).
func virtualIf(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "cni", "flannel", "podman", "lxc", "tun", "wg"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// addLocal traegt die Namen des Hosts mit den Adressen in DNS64 ein. Ein Name, der schon einen Eintrag dieses Typs
// oder einen CNAME hat, wird uebersprungen. Liefert angelegte und uebersprungene Eintraege.
func (m *Module) addLocal(ctx context.Context, h *Host, v4, v6 string) (added int, skipped []string, err error) {
	l := m.ldns()
	if l == nil {
		return 0, nil, errors.New("DNS64 is switched off")
	}
	var want []LocalRecord
	for _, s := range []string{v4, v6} {
		s = strings.TrimSpace(strings.Trim(strings.TrimSpace(s), "[]"))
		if s == "" {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return 0, nil, ferr("ip", "cdn64.err.localdns_ip")
		}
		typ := "AAAA"
		if a = a.Unmap(); a.Is4() {
			typ = "A"
		}
		want = append(want, LocalRecord{Type: typ, Value: a.String()})
	}
	if len(want) == 0 {
		return 0, nil, ferr("ip", "cdn64.err.localdns_ip")
	}
	idx := m.localIndex(ctx)
	for _, name := range h.Names {
		name = strings.ToLower(name)
		for _, w := range want {
			if t := idx[name]; t["CNAME"] || t[w.Type] {
				skipped = append(skipped, name+" "+w.Type)
				continue
			}
			w.Name = name
			if err := l.Add(ctx, w, "PROXY64"); err != nil {
				return added, skipped, err
			}
			added++
		}
	}
	return added, skipped, nil
}

// POST /cdn64/hosts/{id}/localdns (ipv4, ipv6): Namen des Hosts in DNS64 eintragen.
func (m *Module) pageHostLocalDNS(w http.ResponseWriter, r *http.Request) {
	h, err := m.host(r.Context(), pathID(r))
	back := "/cdn64"
	if err == nil {
		back = listPath(h.Kind)
		var added int
		var skipped []string
		added, skipped, err = m.addLocal(r.Context(), h, r.PostFormValue("ipv4"), r.PostFormValue("ipv6"))
		if added > 0 {
			m.g.Audit(r, "cdn64.localdns", strings.Join(h.Names, ","), strings.TrimSpace(r.PostFormValue("ipv4")+" "+r.PostFormValue("ipv6")))
		}
		if err == nil {
			msg := m.g.T(r, "cdn64.localdns.added", "n", added)
			if len(skipped) > 0 {
				msg += " " + m.g.T(r, "cdn64.localdns.skipped", "list", strings.Join(skipped, ", "))
			}
			m.g.Flash(w, r, map[bool]string{true: "success", false: "warning"}[added > 0], msg)
		}
	}
	if err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			m.g.Flash(w, r, "danger", m.g.T(r, fe.Key))
		} else {
			m.g.Flash(w, r, "danger", m.g.T(r, "cdn64.localdns.failed", "error", err.Error()))
		}
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
