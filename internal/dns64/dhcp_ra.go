package dns64

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/dns64/ra"
	"github.com/ipv64net/node64/internal/metrics"
)

// IPv6-DNS per Router Advertisement (Paket ra, Plan D7): auf der DHCP-Seite, aber unabhaengig vom DHCP-Server.
// Opt-in je Node (nie im Cluster). Node64 kuendigt nur sich als DNS-Server an (RDNSS/DNSSL), Adressen und Route
// kommen weiter vom Router. Jede Node kuendigt sich selbst an; Geraete nehmen alle DNS-Server (Cluster ohne Absprache).

const (
	setRA       = "dns64.ra"        // on | off
	setRAIfaces = "dns64.ra_ifaces" // Schnittstellen, mit Komma
	setRADomain = "dns64.ra_domain" // Suchdomain (DNSSL), leer = keine

	raMaxIfaces = 8
	raProbeWait = 3 * time.Second
)

// RAConfig: Einstellungen fuer IPv6-DNS per RA (Seite, API).
type RAConfig struct {
	Enabled bool     `json:"enabled"`
	Ifaces  []string `json:"interfaces"`
	Domain  string   `json:"domain"`
}

// raState: laufender Sender und letzte Pruefung (m.dh).
type raState struct {
	mu     sync.Mutex // Start/Stopp
	cancel context.CancelFunc
	done   chan struct{}
	srv    atomic.Pointer[ra.Sender]
	probe  atomic.Pointer[raProbe]
}

type raProbe struct {
	At      time.Time
	Routers []ra.Router
	Err     string
}

func (m *Module) raConfig(ctx context.Context) RAConfig {
	return RAConfig{Enabled: m.core.SettingOr(ctx, setRA, "") == "on", Ifaces: dhcpList(m.core.SettingOr(ctx, setRAIfaces, "")),
		Domain: m.core.SettingOr(ctx, setRADomain, "")}
}

// SetRAConfig speichert die Einstellungen und startet den Sender passend.
func (m *Module) SetRAConfig(ctx context.Context, c RAConfig) (RAConfig, error) {
	var ifaces []string
	for _, n := range c.Ifaces {
		if n = strings.TrimSpace(n); n == "" || slices.Contains(ifaces, n) {
			continue
		}
		if !validIface(n) {
			return c, errCfg("err_dhcp_iface")
		}
		ifaces = append(ifaces, n)
	}
	if len(ifaces) > raMaxIfaces {
		return c, errCfg("err_ra_ifaces")
	}
	c.Ifaces = ifaces
	if c.Domain = hostName(c.Domain); c.Domain != "" && !validName(c.Domain) {
		return c, errCfg("err_dhcp_domain")
	}
	if c.Enabled && len(c.Ifaces) == 0 {
		return c, errCfg("err_ra_ifaces")
	}
	if c.Enabled && dhcpBridge() {
		return c, errCfg("err_dhcp_bridge")
	}
	for k, v := range map[string]string{setRA: map[bool]string{true: "on", false: "off"}[c.Enabled], setRAIfaces: strings.Join(c.Ifaces, ","), setRADomain: c.Domain} {
		if err := m.core.SetSetting(ctx, k, v); err != nil {
			return c, err
		}
	}
	m.raApply(ctx)
	return c, nil
}

// raApply startet den Sender mit dem aktuellen Stand neu (Modul laeuft und eingeschaltet) oder stoppt ihn.
func (m *Module) raApply(ctx context.Context) {
	m.ctl.Lock()
	defer m.ctl.Unlock()
	m.raApplyLocked(ctx)
}

// raApplyLocked: raApply mit gehaltenem m.ctl (Start).
func (m *Module) raApplyLocked(ctx context.Context) {
	ctx = context.WithoutCancel(ctx)
	m.mu.Lock()
	on := m.life != nil
	m.mu.Unlock()
	c := m.raConfig(ctx)
	m.dh.ra.mu.Lock()
	defer m.dh.ra.mu.Unlock()
	m.raHaltLocked()
	if !on || !c.Enabled || len(c.Ifaces) == 0 || dhcpBridge() {
		return
	}
	s := &ra.Sender{Ifaces: c.Ifaces, DNS: m.raDNS, Log: m.log.With("part", "ra")}
	if c.Domain != "" {
		s.Domains = []string{c.Domain}
	}
	rctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); s.Run(rctx) }()
	m.dh.ra.cancel, m.dh.ra.done = cancel, done
	m.dh.ra.srv.Store(s)
}

// raHalt stoppt den Sender (Modul aus); er nimmt die Ankuendigung vorher zurueck.
func (m *Module) raHalt() {
	m.dh.ra.mu.Lock()
	defer m.dh.ra.mu.Unlock()
	m.raHaltLocked()
}

func (m *Module) raHaltLocked() {
	if m.dh.ra.cancel != nil {
		m.dh.ra.cancel()
		<-m.dh.ra.done
		m.dh.ra.cancel, m.dh.ra.done = nil, nil
	}
	m.dh.ra.srv.Store(nil)
}

// raDNS: Adresse, die der Sender auf iface als DNS-Server ankuendigt - nur wenn DNS64 laeuft und dort per IPv6 auf
// Port 53 antwortet. Bevorzugt ULA (bleibt beim Praefixwechsel gleich), sonst die globale Adresse.
func (m *Module) raDNS(iface string) []netip.Addr {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if m.engNow.Load() == nil || m.port(ctx) != 53 {
		return nil
	}
	var bind netip.Addr
	if b, err := netip.ParseAddr(strings.TrimSpace(m.core.SettingOr(ctx, setBind, ""))); err == nil && !b.IsUnspecified() {
		if b.Is4() {
			return nil
		}
		bind = b
	}
	if a := raPick(ifaceAddrs6(iface), bind); a.IsValid() {
		return []netip.Addr{a}
	}
	return nil
}

// raPick waehlt die DNS-Adresse unter den IPv6-Adressen der Schnittstelle (bind gesetzt: nur diese).
func raPick(addrs []netip.Addr, bind netip.Addr) netip.Addr {
	if bind.IsValid() {
		if slices.Contains(addrs, bind) {
			return bind
		}
		return netip.Addr{}
	}
	var global netip.Addr
	for _, a := range addrs {
		switch {
		case a.Is6() && a.IsPrivate(): // ULA fc00::/7
			return a
		case a.Is6() && a.IsGlobalUnicast() && !global.IsValid():
			global = a
		}
	}
	return global
}

// ifaceAddrs6: IPv6-Adressen der Schnittstelle (mit link-lokalen).
func ifaceAddrs6(iface string) []netip.Addr {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil
	}
	addrs, _ := ifi.Addrs()
	var out []netip.Addr
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() == nil {
			if x, ok := netip.AddrFromSlice(n.IP); ok {
				out = append(out, x)
			}
		}
	}
	return out
}

// ---- Ansicht ----

// raIface: Schnittstelle mit IPv6 (Auswahl) und der Adresse, die angekuendigt wuerde.
type raIface struct {
	Name     string
	Addrs    []netip.Addr
	Pick     netip.Addr
	Selected bool
}

// raRouterView: Router im Netz mit Bewertung.
type raRouterView struct {
	ra.Router
	OtherDNS bool // kuendigt einen anderen DNS-Server an (Geraete fragen dann auch dort)
	OwnDNS   bool // kuendigt (auch) diese Node an
}

// DNSList: DNS-Server mit Komma (Hinweis).
func (r raRouterView) DNSList() string {
	var out []string
	for _, a := range r.DNS {
		out = append(out, a.String())
	}
	return strings.Join(out, ", ")
}

type raView struct {
	Config     RAConfig
	Running    bool
	Err        string // Socket
	Status     []ra.Status
	Ifaces     []raIface
	Routers    []raRouterView
	Probed     bool // Liste stammt aus der letzten Pruefung (Sender aus)
	ProbeAt    time.Time
	ProbeErr   string
	NoAddrs    bool   // Router bekannt, aber keiner vergibt Adressen
	DomainHint string // Domain eines DHCP-Netzes (Vorschlag)
}

func (m *Module) raView(ctx context.Context, scopes []DHCPScope) raView {
	v := raView{Config: m.raConfig(ctx)}
	for _, s := range scopes {
		if s.Domain != "" {
			v.DomainHint = s.Domain
			break
		}
	}
	own := map[netip.Addr]bool{}
	ifs, _ := net.Interfaces()
	for _, ifi := range ifs {
		addrs := ifaceAddrs6(ifi.Name)
		for _, a := range addrs {
			own[a] = true
		}
		sel := slices.Contains(v.Config.Ifaces, ifi.Name)
		if !sel && (ifi.Flags&net.FlagLoopback != 0 || ifi.Flags&net.FlagUp == 0 || virtualIface(ifi.Name) || len(addrs) == 0) {
			continue
		}
		v.Ifaces = append(v.Ifaces, raIface{Name: ifi.Name, Addrs: addrs, Pick: raPick(addrs, netip.Addr{}), Selected: sel})
	}
	var routers []ra.Router
	if s := m.dh.ra.srv.Load(); s != nil {
		v.Running, v.Err, v.Status, routers = true, s.Err(), s.Status(), s.Routers()
	} else if p := m.dh.ra.probe.Load(); p != nil {
		v.Probed, v.ProbeAt, v.ProbeErr, routers = true, p.At, p.Err, p.Routers
	}
	addrs := false
	for _, r := range routers {
		rv := raRouterView{Router: r}
		for _, d := range r.DNS {
			if own[d] {
				rv.OwnDNS = true
			} else {
				rv.OtherDNS = true
			}
		}
		addrs = addrs || r.Addresses()
		v.Routers = append(v.Routers, rv)
	}
	v.NoAddrs = len(routers) > 0 && !addrs
	return v
}

// raProbeRun fragt die Router auf den gewaehlten (sonst allen angezeigten) Schnittstellen.
func (m *Module) raProbeRun(ctx context.Context) *raProbe {
	p := &raProbe{At: time.Now(), Routers: []ra.Router{}}
	names := m.raConfig(ctx).Ifaces
	if len(names) == 0 {
		for _, i := range m.raView(ctx, nil).Ifaces {
			names = append(names, i.Name)
		}
	}
	type res struct {
		r   []ra.Router
		err error
	}
	ch := make(chan res, len(names))
	for _, n := range names { // gleichzeitig: jede Pruefung wartet raProbeWait
		go func() {
			r, err := ra.Probe(ctx, n, raProbeWait)
			ch <- res{r, err}
		}()
	}
	var errs []string
	for range names {
		x := <-ch
		if x.err != nil {
			errs = append(errs, x.err.Error())
		}
		p.Routers = append(p.Routers, x.r...)
	}
	slices.SortFunc(p.Routers, func(a, b ra.Router) int {
		if c := strings.Compare(a.Iface, b.Iface); c != 0 {
			return c
		}
		return a.Source.Compare(b.Source)
	})
	p.Err = strings.Join(errs, "; ")
	m.dh.ra.probe.Store(p)
	return p
}

// ---- Prometheus ----

func (m *Module) raMetrics(w *metrics.Writer) {
	s := m.dh.ra.srv.Load()
	if s == nil {
		return
	}
	w.Gauge("node64_dns64_ra_up", "IPv6-DNS per Router Advertisement eingeschaltet und Socket offen.", metrics.Bool(s.Err() == ""))
	w.Counter("node64_dns64_ra_sent_total", "Gesendete Router Advertisements (nur DNS-Server).", float64(s.Sent()))
	for _, st := range s.Status() {
		w.Gauge("node64_dns64_ra_announcing", "Schnittstelle kuendigt gerade einen DNS-Server an.", metrics.Bool(len(st.DNS) > 0 && st.ErrKind == ""), "interface", st.Iface)
	}
}

// ---- Seite und API ----

func (m *Module) pageRASave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	c := RAConfig{Enabled: r.PostFormValue("enabled") == "1", Ifaces: r.PostForm["iface"], Domain: r.PostFormValue("domain")}
	c, err := m.SetRAConfig(r.Context(), c)
	if err == nil {
		m.audit(r, "dns64.dhcp.ra", onOff(c.Enabled), strings.Join(c.Ifaces, ","))
	}
	m.dhcpBack(w, r, err, "common.saved")
}

func (m *Module) pageRAProbe(w http.ResponseWriter, r *http.Request) {
	m.raProbeRun(r.Context())
	http.Redirect(w, r, "/dns64/dhcp#ipv6", http.StatusSeeOther)
}

func (m *Module) apiRA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := struct {
		Config  RAConfig    `json:"config"`
		Running bool        `json:"running"`
		Error   string      `json:"error,omitempty"`
		Status  []ra.Status `json:"status"`
		Routers []ra.Router `json:"routers"`
	}{Config: m.raConfig(ctx), Status: []ra.Status{}, Routers: []ra.Router{}}
	if s := m.dh.ra.srv.Load(); s != nil {
		out.Running, out.Error, out.Status, out.Routers = true, s.Err(), s.Status(), s.Routers()
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) apiRASave(w http.ResponseWriter, r *http.Request) {
	var c RAConfig
	if !decode(w, r, &c) {
		return
	}
	c, err := m.SetRAConfig(r.Context(), c)
	if err == nil {
		m.audit(r, "dns64.dhcp.ra", onOff(c.Enabled), strings.Join(c.Ifaces, ","))
	}
	m.apiResult(w, r, err, http.StatusOK, c)
}

func (m *Module) apiRAProbe(w http.ResponseWriter, r *http.Request) {
	p := m.raProbeRun(r.Context())
	writeJSON(w, http.StatusOK, struct {
		Routers []ra.Router `json:"routers"`
		Error   string      `json:"error,omitempty"`
	}{p.Routers, p.Err})
}
