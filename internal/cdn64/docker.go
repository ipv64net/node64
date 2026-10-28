package cdn64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Abgleich der Proxy-Hosts mit den Docker-Labels (Plan docs/PLAN-PROXY64-DOCKER.md, Phase D1). Nur mit Schalter
// setDocker = "on". Die Docker-API (nur GET) liefert beim Start und alle dockerFullEvery die volle Liste; dazwischen
// loesen Ereignisse (start, die, destroy, rename) entprellt einen Abgleich aus. Labels legen Namen, Schema und Ziel
// fest, alles andere bleibt wie in der Oberflaeche eingestellt. Fehlt ein Container (bzw. sein Label) in einer
// erfolgreich gelesenen Liste dockerRemoveWait lang ununterbrochen, wird sein Host geloescht (samt Abmelden bei
// CDN64 online); Fehler beim Lesen loeschen nie etwas. Schalter aus: die Hosts bleiben, wie sie sind.

// Zeiten (Variablen, damit Tests sie verkuerzen koennen).
var (
	dockerFullEvery    = 5 * time.Minute  // volle Liste
	dockerRetry        = 30 * time.Second // nach einem Fehler frueher wiederholen
	dockerDebounce     = 2 * time.Second  // Ereignisse zusammenfassen
	dockerRemoveWait   = 2 * time.Minute  // so lange fehlt ein Container, bevor sein Host geloescht wird
	dockerBackoffStart = time.Second      // Ereignis-Stream: Wartezeit vor neuem Verbinden (verdoppelt)
	dockerBackoffMax   = time.Minute
	dockerReqTimeout   = 10 * time.Second // je Anfrage (nicht der Ereignis-Stream)
)

// dockerSelf liefert den Namen des eigenen Containers (Hostname = Container-ID bzw. hostname:; Tests ersetzen ihn).
var dockerSelf = os.Hostname

// dockerState ist der Zustand des Abgleichs.
type dockerState struct {
	kick    chan struct{}
	pending atomic.Bool // Ereignis gesehen, Abgleich folgt nach dockerDebounce

	run  sync.Mutex           // ein Abgleich gleichzeitig
	gone map[string]time.Time // Kennung (Container, Router) -> fehlt seit (nur unter run)

	mu   sync.Mutex
	view dockerView
	acl  map[int64]string // Host -> Zugriffsliste aus den Labels (Feld in der Oberflaeche gesperrt)
}

// dockerContainerView ist ein Container mit Labels (bzw. ein Traefik-Router) fuer die Oberflaeche.
type dockerContainerView struct {
	Name        string   `json:"name"`
	State       string   `json:"state"` // wie Docker (running, exited ...)
	Source      string   `json:"source"`
	Router      string   `json:"router,omitempty"`
	Names       []string `json:"names,omitempty"`
	Target      string   `json:"target,omitempty"`  // scheme://ip:port ("" = keins)
	HostID      int64    `json:"host_id,omitempty"` // 0 = nicht uebernommen
	Access      string   `json:"access,omitempty"`  // Zugriffsliste aus den Labels ("" = in der Oberflaeche)
	Problem     string   `json:"problem,omitempty"` // dockerErr* ("" = ok)
	ProblemName string   `json:"problem_name,omitempty"`
}

// dockerView ist der Stand des Abgleichs fuer die Oberflaeche.
type dockerView struct {
	Enabled    bool                  `json:"enabled"`
	Connected  bool                  `json:"connected"`
	Host       string                `json:"host"`            // Docker-API wie benutzt
	Error      string                `json:"error,omitempty"` // letzter Fehler ("" = keiner)
	Synced     time.Time             `json:"synced"`          // letzter erfolgreicher Abgleich (Null = noch keiner)
	Containers []dockerContainerView `json:"containers"`      // nur Container mit node64.proxy.* bzw. traefik.*-Labels
}

func (m *Module) dockerOn(ctx context.Context) bool {
	return m.core.SettingOr(ctx, setDocker, "") == "on"
}

// dockerAddr: Docker-API aus der Einstellung, sonst wie die Docker-Ueberwachung.
func (m *Module) dockerAddr(ctx context.Context) string {
	if h := strings.TrimSpace(m.core.SettingOr(ctx, setDockerHost, "")); h != "" {
		return h
	}
	return proxmox.DefaultDockerHost()
}

// dockerKick: Einstellungen geaendert (Schalter, Docker-Host) - gleich abgleichen bzw. anhalten.
func (m *Module) dockerKick() {
	select {
	case m.dk.kick <- struct{}{}:
	default:
	}
}

// dockerEvent: Ereignis gesehen - Abgleich nach dockerDebounce (weitere Ereignisse bis dahin zaehlen mit).
func (m *Module) dockerEvent() {
	if m.dk.pending.CompareAndSwap(false, true) {
		time.AfterFunc(dockerDebounce, func() {
			m.dk.pending.Store(false)
			m.dockerKick()
		})
	}
}

// dockerView liefert den Stand fuer die Oberflaeche.
func (m *Module) dockerView(ctx context.Context) dockerView {
	m.dk.mu.Lock()
	v := m.dk.view
	v.Containers = slices.Clone(v.Containers)
	m.dk.mu.Unlock()
	v.Enabled = m.dockerOn(ctx)
	if !v.Enabled {
		v.Connected, v.Error = false, ""
	}
	if v.Host == "" {
		v.Host = m.dockerAddr(ctx)
	}
	if v.Containers == nil {
		v.Containers = []dockerContainerView{}
	}
	return v
}

// dockerHostLabel: Anzeige der Herkunft eines Docker-Hosts ("" = von Hand).
func (m *Module) dockerHostLabel(h *Host) string {
	if h.DockerContainer == "" {
		return ""
	}
	if h.DockerRouter != "" {
		return h.DockerContainer + " / " + h.DockerRouter
	}
	return h.DockerContainer
}

func dockerKey(container, router string) string { return container + "\x00" + router }

// dockerReset: Schalter aus bzw. Modul gestoppt - Wartezeiten vergessen, Stand leeren.
func (m *Module) dockerReset() {
	m.dk.run.Lock()
	m.dk.gone = nil
	m.dk.run.Unlock()
	m.dk.mu.Lock()
	m.dk.view = dockerView{}
	m.dk.mu.Unlock()
}

// dockerFailed merkt einen Fehler (Hinweis wie die Docker-Ueberwachung); die Hosts bleiben unveraendert.
func (m *Module) dockerFailed(host string, err error) {
	msg := proxmox.DockerHint(host, err)
	m.dk.mu.Lock()
	was := m.dk.view.Error
	m.dk.view.Connected, m.dk.view.Error, m.dk.view.Host = false, msg, host
	m.dk.mu.Unlock()
	if was == "" {
		m.log.Warn("cdn64 docker: api failed", "host", host, "err", msg)
	}
}

// dockerLoop gleicht ab, solange das Modul laeuft (Schalter aus: wartet auf dockerKick).
func (m *Module) dockerLoop(ctx context.Context) {
	var evStop context.CancelFunc
	var evDone chan struct{}
	evHost := ""
	stopEv := func() {
		if evStop != nil {
			evStop()
			<-evDone
			evStop, evDone, evHost = nil, nil, ""
		}
	}
	defer func() {
		stopEv()
		m.dockerReset()
	}()
	for {
		wait := dockerFullEvery
		if m.dockerOn(ctx) {
			host := m.dockerAddr(ctx)
			hc, base, err := proxmox.DockerClient(host)
			if err != nil {
				stopEv()
				m.dockerFailed(host, err)
			} else {
				if host != evHost {
					stopEv()
					ectx, cancel := context.WithCancel(ctx)
					done := make(chan struct{})
					go func() { defer close(done); m.dockerEvents(ectx, hc, base) }()
					evStop, evDone, evHost = cancel, done, host
				}
				wait = m.dockerSync(ctx, hc, base, host)
			}
		} else {
			stopEv()
			m.dockerReset()
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-m.dk.kick:
			t.Stop()
		}
	}
}

// dockerEvents liest den Ereignis-Stream, bis ctx endet; nach Abbruch neu verbinden (Wartezeit verdoppelt).
func (m *Module) dockerEvents(ctx context.Context, hc *http.Client, base string) {
	wait, again := dockerBackoffStart, false
	for {
		if m.dockerWatch(ctx, hc, base, again) {
			wait = dockerBackoffStart
		}
		again = true
		if ctx.Err() != nil {
			return
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		wait = min(wait*2, dockerBackoffMax)
	}
}

// dockerWatch: eine Verbindung zum Ereignis-Stream (ohne Zeitlimit); true = war verbunden. kick: nach Wiederverbinden
// einmal abgleichen (Ereignisse waehrend der Unterbrechung fehlen).
func (m *Module) dockerWatch(ctx context.Context, hc *http.Client, base string, kick bool) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/events?filters="+url.QueryEscape(`{"type":["container"]}`), nil)
	if err != nil {
		return false
	}
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	if kick {
		m.dockerKick()
	}
	dec := json.NewDecoder(resp.Body)
	for {
		var ev struct {
			Action string `json:"Action"`
			Status string `json:"status"` // aeltere APIs
		}
		if err := dec.Decode(&ev); err != nil {
			return true
		}
		a := ev.Action
		if a == "" {
			a = ev.Status
		}
		switch a {
		case "start", "die", "destroy", "rename":
			m.dockerEvent()
		}
	}
}

// ---------------------------------------------------------------- Docker-API

// dockerListC ist der benutzte Teil eines Eintrags aus /containers/json.
type dockerListC struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	State   string            `json:"State"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		PrivatePort int    `json:"PrivatePort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

func (c *dockerListC) name() string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	return c.ID
}

// dockerNet ist ein Netz eines Containers.
type dockerNet struct {
	IPAddress         string `json:"IPAddress"`
	GlobalIPv6Address string `json:"GlobalIPv6Address"`
	Gateway           string `json:"Gateway"`
}

func (n dockerNet) ip() string {
	if n.IPAddress != "" {
		return n.IPAddress
	}
	return n.GlobalIPv6Address
}

// dockerInspectC ist der benutzte Teil von /containers/{id}/json.
type dockerInspectC struct {
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Networks map[string]dockerNet `json:"Networks"`
		Ports    map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// netNames: Netze des Containers, sortiert (das "erste" Netz ist damit fest).
func (in *dockerInspectC) netNames() []string {
	out := make([]string, 0, len(in.NetworkSettings.Networks))
	for k := range in.NetworkSettings.Networks {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// gateway: Docker-Gateway des ersten Netzes (Adresse des Docker-Hosts aus Sicht des Containers).
func (in *dockerInspectC) gateway() string {
	for _, k := range in.netNames() {
		if gw := in.NetworkSettings.Networks[k].Gateway; gw != "" {
			return gw
		}
	}
	return ""
}

// dockerGet fragt einen Pfad ab (JSON, hoechstens 8 MiB); liefert auch den HTTP-Status.
func dockerGet(ctx context.Context, hc *http.Client, base, path string, v any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerReqTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		return resp.StatusCode, fmt.Errorf("docker api %s: %d %s", strings.SplitN(path, "?", 2)[0], resp.StatusCode, strings.TrimSpace(e.Message))
	}
	return resp.StatusCode, json.Unmarshal(b, v)
}

// ---------------------------------------------------------------- Abgleich

// dockerSync gleicht einmal ab; Ergebnis: spaetestens nach dieser Zeit wieder.
func (m *Module) dockerSync(ctx context.Context, hc *http.Client, base, host string) time.Duration {
	m.dk.run.Lock()
	defer m.dk.run.Unlock()
	var list []dockerListC
	if _, err := dockerGet(ctx, hc, base, "/containers/json?all=1", &list); err != nil {
		m.dockerFailed(host, err)
		return dockerRetry
	}
	var self *dockerInspectC // eigener Container (nil = keiner gefunden, z. B. Node64 im Host-Netz)
	if hn, err := dockerSelf(); err == nil && hn != "" {
		var in dockerInspectC
		if _, err := dockerGet(ctx, hc, base, "/containers/"+url.PathEscape(hn)+"/json", &in); err == nil {
			self = &in
		}
	}
	hosts, err := m.hosts(ctx)
	if err != nil {
		m.dockerFailed(host, err)
		return dockerRetry
	}
	traefik := m.core.SettingOr(ctx, setDockerTraefik, "") != "off"
	// aeltere Container zuerst: bei gleichem Namen gewinnt der zuerst gesehene
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Created != list[j].Created {
			return list[i].Created < list[j].Created
		}
		return list[i].name() < list[j].name()
	})
	seen := map[string]bool{}
	views := []dockerContainerView{}
	for i := range list {
		c := &list[i]
		specs, probs := dockerSpecs(c.Labels, traefik)
		if len(specs) == 0 && len(probs) == 0 {
			continue
		}
		name := c.name()
		for _, p := range probs { // ungueltige Labels: kein neuer Host, ein vorhandener bleibt wie er ist
			seen[dockerKey(name, p.Router)] = true
			src := dockerSrcTraefik
			if p.Router == "" {
				src = dockerSrcNode64
			}
			v := dockerContainerView{Name: name, State: c.State, Source: src, Router: p.Router, Problem: p.Key, ProblemName: p.Name}
			if h := dockerHostOf(hosts, name, p.Router); h != nil {
				v.HostID, v.Names = h.ID, h.Names
			}
			views = append(views, v)
		}
		if len(specs) == 0 {
			continue
		}
		var in dockerInspectC
		code, err := dockerGet(ctx, hc, base, "/containers/"+url.PathEscape(c.ID)+"/json", &in)
		if code == http.StatusNotFound {
			continue // eben entfernt: zaehlt als fehlend
		}
		if err != nil {
			m.dockerFailed(host, err)
			return dockerRetry
		}
		for _, s := range specs {
			seen[dockerKey(name, s.Router)] = true
			v, err := m.dockerApply(ctx, &hosts, name, c, &in, self, s)
			if err != nil {
				m.dockerFailed(host, err)
				return dockerRetry
			}
			views = append(views, v)
		}
	}
	wait := m.dockerRemove(ctx, hosts, seen)
	acl := map[int64]string{}
	for _, v := range views {
		if v.Access != "" && v.HostID > 0 {
			acl[v.HostID] = v.Access
		}
	}
	m.dk.mu.Lock()
	m.dk.view.Connected, m.dk.view.Error, m.dk.view.Host, m.dk.view.Synced, m.dk.view.Containers = true, "", host, time.Now(), views
	m.dk.acl = acl
	m.dk.mu.Unlock()
	return wait
}

// dockerRemove loescht Docker-Hosts, deren Container (bzw. Label) dockerRemoveWait lang ununterbrochen fehlt;
// Ergebnis: Zeit bis zum naechsten Abgleich (spaetestens dockerFullEvery).
func (m *Module) dockerRemove(ctx context.Context, hosts []*Host, seen map[string]bool) time.Duration {
	if m.dk.gone == nil {
		m.dk.gone = map[string]time.Time{}
	}
	now := time.Now()
	wait := dockerFullEvery
	live := map[string]bool{}
	for _, h := range hosts {
		if h.DockerContainer == "" {
			continue
		}
		k := dockerKey(h.DockerContainer, h.DockerRouter)
		live[k] = true
		if seen[k] {
			delete(m.dk.gone, k)
			continue
		}
		since, ok := m.dk.gone[k]
		if !ok {
			since = now
			m.dk.gone[k] = now
			m.log.Info("cdn64 docker: container missing, host will be removed", "container", m.dockerHostLabel(h), "names", strings.Join(h.Names, ","),
				"after", dockerRemoveWait.String())
		}
		if left := dockerRemoveWait - now.Sub(since); left > 0 {
			wait = min(wait, left)
			continue
		}
		if err := m.deleteHost(ctx, h.ID); err != nil && !errors.Is(err, errNotFound) {
			m.log.Warn("cdn64 docker: delete host failed", "container", m.dockerHostLabel(h), "err", err)
			wait = min(wait, dockerRetry)
			continue
		}
		delete(m.dk.gone, k)
		m.log.Info("cdn64 docker: host deleted", "container", m.dockerHostLabel(h), "names", strings.Join(h.Names, ","))
	}
	for k := range m.dk.gone {
		if !live[k] {
			delete(m.dk.gone, k)
		}
	}
	return wait
}

// dockerApply legt den Host eines Containers an bzw. uebernimmt Namen, Schema und Ziel aus den Labels.
// Fehler nur bei Problemen mit der Datenbank (Probleme mit den Labels stehen in der Ansicht).
func (m *Module) dockerApply(ctx context.Context, hosts *[]*Host, name string, c *dockerListC, in, self *dockerInspectC, s dockerSpec) (dockerContainerView, error) {
	v := dockerContainerView{Name: name, State: c.State, Source: s.Source, Router: s.Router, Names: s.Names}
	h := dockerHostOf(*hosts, name, s.Router)
	if h != nil {
		v.HostID = h.ID
	}
	fail := func(key, val string) (dockerContainerView, error) {
		v.Problem, v.ProblemName = key, val
		return v, nil
	}
	var names []string
	for _, n := range s.Names {
		nn, err := edge.NormalizeName(n)
		if err != nil {
			return fail(dockerErrName, n)
		}
		if !slices.Contains(names, nn) {
			names = append(names, nn)
		}
	}
	v.Names = names
	for _, n := range names {
		for _, o := range *hosts {
			if (h != nil && o.ID == h.ID) || !slices.Contains(o.Names, n) {
				continue
			}
			if o.DockerContainer == "" {
				return fail(dockerErrNameTaken, n) // von Hand angelegt: der gewinnt
			}
			return fail(dockerErrDup, m.dockerHostLabel(o))
		}
	}
	port := dockerPort(s, c, in)
	if port == 0 {
		return fail(dockerErrNoPort, "")
	}
	addr, tport, key, val := dockerTarget(s, in, self, port)
	if addr == "" { // kein Ziel (bzw. Container gestoppt): nichts anlegen, ein vorhandener Host bleibt unveraendert
		return fail(key, val)
	}
	v.Target = s.Scheme + "://" + net.JoinHostPort(addr, strconv.Itoa(tport))
	saveErr := func(err error) (dockerContainerView, error) {
		var fe *FieldError
		if !errors.As(err, &fe) {
			return v, err
		}
		switch fe.Key {
		case "cdn64.err.name_taken":
			return fail(dockerErrNameTaken, fe.Name)
		case "cdn64.err.name", "cdn64.err.names_required", "cdn64.err.names_many":
			return fail(dockerErrName, fe.Name)
		}
		return fail(fe.Key, fe.Name)
	}
	// Zugriffsliste aus den Labels; fehlt verlangter Schutz, kommt ein neuer Host ausgeschaltet (nie ungeschuetzt
	// online), ein vorhandener behaelt seine Liste
	acl, aclName, missing := m.dockerACLFor(ctx, s)
	switch {
	case missing != "" && s.Access != nil:
		v.Problem, v.ProblemName = dockerErrAccess, missing
	case missing != "":
		v.Problem, v.ProblemName = dockerErrMW, missing
	}
	if acl > 0 {
		v.Access = aclName
	}
	if h == nil {
		nh := newHost()
		nh.Names, nh.Scheme, nh.TargetHost, nh.TargetPort = names, s.Scheme, addr, tport
		nh.DockerContainer, nh.DockerRouter = name, s.Router
		if acl > 0 {
			nh.AccessListID = acl
		}
		if missing != "" {
			nh.Enabled = false
		}
		if err := m.saveHost(ctx, nh); err != nil {
			return saveErr(err)
		}
		*hosts = append(*hosts, nh)
		v.HostID = nh.ID
		m.log.Info("cdn64 docker: host created", "container", m.dockerHostLabel(nh), "names", strings.Join(nh.Names, ","), "target", nh.Target())
		m.dockerCert(ctx, nh)
		return v, nil
	}
	if acl == 0 {
		acl = h.AccessListID // ohne Label: wie in der Oberflaeche eingestellt
	}
	if slices.Equal(h.Names, names) && h.Scheme == s.Scheme && h.TargetHost == addr && h.TargetPort == tport && h.AccessListID == acl {
		return v, nil
	}
	nh := *h // nur Namen, Schema, Ziel und Zugriffsliste aus den Labels; alles andere bleibt
	nh.Names, nh.Scheme, nh.TargetHost, nh.TargetPort, nh.AccessListID = names, s.Scheme, addr, tport, acl
	if err := m.saveHost(ctx, &nh); err != nil {
		return saveErr(err)
	}
	m.log.Info("cdn64 docker: host updated", "container", m.dockerHostLabel(h), "names", strings.Join(nh.Names, ","), "target", nh.Target(),
		"was", strings.Join(h.Names, ",")+" "+h.Target())
	*h = nh
	return v, nil
}

// dockerACLFrom: Name der Zugriffsliste, die die Labels fuer diesen Host festlegen ("" = keine bzw. Labels aus).
func (m *Module) dockerACLFrom(ctx context.Context, h *Host) string {
	if h.DockerContainer == "" || !m.dockerOn(ctx) {
		return ""
	}
	m.dk.mu.Lock()
	defer m.dk.mu.Unlock()
	return m.dk.acl[h.ID]
}

// dockerACLFor: Zugriffsliste aus den Labels (0 = keine). missing nennt verlangten Schutz, den es nicht gibt (Name
// der Liste bzw. nicht uebernommene Middlewares). Eine Liste aus einer Traefik-Middleware mit forwardAuth wird beim
// ersten Mal angelegt und bei geaenderten Antwort-Headern nachgezogen (andere Adresse = anderer Name).
func (m *Module) dockerACLFor(ctx context.Context, s dockerSpec) (id int64, name, missing string) {
	if s.Access == nil && len(s.Middlewares) == 0 {
		return 0, "", ""
	}
	lists, err := m.accessLists(ctx)
	if err != nil {
		if s.Access != nil {
			return 0, "", s.Access.Name
		}
		return 0, "", strings.Join(s.Middlewares, ", ")
	}
	byName := func(n string) *AccessList {
		for _, l := range lists {
			if strings.EqualFold(l.Name, n) {
				return l
			}
		}
		return nil
	}
	if a := s.Access; a != nil {
		l := byName(a.Name)
		if l == nil && a.Forward != nil {
			l = &AccessList{Name: a.Name, Auth: a.Auth, Forward: *a.Forward}
			if err := m.saveAccessList(ctx, l, nil); err != nil {
				m.log.Warn("cdn64 docker: access list from traefik labels not created", "name", a.Name, "err", err)
				return 0, "", a.Name
			}
			m.log.Info("cdn64 docker: access list created from traefik labels", "name", l.Name, "auth", l.Auth, "address", l.Forward.Address)
		} else if l != nil && a.Forward != nil && (l.Auth != a.Auth || l.Forward.Address != a.Forward.Address ||
			(len(a.Forward.Headers) > 0 && !slices.Equal(l.Forward.Headers, a.Forward.Headers))) {
			l.Auth, l.Forward.Address = a.Auth, a.Forward.Address
			if len(a.Forward.Headers) > 0 {
				l.Forward.Headers = a.Forward.Headers
			}
			users := make([]UserInput, 0, len(l.Users))
			for _, u := range l.Users {
				users = append(users, UserInput{Username: u.Username})
			}
			if err := m.saveAccessList(ctx, l, users); err != nil {
				m.log.Warn("cdn64 docker: access list from traefik labels not updated", "name", l.Name, "err", err)
			}
		}
		if l == nil {
			return 0, "", a.Name
		}
		return l.ID, l.Name, ""
	}
	for _, mw := range s.Middlewares { // name@file usw.: Zugriffsliste mit diesem Namen
		n, _, _ := strings.Cut(mw, "@")
		if l := byName(n); l != nil {
			return l.ID, l.Name, ""
		}
	}
	return 0, "", strings.Join(s.Middlewares, ", ")
}

// dockerPort: Port aus dem Label, sonst der einzige freigegebene TCP-Port (0 = keiner bzw. mehrere).
func dockerPort(s dockerSpec, c *dockerListC, in *dockerInspectC) int {
	if s.Port > 0 {
		return s.Port
	}
	ports := map[int]bool{}
	for k := range in.Config.ExposedPorts {
		p, proto, _ := strings.Cut(k, "/")
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 && (proto == "" || proto == "tcp") {
			ports[n] = true
		}
	}
	for _, p := range c.Ports {
		if p.Type == "tcp" && p.PrivatePort > 0 && p.PrivatePort < 65536 {
			ports[p.PrivatePort] = true
		}
	}
	if len(ports) != 1 {
		return 0
	}
	for p := range ports {
		return p
	}
	return 0
}

// dockerTarget: Adresse und Port, ueber die PROXY64 den Container erreicht (Plan Abschnitt 3). Ohne Adresse: key
// ist das Problem ("" = Container laeuft nicht, dann fehlt nur die IP).
func dockerTarget(s dockerSpec, in, self *dockerInspectC, port int) (addr string, p int, key, val string) {
	nets := in.NetworkSettings.Networks
	if s.Network != "" { // (1) Netz aus dem Label
		n, ok := nets[s.Network]
		if !ok {
			return "", 0, dockerErrNetwork, s.Network
		}
		if ip := n.ip(); ip != "" {
			return ip, port, "", ""
		}
		if !in.State.Running {
			return "", 0, "", ""
		}
		return "", 0, dockerErrNoTarget, ""
	}
	if !in.State.Running {
		return "", 0, "", ""
	}
	selfHost := self == nil || self.HostConfig.NetworkMode == "host"
	if in.HostConfig.NetworkMode == "host" { // Container im Host-Netz: ueber den Docker-Host
		if selfHost {
			return "127.0.0.1", port, "", ""
		}
		if gw := self.gateway(); gw != "" {
			return gw, port, "", ""
		}
		return "", 0, dockerErrNoTarget, ""
	}
	for _, k := range in.netNames() {
		if !selfHost { // (2) gemeinsames Netz mit Node64
			if _, ok := self.NetworkSettings.Networks[k]; !ok {
				continue
			}
		} // (3) Node64 im Host-Netz: erstes Netz mit IP
		if ip := nets[k].ip(); ip != "" {
			return ip, port, "", ""
		}
	}
	if !selfHost { // (4) freigegebener Port auf dem Docker-Host (ueber das Gateway des eigenen Netzes)
		if gw := self.gateway(); gw != "" {
			for _, b := range in.NetworkSettings.Ports[strconv.Itoa(port)+"/tcp"] {
				if a, err := netip.ParseAddr(b.HostIP); err == nil && a.IsLoopback() {
					continue
				}
				if n, err := strconv.Atoi(b.HostPort); err == nil && n > 0 && n < 65536 {
					return gw, n, "", ""
				}
			}
		}
	}
	return "", 0, dockerErrNoTarget, ""
}

// dockerCert: neuer Docker-Host ohne passendes Zertifikat - eines anfordern, wenn eingestellt (Weg wie im
// Host-Formular). Let's Encrypt nur mit angenommenen Nutzungsbedingungen; der Abruf laeuft im Hintergrund (certs).
func (m *Module) dockerCert(ctx context.Context, h *Host) {
	src := strings.TrimSpace(m.core.SettingOr(ctx, setDockerCert, ""))
	if src == "" || m.certs == nil || !h.HTTPS() {
		return
	}
	missing := false
	for _, n := range h.Names {
		if m.certs.MatchID(n) == 0 {
			missing = true
		}
	}
	if !missing || m.certIndex(ctx)[nameKey(h.Names)] != 0 { // passendes da bzw. schon angefordert
		return
	}
	var c *certs.Cert
	var err error
	switch {
	case src == "self":
		c, err = m.certs.Create(ctx, certs.Request{Names: h.Names, Source: "self"})
	case strings.HasPrefix(src, "ca:"):
		caID, _ := strconv.ParseInt(strings.TrimPrefix(src, "ca:"), 10, 64)
		c, err = m.certs.Create(ctx, certs.Request{Names: h.Names, Source: "ca", CAID: caID})
	default:
		if !m.certs.Account(ctx).TOSAccepted {
			m.log.Info("cdn64 docker: no certificate requested, terms of Let's Encrypt not accepted", "container", m.dockerHostLabel(h))
			return
		}
		dnsAcc := int64(0)
		if v, ok := strings.CutPrefix(src, "dns:"); ok { // "dns:<Zugang>"
			src = "dns"
			dnsAcc, _ = strconv.ParseInt(v, 10, 64)
		}
		c, err = m.requestCert(ctx, h.Names, src, "", "", dnsAcc, false)
	}
	if err != nil {
		m.log.Warn("cdn64 docker: certificate request failed", "container", m.dockerHostLabel(h), "names", strings.Join(h.Names, ","), "err", certErrText(err))
		return
	}
	m.log.Info("cdn64 docker: certificate requested", "container", m.dockerHostLabel(h), "cert", c.Title())
}
