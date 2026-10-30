package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker-Container: Seite unter /healthchecks/docker (Menuepunkt unter Healthchecks wie Proxmox VE). Der Docker-Host
// ist ein System der Proxmox-Ueberwachung (Kind docker, internal/proxmox/docker.go): alle Container werden ueberwacht
// (Zustand, CPU, RAM, Netz, Disk-I/O, Verlauf, Regeln mit Vererbung, Kanaele, Ruhezeiten); „Als Check fuehren“ legt
// zusaetzlich einen Healthchecks-Check vom Typ docker an. Die Seite beginnt immer mit der Uebersicht der Hosts; auch
// der lokale Socket wird erst ueberwacht, wenn er hinzugefuegt wird (Formular oder Knopf in der leeren Uebersicht).
// Docker-Checks ohne Container erscheinen als „Container fehlt“, Checks fuer andere Hosts als „andere Node/anderer Host“.

const (
	dockerPath           = "/healthchecks/docker"
	dockerSettingMonitor = "docker.monitor" // "off": Docker-Host nicht automatisch einrichten
)

// listContainers fragt den Docker-Host ab (Einrichtung und Anzeige ohne laufende Abfrage; in Tests austauschbar).
var listContainers = checks.ListContainers

func (m *Module) dockerRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+dockerPath, page(m.pageDocker))
	mux.Handle("POST "+dockerPath+"/enable", page(m.pageDockerEnable))
	mux.Handle("GET "+dockerPath+"/new", page(m.pageDockerForm))
	mux.Handle("POST "+dockerPath+"/new", page(m.pageDockerSave))
	mux.Handle("GET "+dockerPath+"/system/{id}", page(m.pageDocker))
	mux.Handle("GET "+dockerPath+"/system/{id}/edit", page(m.pageDockerForm))
	mux.Handle("POST "+dockerPath+"/system/{id}/edit", page(m.pageDockerSave))
	mux.Handle("GET "+dockerPath+"/system/{id}/c/{name}", page(m.pageDockerContainer))
	mux.Handle("GET /api"+dockerPath+"/containers", page(m.apiDockerContainers))
}

// dockerSysHost: Adresse des Docker-Hosts eines Systems.
func dockerSysHost(sys *proxmox.System) string {
	if sys != nil && len(sys.Addresses) > 0 && sys.Addresses[0] != "" {
		return sys.Addresses[0]
	}
	return checks.DefaultDockerHost()
}

// dockerSystems liefert die Docker-Hosts (nach ID).
func (m *Module) dockerSystems(ctx context.Context) ([]*proxmox.System, error) {
	list, err := m.pve.st.Systems(ctx)
	if err != nil {
		return nil, err
	}
	var out []*proxmox.System
	for _, s := range list {
		if s.IsDocker() {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// dockerLocalOf liefert den lokalen Docker-Host (Socket bzw. NODE64_DOCKER_HOST) aus der Liste (nil = keiner).
func dockerLocalOf(list []*proxmox.System) *proxmox.System {
	for _, s := range list {
		if dockerSysHost(s) == checks.DefaultDockerHost() {
			return s
		}
	}
	for _, s := range list { // NODE64_DOCKER_HOST umgestellt: ein Socket dieser Maschine bleibt der lokale Host
		if dockerIsLocal(s) {
			return s
		}
	}
	return nil
}

// dockerIsLocal: Host dieser Maschine (Standard bzw. NODE64_DOCKER_HOST oder ein unix-Socket).
func dockerIsLocal(sys *proxmox.System) bool {
	h := dockerSysHost(sys)
	return h == checks.DefaultDockerHost() || proxmox.DockerLocal(h)
}

// dockerNeedsPoll: Docker-Checks des Hosts brauchen die laufende Abfrage (Zugangsdaten: ssh://, https://).
func dockerNeedsPoll(sys *proxmox.System) bool {
	return sys.IsDocker() && proxmox.DockerUsesSecret(dockerSysHost(sys))
}

// dockerRemote liefert die Verbindung der laufenden Abfrage eines Hosts mit Zugangsdaten (https://, ssh://) fuer den
// Check-Typ docker (Runner.Docker): dieselbe SSH-Verbindung bzw. dasselbe Client-Zertifikat.
func (m *Module) dockerRemote(host string) (*http.Client, string, bool) {
	if !proxmox.DockerUsesSecret(host) {
		return nil, "", false
	}
	rt := m.pve
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, pp := range rt.polls {
		if dp, ok := pp.p.(interface {
			Host() string
			Client() (*http.Client, string)
		}); ok && dp.Host() == host {
			if hc, base := dp.Client(); hc != nil {
				return hc, base, true
			}
		}
	}
	return nil, "", false
}

// dockerEnsure richtet den lokalen Docker-Host ein, wenn der Socket erreichbar ist, er noch nicht eingerichtet ist und
// die Einrichtung nicht abgeschaltet wurde (force: auch dann; ein abgeschalteter Host wird eingeschaltet). Hosts aus der
// Ferne zaehlen dabei nicht.
func (m *Module) dockerEnsure(ctx context.Context, force bool) (*proxmox.System, error) {
	rt := m.pve
	rt.dockerMu.Lock()
	defer rt.dockerMu.Unlock()
	list, err := m.dockerSystems(ctx)
	if err != nil {
		return nil, err
	}
	if sys := dockerLocalOf(list); sys != nil {
		if force && !sys.Enabled {
			sys.Enabled, sys.Secret = true, ""
			if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
				return nil, err
			}
			m.pveReload(ctx, sys.ID)
		}
		return sys, nil
	}
	if !force && m.core.SettingOr(ctx, dockerSettingMonitor, "") == "off" {
		return nil, nil
	}
	pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	_, perr := listContainers(pctx, "")
	cancel()
	if perr != nil {
		return nil, perr
	}
	sys := &proxmox.System{Kind: proxmox.KindDocker, Name: "Docker", Addresses: []string{checks.DefaultDockerHost()},
		Interval: proxmox.DefaultInterval, Enabled: true}
	if err := m.pve.st.SaveSystem(ctx, sys); err != nil {
		return nil, err
	}
	if force {
		_ = m.core.SetSetting(ctx, dockerSettingMonitor, "")
	}
	m.log.Info("docker host monitored", "host", sys.Addresses[0], "system_id", sys.ID)
	m.pveReload(ctx, sys.ID)
	return sys, nil
}

// dockerChecks liefert alle Checks vom Typ docker.
func (m *Module) dockerChecks(ctx context.Context) ([]*Check, error) {
	rows, err := m.st.r.QueryContext(ctx, `SELECT `+checkCols+` FROM hc_checks WHERE type = ? ORDER BY name COLLATE NOCASE, token`, string(checks.TypeDocker))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Check
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// dockerTarget: Containername eines Docker-Checks.
func dockerTarget(c *Check) string { return strings.TrimPrefix(strings.TrimSpace(c.Target), "/") }

// dockerLinkChecks fuehrt vorhandene Docker-Checks dieses Hosts als Check des Containers (sonst meldeten Check und
// Ueberwachung denselben Ausfall doppelt). Nur Container aus der Abfrage, nur noch nicht zugeordnete Checks.
func (m *Module) dockerLinkChecks(ctx context.Context, set *proxmox.SystemSettings, s *proxmox.Snapshot) {
	if s == nil || !s.OK {
		return
	}
	names := map[string]bool{}
	for i := range s.Resources {
		if s.Resources[i].Type == proxmox.TypeDocker && !s.Resources[i].Excluded() {
			names[s.Resources[i].Name] = true
		}
	}
	linked := map[string]bool{}
	for _, it := range set.Items {
		if it.AsCheck && it.CheckToken != "" {
			linked[it.CheckToken] = true
		}
	}
	list, err := m.dockerChecks(ctx)
	if err != nil {
		return
	}
	sys, err := m.pve.st.System(ctx, set.SystemID)
	if err != nil {
		return
	}
	host := dockerSysHost(sys)
	for _, c := range list {
		name := dockerTarget(c)
		key := proxmox.TypeDocker + "/" + name
		if linked[c.Token] || !names[name] || !dockerOnHost(c, host) {
			continue
		}
		if it := set.Item(key); it != nil && it.AsCheck {
			continue // schon ein anderer Check
		}
		it := set.Item(key)
		if it == nil {
			it = &proxmox.Settings{SystemID: set.SystemID, Key: key}
			set.Items[key] = it
		}
		it.AsCheck, it.CheckToken = true, c.Token
		linked[c.Token] = true
		if err := m.pve.st.SaveSettings(ctx, it); err != nil {
			m.log.Error("docker check link", "err", err)
		}
	}
}

// dockerOnHost: der Check prueft einen Container dieses Hosts auf dieser Node.
func dockerOnHost(c *Check, host string) bool {
	return !c.Foreign() && dockerCheckHost(c) == host
}

// dockerCheckHost: Docker-Host eines Checks (leer = Standard).
func dockerCheckHost(c *Check) string {
	var p checks.DockerParams
	_ = json.Unmarshal(c.Params, &p)
	if h := strings.TrimSpace(p.Host); h != "" {
		return h
	}
	return checks.DefaultDockerHost()
}

// ---------------------------------------------------------------- Darstellung

// dockerRow ist ein Container (aus der Abfrage bzw. der Containerliste) und/oder ein Docker-Check.
type dockerRow struct {
	pveResRow
	Name   string
	Found  bool   // Container auf dem Host
	Hc     *row   // Check: als Check gefuehrt bzw. Docker-Check ohne Container / fuer einen anderen Host
	Linked bool   // Hc ist „als Check gefuehrt“ (Schalter an)
	Kind   string // running, stopped, paused, restarting, missing, remote, unknown
}

// Started: Erstellzeit des Containers.
func (r dockerRow) Started() time.Time {
	if r.R.Created == 0 {
		return time.Time{}
	}
	return time.Unix(r.R.Created, 0)
}

// Problem: gestoert (wie die Regeln, ohne stumme und ausgeschlossene) oder Container fehlt.
func (r dockerRow) Problem() bool {
	if r.Kind == "missing" {
		return true
	}
	return r.Found && r.Bad && !r.Muted && !r.Excluded
}

// RowClass: Zeilenfarbe wie in der Healthchecks-Liste.
func (r dockerRow) RowClass() string {
	switch {
	case r.Problem():
		return "hc-row-down"
	case r.Excluded:
		return "text-body-tertiary"
	}
	return ""
}

// MemUsed: RAM belegt/Limit anzeigen.
func (r dockerRow) MemUsed() bool { return r.Measured && r.R.MaxMem > 0 }

// dockerKind: Art fuer Filter und API aus dem Docker-Status.
func dockerKind(state string) string {
	switch state {
	case "running":
		return "running"
	case "paused":
		return "paused"
	case "restarting":
		return "restarting"
	}
	return "stopped" // exited, created, dead, removing
}

func dockerHealth(status string) string {
	switch {
	case strings.Contains(status, "(unhealthy)"):
		return "unhealthy"
	case strings.Contains(status, "(healthy)"):
		return "healthy"
	case strings.Contains(status, "health: starting"):
		return "starting"
	}
	return ""
}

// dockerListResource: Container aus der Containerliste (ohne laufende Abfrage: keine Werte, einfacher Zustand).
func dockerListResource(c checks.Container) proxmox.Resource {
	r := proxmox.Resource{Type: proxmox.TypeDocker, Name: c.Name, Status: c.State, ContainerID: c.ID, Image: c.Image, Created: c.Created,
		Ports: c.Ports, Health: dockerHealth(c.Status)}
	switch c.State {
	case "running":
		r.State = proxmox.StateRunning
		if r.Health == "unhealthy" {
			r.State, r.Detail = proxmox.StateError, proxmox.DockerUnhealthy
		}
	case "restarting":
		r.State, r.Detail = proxmox.StateError, proxmox.DockerRestarting
	case "paused":
		r.State = proxmox.StatePaused
	default:
		r.State = proxmox.StateStopped
	}
	return r
}

type dockerData struct {
	Host      string
	Sys       *proxmox.System // nil: kein Docker-Host eingerichtet
	View      pveSysRow       // Zustand des Systems (wie Proxmox)
	Path      string          // Seite des Systems
	Act       string          // Aktionen des Systems (/healthchecks/proxmox/system/{id}: settings, ascheck, toggle)
	Off       bool            // Einrichtung abgeschaltet (docker.monitor = off) und kein Host
	Local     bool            // Socket dieser Maschine (sonst aus der Ferne: tcp, https, ssh)
	Hosts     int             // eingerichtete Docker-Hosts (ab 2 gibt es die Uebersicht)
	Socket    bool            // Docker-Socket erreichbar
	SocketErr string          // Fehler mit Hinweis (Socket fehlt, keine Rechte)
	Live      bool            // Werte aus der laufenden Abfrage (sonst nur die Containerliste)
	Rows      []dockerRow
	Hcs       []row // Docker-Checks (versteckte Aktionsformulare)
	Total     int   // Container auf dem Host
	Running   int
	Bad       int // gestoert (wie die Regeln) bzw. Container fehlt
	Missing   int
	Watched   int // Docker-Checks
	AsCheck   int // davon als Check gefuehrt
	Add       int // Container, die noch nicht als Check gefuehrt werden (Knopf „alle aufnehmen“)
	All       int // Zeilen ohne Filter
	Filter    map[string]string
	States    []string
	Rules     pveRulesForm
	Info      *proxmox.DockerInfo
	CPUCores  float64 // Summe der laufenden Container (Kerne)
	MemSum    int64
	Last      *pveIncident
	LastURL   string
	Res       *dockerResData // Containerseite
}

// dockerResData ist die Seite eines Containers.
type dockerResData struct {
	Row    dockerRow
	Key    string
	Reach  bool // Abfrage erfolgreich
	Ranges []string
	Series string // URL der Werte
}

func (d dockerData) Crumb() string {
	if d.Res != nil {
		return d.Res.Row.Name
	}
	if d.Sys != nil {
		return d.Sys.Name
	}
	return ""
}

// CPUText: CPU der laufenden Container zusammen, bezogen auf den Host.
func (d dockerData) CPUText() string {
	if d.Info == nil || d.Info.NCPU <= 0 {
		return ""
	}
	return pvePctText(d.CPUCores * 100 / float64(d.Info.NCPU))
}

// dockerStates sind die Werte des Zustandsfilters.
var dockerStates = []string{"running", "problem", "stopped", "paused", "watched", "unwatched", "missing"}

// dockerCollect baut die Zeilen eines Docker-Hosts (sys nil = keiner eingerichtet) zusammen mit den Docker-Checks.
func (m *Module) dockerCollect(r *http.Request, sys *proxmox.System) (dockerData, []dockerRow, error) {
	ctx := r.Context()
	lang := m.g.Lang(r)
	d := dockerData{Host: dockerSysHost(sys), Sys: sys, States: dockerStates, Last: m.lastIncident(ctx, dockerSettingLast)}
	d.Local = proxmox.DockerLocal(d.Host)
	list, err := m.dockerChecks(ctx)
	if err != nil {
		return d, nil, err
	}
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 30)
	if err != nil {
		return d, nil, err
	}
	others := map[string]bool{} // Adressen der anderen eingerichteten Hosts
	if sys != nil {
		if all, err := m.dockerSystems(ctx); err == nil {
			for _, x := range all {
				if x.ID != sys.ID {
					others[dockerSysHost(x)] = true
				}
			}
		}
	}
	for _, c := range list {
		if !c.Foreign() && others[dockerCheckHost(c)] {
			continue
		}
		d.Hcs = append(d.Hcs, m.rowOf(ctx, lang, c, pills))
	}
	d.Watched = len(d.Hcs)
	set := &proxmox.SystemSettings{Items: map[string]*proxmox.Settings{}, Kind: proxmox.KindDocker}
	var res []proxmox.Resource
	if sys != nil {
		d.View = m.pveSysView(ctx, sys)
		d.Path, d.Act = d.View.Path, pveResPath(sys.ID, "")
		set = d.View.Settings
		d.Rules = pveRulesFor(set, "", "", pveResPath(sys.ID, "")+"/settings")
		m.pveRulesChannels(ctx, &d.Rules, set, "", "")
		if d.Last != nil && d.Last.SystemID == sys.ID {
			d.LastURL = pveKeyPath(proxmox.KindDocker, sys.ID, d.Last.Key)
		} else {
			d.Last = nil
		}
		if s := d.View.Snap; s != nil {
			d.Socket, d.SocketErr, d.Live, d.Info = s.OK, s.Error, s.OK, s.Docker
			res = s.Resources
		}
	} else {
		d.Off = m.core.SettingOr(ctx, dockerSettingMonitor, "") == "off"
		d.Last = nil
	}
	if !d.Live && d.SocketErr == "" && !proxmox.DockerUsesSecret(d.Host) { // keine Abfrage (aus, wartet): Containerliste direkt
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		cs, cerr := listContainers(cctx, dockerListHost(d.Host))
		cancel()
		if cerr != nil {
			d.SocketErr = cerr.Error()
		} else {
			d.Socket = true
			for _, c := range cs {
				res = append(res, dockerListResource(c))
			}
		}
	}
	var sparks map[string]template.HTML
	if d.Live {
		sparks = m.pveSparks(ctx, sys.ID)
	}
	// Checks „als Check“ und Docker-Checks je Container
	byToken := map[string]*row{}
	for k := range d.Hcs {
		byToken[d.Hcs[k].Check.Token] = &d.Hcs[k]
	}
	used := map[string]bool{}
	var all []dockerRow
	id := int64(0)
	if sys != nil {
		id = sys.ID
	}
	for _, x := range res {
		pr := pveRow(id, x, set)
		dr := dockerRow{pveResRow: pr, Name: x.Name, Found: true, Kind: dockerKind(x.Status)}
		if sys == nil {
			dr.Path = ""
		}
		dr.Spark = sparks[pr.Key]
		if hc := byToken[pr.CheckToken]; pr.AsCheck && hc != nil {
			dr.Hc, dr.Linked = hc, true
			used[hc.Check.Token] = true
		}
		all = append(all, dr)
	}
	for i := range all { // nicht zugeordnete Docker-Checks dieses Hosts zum Container (z. B. Ueberwachung aus)
		if all[i].Hc != nil {
			continue
		}
		for k := range d.Hcs {
			c := d.Hcs[k].Check
			if !used[c.Token] && dockerOnHost(c, d.Host) && (dockerTarget(c) == all[i].Name || (all[i].R.ContainerID != "" && strings.HasPrefix(dockerTarget(c), all[i].R.ContainerID))) {
				all[i].Hc = &d.Hcs[k]
				used[c.Token] = true
				break
			}
		}
	}
	for k := range d.Hcs {
		c := d.Hcs[k].Check
		if used[c.Token] {
			continue
		}
		dr := dockerRow{Name: dockerTarget(c), Hc: &d.Hcs[k], Kind: "unknown"}
		dr.Label, dr.Class = "hc.docker.kind.unknown", "text-bg-secondary"
		switch {
		case !dockerOnHost(c, d.Host):
			dr.Kind, dr.Label = "remote", "hc.docker.kind.remote"
		case d.Socket:
			dr.Kind, dr.Label, dr.Class = "missing", "hc.docker.kind.missing", "text-bg-danger"
		}
		all = append(all, dr)
	}
	for _, dr := range all {
		if dr.Found {
			d.Total++
			if dr.R.Status == "running" && !dr.Problem() {
				d.Running++
			}
			if dr.Measured {
				d.CPUCores += dr.R.CPU * dr.R.MaxCPU
				d.MemSum += dr.R.Mem
			}
			if dr.Linked {
				d.AsCheck++
			} else if !dr.Excluded {
				d.Add++
			}
		}
		if dr.Kind == "missing" {
			d.Missing++
		}
		if dr.Problem() {
			d.Bad++
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	d.All = len(all)
	return d, all, nil
}

// dockerMatch prueft Filter und Suche.
func dockerMatch(dr dockerRow, f map[string]string) bool {
	switch f["state"] {
	case "running":
		if dr.Kind != "running" {
			return false
		}
	case "problem":
		if !dr.Problem() {
			return false
		}
	case "stopped":
		if !dr.Found || dr.Kind != "stopped" {
			return false
		}
	case "paused":
		if dr.Kind != "paused" {
			return false
		}
	case "watched":
		if dr.Hc == nil {
			return false
		}
	case "unwatched":
		if dr.Hc != nil {
			return false
		}
	case "missing":
		if dr.Kind != "missing" {
			return false
		}
	}
	if q := strings.ToLower(f["q"]); q != "" {
		hay := dr.Name + " " + dr.R.Image + " " + dr.R.ContainerID + " " + strings.Join(dr.R.Tags, " ")
		if dr.Hc != nil {
			hay += " " + dr.Hc.Check.Name
		}
		if !strings.Contains(strings.ToLower(hay), q) {
			return false
		}
	}
	return true
}

// dockerListHost: Host fuer die Containerliste ohne Abfrage ("" = Standard).
func dockerListHost(host string) string {
	if host == checks.DefaultDockerHost() {
		return ""
	}
	return host
}

// dockerSystemOf liefert den Docker-Host der Seite: {id} bzw. ohne {id} der erste eingerichtete (nil = keiner).
func (m *Module) dockerSystemOf(w http.ResponseWriter, r *http.Request) (*proxmox.System, bool) {
	ctx := r.Context()
	if r.PathValue("id") == "" {
		var sys *proxmox.System
		if list, _ := m.dockerSystems(ctx); len(list) > 0 {
			sys = list[0]
		}
		return sys, true
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err == nil {
		var sys *proxmox.System
		if sys, err = m.pve.st.System(ctx, id); err == nil && sys.IsDocker() {
			return sys, true
		}
	}
	if err != nil && !errors.Is(err, proxmox.ErrNotFound) && !errors.Is(err, strconv.ErrSyntax) && !errors.Is(err, strconv.ErrRange) {
		m.fail(w, r, err)
		return nil, false
	}
	m.g.Flash(w, r, "warning", m.g.T(r, "pve.not_found"))
	http.Redirect(w, r, dockerPath, http.StatusSeeOther)
	return nil, false
}

func (m *Module) pageDocker(w http.ResponseWriter, r *http.Request) {
	if r.PathValue("id") == "" { // immer zuerst die Uebersicht wie Proxmox VE (auch mit einem oder keinem Host)
		list, err := m.dockerSystems(r.Context())
		if err != nil {
			m.fail(w, r, err)
			return
		}
		m.pageDockerHosts(w, r, list)
		return
	}
	sys, ok := m.dockerSystemOf(w, r)
	if !ok {
		return
	}
	d, all, err := m.dockerCollect(r, sys)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	if list, err := m.dockerSystems(r.Context()); err == nil {
		d.Hosts = len(list)
	}
	q := r.URL.Query()
	d.Filter = map[string]string{"state": q.Get("state"), "q": strings.TrimSpace(q.Get("q"))}
	for _, dr := range all {
		if dockerMatch(dr, d.Filter) {
			d.Rows = append(d.Rows, dr)
		}
	}
	m.g.Render(w, r, http.StatusOK, Name+"/docker", "nav.docker", d)
}

func (m *Module) pageDockerContainer(w http.ResponseWriter, r *http.Request) {
	sys, ok := m.dockerSystemOf(w, r)
	if !ok || sys == nil {
		return
	}
	name := r.PathValue("name")
	key := proxmox.TypeDocker + "/" + name
	if !proxmox.ValidKey(key) {
		http.NotFound(w, r)
		return
	}
	d, all, err := m.dockerCollect(r, sys)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	rd := &dockerResData{Key: key, Reach: d.Live, Ranges: []string{"1h", "24h", "7d", "30d"},
		Series: "/api" + dockerPath + "/systems/" + strconv.FormatInt(sys.ID, 10) + "/series?key=" + key}
	for _, dr := range all {
		if dr.Name == name && (dr.Found || dr.Hc != nil) {
			rd.Row = dr
			break
		}
	}
	if rd.Row.Name == "" {
		rd.Row = dockerRow{Name: name, pveResRow: pveResRow{Key: key, Path: pveResPath(sys.ID, key), Label: "docker.state.unknown", Class: "text-bg-secondary"}}
		if it := d.View.Settings.Item(key); it != nil {
			rd.Row.AsCheck, rd.Row.CheckToken, rd.Row.Muted = it.AsCheck, it.CheckToken, it.Muted
		}
	}
	d.Res = rd
	d.Rules = pveRulesFor(d.View.Settings, key, "", pveResPath(sys.ID, "")+"/settings")
	m.pveRulesChannels(r.Context(), &d.Rules, d.View.Settings, key, "")
	m.g.Render(w, r, http.StatusOK, Name+"/docker", "nav.docker", d)
}

// pageDockerEnable richtet den Docker-Host ein bzw. schaltet ihn ein (auch nach dem Entfernen).
func (m *Module) pageDockerEnable(w http.ResponseWriter, r *http.Request) {
	sys, err := m.dockerEnsure(r.Context(), true)
	switch {
	case sys != nil:
		m.auditText(r, "proxmox.enable", sys.Name)
		m.g.Flash(w, r, "success", m.g.T(r, "common.saved"))
	case err != nil:
		m.g.Flash(w, r, "danger", m.g.T(r, "hc.docker.socket_missing", "host", checks.DefaultDockerHost())+" "+err.Error())
	}
	if sys != nil {
		http.Redirect(w, r, dockerSysPath(sys.ID), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, dockerPath, http.StatusSeeOther)
}

// ---------------------------------------------------------------- API

// dockerJSON ist ein Eintrag von GET /api/healthchecks/docker/containers.
type dockerJSON struct {
	Name    string           `json:"name"`
	Kind    string           `json:"kind"`             // running, stopped, paused, restarting, missing, remote, unknown
	Health  string           `json:"health,omitempty"` // healthy, unhealthy, starting
	ID      string           `json:"id,omitempty"`
	Image   string           `json:"image,omitempty"`
	State   string           `json:"state,omitempty"` // Docker: running, exited, ...
	Created *time.Time       `json:"created,omitempty"`
	Ports   []string         `json:"ports,omitempty"`
	Check   *dockerCheckJSON `json:"check"` // null = kein Check
	// aus der Ueberwachung (fehlen ohne laufende Abfrage)
	Key       string   `json:"key,omitempty"`        // docker/<name> (Einstellungen, Verlauf)
	Monitor   string   `json:"monitor,omitempty"`    // Zustand wie die Regeln: running, stopped, paused, error, unknown
	Detail    string   `json:"detail,omitempty"`     // bei error: unhealthy, restarting, exited, oom, dead
	Bad       bool     `json:"bad"`                  // gestoert (wie die Regeln)
	AsCheck   bool     `json:"as_check"`             // als Check gefuehrt
	Excluded  bool     `json:"excluded,omitempty"`   // Label node64.nomonitor=true
	Muted     bool     `json:"muted,omitempty"`      // stumm
	CPU       *float64 `json:"cpu,omitempty"`        // Anteil 0..1 bezogen auf cpus
	CPUs      float64  `json:"cpus,omitempty"`       // CPU-Limit bzw. Kerne des Hosts
	Mem       int64    `json:"mem,omitempty"`        // Byte (ohne inactive_file)
	MaxMem    int64    `json:"max_mem,omitempty"`    // Limit bzw. RAM des Hosts
	NetIn     float64  `json:"net_in,omitempty"`     // Byte/s
	NetOut    float64  `json:"net_out,omitempty"`    // Byte/s
	DiskRead  float64  `json:"disk_read,omitempty"`  // Byte/s
	DiskWrite float64  `json:"disk_write,omitempty"` // Byte/s
	Uptime    int64    `json:"uptime,omitempty"`     // Sekunden
	Restarts  int      `json:"restart_count,omitempty"`
	ExitCode  int      `json:"exit_code,omitempty"`
}

type dockerCheckJSON struct {
	Token   string `json:"token"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// apiDockerContainers: Container des Hosts mit den Werten der Ueberwachung und den Docker-Checks (wie die Seite,
// ohne Filter).
func (m *Module) apiDockerContainers(w http.ResponseWriter, r *http.Request) {
	list, err := m.dockerSystems(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	var sys *proxmox.System
	if len(list) > 0 {
		sys = list[0]
	}
	d, all, err := m.dockerCollect(r, sys)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := struct {
		Host       string       `json:"host"`
		Socket     bool         `json:"socket"`
		Error      string       `json:"error,omitempty"`
		SystemID   int64        `json:"system_id,omitempty"` // Docker-Host der Ueberwachung (0 = keiner)
		Monitored  bool         `json:"monitored"`           // Ueberwachung laeuft (Werte vorhanden)
		Containers []dockerJSON `json:"containers"`
	}{Host: d.Host, Socket: d.Socket, Error: d.SocketErr, Monitored: d.Live, Containers: []dockerJSON{}}
	if sys != nil {
		out.SystemID = sys.ID
	}
	for _, dr := range all {
		j := dockerJSON{Name: dr.Name, Kind: dr.Kind, Bad: dr.Problem()}
		if dr.Found {
			x := dr.R
			j.Health, j.ID, j.Image, j.State, j.Ports, j.Restarts, j.ExitCode = x.Health, x.ContainerID, x.Image, x.Status, x.Ports, x.Restarts, x.ExitCode
			if t := dr.Started(); !t.IsZero() {
				j.Created = &t
			}
			j.Key, j.Monitor, j.Detail, j.AsCheck, j.Excluded, j.Muted = dr.Key, string(x.State), x.Detail, dr.Linked, dr.Excluded, dr.Muted
			if d.Live && dr.Measured {
				cpu := x.CPU
				j.CPU, j.CPUs, j.Mem, j.MaxMem, j.Uptime = &cpu, x.MaxCPU, x.Mem, x.MaxMem, x.Uptime
				j.NetIn, j.NetOut, j.DiskRead, j.DiskWrite = x.NetIn, x.NetOut, x.DiskRead, x.DiskWrite
			}
		}
		if hc := dr.Hc; hc != nil {
			j.Check = &dockerCheckJSON{Token: hc.Check.Token, Name: hc.Check.Name, State: hc.State, Message: hc.Message}
		}
		out.Containers = append(out.Containers, j)
	}
	writeJSON(w, http.StatusOK, out)
}
