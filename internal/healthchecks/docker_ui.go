package healthchecks

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
)

// Docker-Container: eigene Seite unter /healthchecks/docker (Menuepunkt unter Healthchecks wie Proxmox VE).
// Alle Container des Hosts (Docker-Socket) zusammen mit den Docker-Checks: ueberwachte mit Check-Zustand und
// Aktionen, nicht ueberwachte mit „Ueberwachen“ (Formular vorbelegt), Checks ohne Container als „Container fehlt“.
// Die Containerliste wird nur hier abgefragt (die Healthchecks-Liste bleibt dadurch schnell).

const dockerPath = "/healthchecks/docker"

// listContainers fragt den Docker-Host ab (in Tests austauschbar).
var listContainers = checks.ListContainers

func (m *Module) dockerRoutes(mux *http.ServeMux, page func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET "+dockerPath, page(m.pageDocker))
	mux.Handle("GET /api"+dockerPath+"/containers", page(m.apiDockerContainers))
}

// dockerRow ist ein Container des Hosts und/oder ein Docker-Check.
type dockerRow struct {
	Name   string
	Ct     *checks.Container // nil: Container nicht auf dem Host (bzw. Socket fehlt, andere Node/anderer Host)
	Hc     *row              // nil: nicht ueberwacht
	Kind   string            // running, stopped, paused, restarting, missing, remote, unknown
	Health string            // healthy, unhealthy, starting oder leer
}

// Started: Erstellzeit des Containers.
func (r dockerRow) Started() time.Time {
	if r.Ct == nil || r.Ct.Created == 0 {
		return time.Time{}
	}
	return time.Unix(r.Ct.Created, 0)
}

// Problem: gestoppt, pausiert, Neustart-Schleife, unhealthy oder Container fehlt.
func (r dockerRow) Problem() bool {
	switch r.Kind {
	case "stopped", "paused", "restarting", "missing":
		return true
	}
	return r.Health == "unhealthy"
}

// Class: Farbe des Container-Zustands (Badge).
func (r dockerRow) Class() string {
	switch {
	case r.Kind == "running" && r.Health == "unhealthy":
		return "text-bg-danger"
	case r.Kind == "running":
		return "text-bg-success"
	case r.Kind == "paused" || r.Kind == "restarting":
		return "text-bg-warning"
	case r.Kind == "stopped" || r.Kind == "missing":
		return "text-bg-danger"
	}
	return "text-bg-secondary"
}

// RowClass: Zeilenfarbe wie in der Healthchecks-Liste.
func (r dockerRow) RowClass() string {
	if r.Problem() {
		return "hc-row-down"
	}
	return ""
}

type dockerData struct {
	Host      string
	Socket    bool   // Docker-Socket erreichbar
	SocketErr string // Fehler mit Hinweis (Socket fehlt, keine Rechte)
	Rows      []dockerRow
	Hcs       []row // Docker-Checks (versteckte Aktionsformulare)
	Total     int   // Container auf dem Host
	Running   int
	Bad       int // gestoppt, pausiert, Neustart, unhealthy oder Container fehlt
	Missing   int
	Watched   int // Docker-Checks
	All       int // Zeilen ohne Filter
	Filter    map[string]string
	States    []string
}

// dockerStates sind die Werte des Zustandsfilters.
var dockerStates = []string{"running", "problem", "watched", "unwatched", "missing"}

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

// dockerLocal: der Check prueft einen Container ueber den Standard-Host dieser Node.
func dockerLocal(c *Check) bool {
	if c.Foreign() {
		return false
	}
	var p checks.DockerParams
	_ = json.Unmarshal(c.Params, &p)
	h := strings.TrimSpace(p.Host)
	return h == "" || h == checks.DefaultDockerHost()
}

// dockerCollect fragt die Container ab und fuehrt sie mit den Docker-Checks zusammen (alle Zeilen, ohne Filter).
func (m *Module) dockerCollect(r *http.Request) (dockerData, []dockerRow, error) {
	ctx := r.Context()
	lang := m.g.Lang(r)
	d := dockerData{Host: checks.DefaultDockerHost(), States: dockerStates}
	list, err := m.st.Checks(ctx)
	if err != nil {
		return d, nil, err
	}
	pills, err := m.pillsFor(ctx, lang, m.g.Timezone(r), 30)
	if err != nil {
		return d, nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	cs, cerr := listContainers(cctx, "")
	cancel()
	if cerr != nil {
		d.SocketErr = cerr.Error()
	} else {
		d.Socket = true
	}
	for _, c := range list {
		if c.Type == checks.TypeDocker {
			d.Hcs = append(d.Hcs, m.rowOf(ctx, lang, c, pills))
		}
	}
	d.Watched = len(d.Hcs)
	var all []dockerRow
	used := map[int]bool{} // Container mit Check
	for k := range d.Hcs {
		c := d.Hcs[k].Check
		dr := dockerRow{Name: strings.TrimPrefix(c.Target, "/"), Hc: &d.Hcs[k], Kind: "unknown"}
		if !dockerLocal(c) {
			dr.Kind = "remote"
		} else if d.Socket {
			dr.Kind = "missing"
			for i := range cs {
				if ct := &cs[i]; ct.Name == dr.Name || ct.ID == dr.Name || (len(dr.Name) > 12 && strings.HasPrefix(dr.Name, ct.ID)) {
					dr.Ct, dr.Kind, dr.Health = ct, dockerKind(ct.State), dockerHealth(ct.Status)
					used[i] = true
					break
				}
			}
		}
		all = append(all, dr)
	}
	for i := range cs {
		ct := &cs[i]
		dr := dockerRow{Name: ct.Name, Ct: ct, Kind: dockerKind(ct.State), Health: dockerHealth(ct.Status)}
		if !used[i] {
			all = append(all, dr)
		}
		d.Total++
		if dr.Kind == "running" {
			d.Running++
		}
		if dr.Problem() {
			d.Bad++
		}
	}
	for _, dr := range all {
		if dr.Kind == "missing" {
			d.Missing++
			d.Bad++
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return strings.ToLower(all[i].Name) < strings.ToLower(all[j].Name) })
	d.All = len(all)
	return d, all, nil
}

func (m *Module) pageDocker(w http.ResponseWriter, r *http.Request) {
	d, all, err := m.dockerCollect(r)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	f := map[string]string{"state": q.Get("state"), "q": strings.TrimSpace(q.Get("q"))}
	d.Filter = f
	for _, dr := range all {
		switch f["state"] {
		case "running":
			if dr.Kind != "running" {
				continue
			}
		case "problem":
			if !dr.Problem() {
				continue
			}
		case "watched":
			if dr.Hc == nil {
				continue
			}
		case "unwatched":
			if dr.Hc != nil {
				continue
			}
		case "missing":
			if dr.Kind != "missing" {
				continue
			}
		}
		if f["q"] != "" {
			hay := dr.Name
			if dr.Ct != nil {
				hay += " " + dr.Ct.Image + " " + dr.Ct.ID
			}
			if dr.Hc != nil {
				hay += " " + dr.Hc.Check.Name
			}
			if !strings.Contains(strings.ToLower(hay), strings.ToLower(f["q"])) {
				continue
			}
		}
		d.Rows = append(d.Rows, dr)
	}
	m.g.Render(w, r, http.StatusOK, Name+"/docker", "nav.docker", d)
}

// dockerJSON ist ein Eintrag von GET /api/healthchecks/docker/containers.
type dockerJSON struct {
	Name    string           `json:"name"`
	Kind    string           `json:"kind"`             // running, stopped, paused, restarting, missing, remote, unknown
	Health  string           `json:"health,omitempty"` // healthy, unhealthy, starting
	ID      string           `json:"id,omitempty"`
	Image   string           `json:"image,omitempty"`
	State   string           `json:"state,omitempty"`  // Docker: running, exited, ...
	Status  string           `json:"status,omitempty"` // Docker: "Up 3 hours (healthy)"
	Created *time.Time       `json:"created,omitempty"`
	Ports   []string         `json:"ports,omitempty"`
	Check   *dockerCheckJSON `json:"check"` // null = nicht ueberwacht
}

type dockerCheckJSON struct {
	Token   string `json:"token"`
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// apiDockerContainers: Container des Hosts zusammen mit den Docker-Checks (wie die Seite, ohne Filter).
func (m *Module) apiDockerContainers(w http.ResponseWriter, r *http.Request) {
	d, all, err := m.dockerCollect(r)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := struct {
		Host       string       `json:"host"`
		Socket     bool         `json:"socket"`
		Error      string       `json:"error,omitempty"`
		Containers []dockerJSON `json:"containers"`
	}{Host: d.Host, Socket: d.Socket, Error: d.SocketErr, Containers: []dockerJSON{}}
	for _, dr := range all {
		j := dockerJSON{Name: dr.Name, Kind: dr.Kind, Health: dr.Health}
		if ct := dr.Ct; ct != nil {
			j.ID, j.Image, j.State, j.Status, j.Ports = ct.ID, ct.Image, ct.State, ct.Status, ct.Ports
			if t := dr.Started(); !t.IsZero() {
				j.Created = &t
			}
		}
		if hc := dr.Hc; hc != nil {
			j.Check = &dockerCheckJSON{Token: hc.Check.Token, Name: hc.Check.Name, State: hc.State, Message: hc.Message}
		}
		out.Containers = append(out.Containers, j)
	}
	writeJSON(w, http.StatusOK, out)
}
