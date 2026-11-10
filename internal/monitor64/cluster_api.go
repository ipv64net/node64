package monitor64

import (
	"context"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
)

// JSON-API fuer den Cluster unter /api/monitor64/cluster/... (Oberflaeche in monitor64.js).

// clusterRoutes registriert die Endpunkte (aus uiRoutes).
func (m *Module) clusterRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/monitor64/cluster", api(m.apiCluster))
	mux.Handle("GET /api/monitor64/cluster/views", api(m.apiClusterViews))
	mux.Handle("GET /api/monitor64/cluster/hosts/{uid}", api(m.apiClusterHostInfo))
	mux.Handle("PUT /api/monitor64/cluster/hosts/{uid}", api(m.apiClusterHost))
	mux.Handle("POST /api/monitor64/cluster/hosts/{uid}/reach", api(m.apiClusterReach))
	mux.Handle("GET /api/monitor64/cluster/keys", api(m.apiClusterKeys))
	mux.Handle("POST /api/monitor64/cluster/keys/rotate", api(m.apiClusterKeyRotate))
	mux.Handle("POST /api/monitor64/cluster/keys/retry", api(m.apiClusterKeyRetry))
	mux.Handle("POST /api/monitor64/cluster/keys/confirm", api(m.apiClusterKeyConfirm))
	mux.Handle("POST /api/monitor64/cluster/keys/retire", api(m.apiClusterKeyRetire))
	mux.Handle("GET /api/monitor64/cluster/orphans", api(m.apiClusterOrphans)) // verwaiste Hosts (cluster_orphans.go)
	mux.Handle("POST /api/monitor64/cluster/orphans/assign", api(m.apiClusterOrphansAct(true)))
	mux.Handle("POST /api/monitor64/cluster/orphans/remove", api(m.apiClusterOrphansAct(false)))
}

type clusterNodeOut struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Self   bool   `json:"self"`
	Online bool   `json:"online"`
	Stable bool   `json:"stable"` // seit 5 min erreichbar (darf zustaendig werden)
}

type clusterHostOut struct {
	UID       string   `json:"uid"`
	Name      string   `json:"name"`
	Owner     string   `json:"owner"`
	OwnerName string   `json:"owner_name"`
	Preferred string   `json:"preferred"`
	Backups   []string `json:"backups"`
	Role      string   `json:"role"` // report, measure, idle (Sicht dieser Node)
	Reachable bool     `json:"reachable"`
}

type clusterOut struct {
	Active    bool             `json:"active"`
	Self      string           `json:"self"`
	Majority  bool             `json:"majority"`
	Total     int              `json:"total"`
	Connected int              `json:"connected"`
	Nodes     []clusterNodeOut `json:"nodes"`
	Hosts     []clusterHostOut `json:"hosts"`
	Key       *keyInfo         `json:"key,omitempty"`
}

var roleNames = map[int]string{roleReport: "report", roleMeasure: "measure", roleIdle: "idle"}

// apiCluster: GET Stand des Clusters fuer Monitor64 (Nodes, Zustaendigkeit je Host, Schluessel).
func (m *Module) apiCluster(w http.ResponseWriter, r *http.Request) {
	out, err := m.clusterInfo(r.Context())
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// clusterInfo baut den Stand des Clusters (API und Seite Einstellungen).
func (m *Module) clusterInfo(ctx context.Context) (clusterOut, error) {
	s := m.clusterRefresh(ctx)
	out := clusterOut{Active: s.Active, Self: s.Self, Majority: s.Majority, Total: s.Total, Connected: s.Connected, Nodes: m.clusterNodes(ctx, s), Hosts: []clusterHostOut{}}
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return out, err
	}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, m.clusterHostOf(h, s))
	}
	if k, err := m.keyInfo(ctx); err == nil {
		out.Key = &k
	}
	return out, nil
}

// clusterNodes: diese Node zuerst, dann die anderen nach Namen.
func (m *Module) clusterNodes(ctx context.Context, s *clusterSnap) []clusterNodeOut {
	out := []clusterNodeOut{{ID: s.Self, Name: m.st.SettingOr(ctx, "node.name", "Node64"), Self: true, Online: true, Stable: true}}
	for id, p := range s.Peers {
		out = append(out, clusterNodeOut{ID: id, Name: p.Name, Online: p.Online, Stable: s.Stable[id]})
	}
	sort.SliceStable(out[1:], func(i, j int) bool {
		return strings.ToLower(out[i+1].Name) < strings.ToLower(out[j+1].Name)
	})
	return out
}

func (m *Module) clusterHostOf(h *Host, s *clusterSnap) clusterHostOut {
	role, owner := m.roleOf(h)
	b := h.BackupNodes
	if b == nil {
		b = []string{}
	}
	return clusterHostOut{UID: h.UID, Name: h.Name, Owner: owner, OwnerName: s.name(owner), Preferred: preferredOf(h, s.Self),
		Backups: b, Role: roleNames[role], Reachable: s.online(owner)}
}

// clusterViewsOut: welche Node die Hosts ueberwacht (Ansicht der Hosts, Uebersicht und Host-Seite).
type clusterViewsOut struct {
	Active   bool                   `json:"active"`
	Self     string                 `json:"self"`
	SelfName string                 `json:"self_name"`
	Refs     map[string]*ClusterRef `json:"refs"`
	Orphans  []orphanOut            `json:"orphans,omitempty"` // verwaiste Hosts (nur ohne host; cluster_orphans.go)
}

// clusterViews liest den Hinweis "ueberwacht von" aus dem Stand der Hosts (host = nur dieser; ohne Datenbank).
func (m *Module) clusterViews(ctx context.Context, host string) clusterViewsOut {
	s := m.clusterSnapshot()
	out := clusterViewsOut{Active: s.Active, Self: s.Self, SelfName: m.st.SettingOr(ctx, "node.name", "Node64"), Refs: map[string]*ClusterRef{}}
	for _, v := range m.Views() {
		if v.Cluster != nil && (host == "" || v.Host.UID == host) {
			out.Refs[v.Host.UID] = v.Cluster
		}
	}
	if host == "" {
		out.Orphans = m.orphanViews(s)
	}
	return out
}

// apiClusterViews: GET Hinweise "ueberwacht von" je Host (?host= nur einer).
func (m *Module) apiClusterViews(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.clusterViews(r.Context(), r.URL.Query().Get("host")))
}

// clusterHostInfo ist die Zustaendigkeit eines Hosts fuer die Host-Seite (Mitglieder, Einstellung, Ansicht,
// letzte Uebernahmen und Rueckgaben).
type clusterHostInfo struct {
	Active   bool             `json:"active"`
	Self     string           `json:"self"`
	Majority bool             `json:"majority"`
	Nodes    []clusterNodeOut `json:"nodes"`
	Host     clusterHostOut   `json:"host"`
	Ref      *ClusterRef      `json:"ref,omitempty"`
	Events   []eventRow       `json:"events"`
}

func (m *Module) clusterHostInfo(ctx context.Context, h *Host) clusterHostInfo {
	s := m.clusterSnapshot()
	out := clusterHostInfo{Active: s.Active, Self: s.Self, Majority: s.Majority, Nodes: m.clusterNodes(ctx, s), Host: m.clusterHostOf(h, s), Events: []eventRow{}}
	if v := m.viewOf(h.UID); v != nil {
		out.Ref = v.Cluster
	}
	evs, err := m.store.queryEvents(ctx, `SELECT ts, kind, text, actor, host_uid, service_key, problem_uid FROM m64_events
		WHERE host_uid = ? AND problem_uid = '' AND kind IN ('takeover', 'handover') ORDER BY ts DESC, id DESC LIMIT 20`, h.UID)
	if err == nil && evs != nil {
		out.Events = evs
	}
	return out
}

// apiClusterHostInfo: GET Zustaendigkeit eines Hosts (Host-Seite).
func (m *Module) apiClusterHostInfo(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, m.clusterHostInfo(ctx, h))
}

type clusterHostIn struct {
	Preferred string   `json:"preferred_node"`
	Backups   []string `json:"backup_nodes"`
}

// apiClusterHost: PUT bevorzugte Node und Ersatz-Nodes eines Hosts (nur Nodes des Clusters bzw. diese).
func (m *Module) apiClusterHost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	var in clusterHostIn
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	s := m.clusterRefresh(ctx)
	known := func(id string) bool { return id == s.Self || isPeer(s, id) }
	if in.Preferred == "" {
		in.Preferred = s.Self
	}
	if !known(in.Preferred) {
		m.fail(w, r, errBad("cluster_node", "node", in.Preferred))
		return
	}
	var backups []string
	for _, b := range in.Backups {
		if b == "" || b == in.Preferred || slices.Contains(backups, b) {
			continue
		}
		if !known(b) || len(backups) >= 8 {
			m.fail(w, r, errBad("cluster_node", "node", b))
			return
		}
		backups = append(backups, b)
	}
	if s.Active && h.OwnerNode == "" && preferredOf(h, s.Self) != in.Preferred {
		// die zustaendige Node bleibt, bis die neue bevorzugte lange genug erreichbar ist (Rueckgabe-Regel)
		if _, err := m.st.Writer().ExecContext(ctx, `UPDATE m64_hosts SET owner_node = ? WHERE uid = ?`, preferredOf(h, s.Self), h.UID); err != nil {
			m.fail(w, r, err)
			return
		}
		m.clusterChange(ctx, ClusterItemConfig, "owner:"+h.UID, false)
	}
	h.PreferredNode, h.BackupNodes = in.Preferred, backups
	if err := m.store.SaveHost(ctx, h, m.actor(r)); err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "host.cluster", h.Name, "preferred="+in.Preferred+" backups="+strings.Join(backups, ","))
	m.ReloadHost(ctx, h.UID)
	writeJSON(w, http.StatusOK, map[string]any{"uid": h.UID, "preferred_node": h.PreferredNode, "backup_nodes": backups})
}

type reachNodeOut struct {
	Node     string        `json:"node"`
	Name     string        `json:"name"`
	Self     bool          `json:"self"`
	OK       bool          `json:"ok"` // alle getesteten Zugaenge antworten
	Error    string        `json:"error,omitempty"`
	Accesses []reachResult `json:"accesses"`
}

// apiClusterReach: POST Zugaenge des Hosts von allen erreichbaren Nodes aus testen (Vorschlag der Ersatz-Nodes). Die
// eigene Pruefung laeuft neben den Anfragen an die anderen Nodes, die Zugaenge je Node nebeneinander: zusammen
// hoechstens reachLimit (unter dem Schreib-Zeitlimit des Webservers).
func (m *Module) apiClusterReach(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	h, err := m.store.Host(ctx, r.PathValue("uid"))
	if err != nil {
		m.fail(w, r, err)
		return
	}
	s := m.clusterRefresh(ctx)
	sum := func(list []reachResult) bool {
		ok, any := true, false
		for _, a := range list {
			if a.Skip {
				continue
			}
			any = true
			ok = ok && a.OK
		}
		return ok && any
	}
	ctx, cancel := context.WithTimeout(ctx, reachLimit)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	self := reachNodeOut{Node: s.Self, Name: m.st.SettingOr(ctx, "node.name", "Node64"), Self: true, Accesses: []reachResult{}}
	wg.Go(func() {
		own, err := m.reachHere(ctx, h.UID)
		mu.Lock()
		defer mu.Unlock()
		if own != nil {
			self.Accesses = own
		}
		self.OK = err == nil && sum(own)
		if err != nil {
			self.Error = err.Error()
		}
	})
	var peers []reachNodeOut
	for id, p := range s.Peers {
		if !p.Online || m.hooks().Call == nil {
			mu.Lock()
			peers = append(peers, reachNodeOut{Node: id, Name: p.Name, Error: "offline", Accesses: []reachResult{}})
			mu.Unlock()
			continue
		}
		wg.Go(func() {
			var res []reachResult
			o := reachNodeOut{Node: id, Name: p.Name, Accesses: []reachResult{}}
			if err := m.hooks().Call(ctx, id, callReach, hostReq{Host: h.UID}, &res); err != nil {
				o.Error = err.Error()
			} else {
				o.Accesses, o.OK = res, sum(res)
			}
			mu.Lock()
			peers = append(peers, o)
			mu.Unlock()
		})
	}
	wg.Wait()
	sort.SliceStable(peers, func(i, j int) bool { return strings.ToLower(peers[i].Name) < strings.ToLower(peers[j].Name) })
	writeJSON(w, http.StatusOK, map[string]any{"nodes": append([]reachNodeOut{self}, peers...)})
}

// apiClusterKeys: GET Schluessel der Node (Fingerabdruck, Zeile fuer authorized_keys, alte Schluessel, offene Umstellungen).
func (m *Module) apiClusterKeys(w http.ResponseWriter, r *http.Request) {
	k, err := m.keyInfo(r.Context())
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// apiClusterKeyRotate: POST neuer Schluessel fuer alle Nodes; Agents werden per "keys" umgestellt, SSH-Hosts bekommen
// die neue Zeile (authorized_key in der Antwort).
func (m *Module) apiClusterKeyRotate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if m.scheduler() == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	if err := m.RotateKey(ctx); err != nil {
		m.fail(w, r, err)
		return
	}
	m.startKeySwitch(context.WithoutCancel(ctx), true)
	k, err := m.keyInfo(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	m.audit(r, "key.rotate", k.Fingerprint, "")
	writeJSON(w, http.StatusOK, k)
}

// apiClusterKeyRetry: POST nicht umgestellte Agents jetzt erneut versuchen (im Hintergrund, je Agent bis 30 s; die
// Oberflaeche fragt den Stand per GET ab, solange "running").
func (m *Module) apiClusterKeyRetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if m.scheduler() == nil {
		m.fail(w, r, errNotRunning)
		return
	}
	m.startKeySwitch(context.WithoutCancel(ctx), true)
	k, err := m.keyInfo(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// apiClusterKeyConfirm: POST {"access_uid"} - SSH-Host von Hand umgestellt (Zeile eingetragen) bzw. Eintrag verwerfen.
// Gilt clusterweit (die anderen Nodes erfahren es ueber den Eintrag "key:cluster").
func (m *Module) apiClusterKeyConfirm(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var in struct {
		AccessUID string `json:"access_uid"`
	}
	if err := decode(r, &in); err != nil {
		m.fail(w, r, err)
		return
	}
	var fp string
	if err := m.st.Reader().QueryRowContext(ctx, `SELECT target_fp FROM m64_keypending WHERE access_uid = ?`, in.AccessUID).Scan(&fp); err != nil {
		m.fail(w, r, ErrNotFound)
		return
	}
	res, err := m.st.Writer().ExecContext(ctx, `DELETE FROM m64_keypending WHERE access_uid = ?`, in.AccessUID)
	if err := affected(res, err); err != nil {
		m.fail(w, r, err)
		return
	}
	m.markKeyDone(ctx, fp, in.AccessUID)
	m.audit(r, "key.confirm", in.AccessUID, "")
	m.startKeySwitch(context.WithoutCancel(ctx), false) // im Hintergrund: ggf. alte Schluessel abraeumen
	k, err := m.keyInfo(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}

// apiClusterKeyRetire: POST alte Schluessel sofort verwerfen (nicht umgestellte Agents sind dann ausgesperrt).
func (m *Module) apiClusterKeyRetire(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, _ = m.st.Writer().ExecContext(ctx, `DELETE FROM m64_keypending`)
	m.retireOldKeys(ctx)
	m.audit(r, "key.retire", "", "")
	k, err := m.keyInfo(ctx)
	if err != nil {
		m.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, k)
}
