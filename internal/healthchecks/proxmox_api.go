package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// Proxmox VE: JSON-API unter /api/healthchecks/proxmox (Anmeldung wie die uebrige API, Audit wie die Oberflaeche).
// Das Token-Secret wird nie ausgegeben; beim Aendern behaelt ein leeres Secret das gespeicherte.

func (m *Module) pveAPIRoutes(mux *http.ServeMux, api func(http.HandlerFunc) http.Handler) {
	const p = "/api/healthchecks/proxmox"
	mux.Handle("GET "+p+"/systems", api(m.apiPVESystems))
	mux.Handle("POST "+p+"/systems", api(m.apiPVECreate))
	mux.Handle("POST "+p+"/probe", api(m.apiPVEProbe))
	mux.Handle("GET "+p+"/systems/{id}", api(m.apiPVEGet))
	mux.Handle("PUT "+p+"/systems/{id}", api(m.apiPVEUpdate))
	mux.Handle("DELETE "+p+"/systems/{id}", api(m.apiPVEDelete))
	mux.Handle("GET "+p+"/systems/{id}/resources", api(m.apiPVEResources))
	mux.Handle("GET "+p+"/systems/{id}/series", api(m.apiPVESeries))
	mux.Handle("GET "+p+"/systems/{id}/settings", api(m.apiPVESettings))
	mux.Handle("PUT "+p+"/systems/{id}/settings", api(m.apiPVESettingsPut))
	mux.Handle("DELETE "+p+"/systems/{id}/settings", api(m.apiPVESettingsDelete))
	// Docker-Hosts (Kind docker): dieselben Handler unter /api/healthchecks/docker (die Liste nur mit Docker-Hosts)
	const d = "/api/healthchecks/docker"
	mux.Handle("GET "+d+"/systems", api(m.apiDockerSystems))
	mux.Handle("POST "+d+"/systems", api(m.apiDockerCreate))
	mux.Handle("GET "+d+"/systems/{id}", api(m.apiPVEGet))
	mux.Handle("PUT "+d+"/systems/{id}", api(m.apiPVEUpdate))
	mux.Handle("DELETE "+d+"/systems/{id}", api(m.apiPVEDelete))
	mux.Handle("GET "+d+"/systems/{id}/resources", api(m.apiPVEResources))
	mux.Handle("GET "+d+"/systems/{id}/series", api(m.apiPVESeries))
	mux.Handle("GET "+d+"/systems/{id}/settings", api(m.apiPVESettings))
	mux.Handle("PUT "+d+"/systems/{id}/settings", api(m.apiPVESettingsPut))
	mux.Handle("DELETE "+d+"/systems/{id}/settings", api(m.apiPVESettingsDelete))
}

// pveSystemJSON ist ein System in der API (ohne Secret) mit seinem Zustand.
type pveSystemJSON struct {
	*proxmox.System
	HasSecret   bool                 `json:"has_secret"`
	State       string               `json:"state"` // ok, warn, down, error, off, pending
	Error       string               `json:"error,omitempty"`
	Version     string               `json:"version,omitempty"`
	Cluster     string               `json:"cluster,omitempty"`
	Quorate     *bool                `json:"quorate,omitempty"`
	Address     string               `json:"address,omitempty"`
	LastPoll    *time.Time           `json:"last_poll,omitempty"`
	Nodes       int                  `json:"nodes"`
	NodesOnline int                  `json:"nodes_online"`
	Guests      int                  `json:"guests"`
	Running     int                  `json:"guests_running"`
	Bad         int                  `json:"guests_bad"`
	PBS         *proxmox.PBSInfo     `json:"pbs,omitempty"`      // nur Proxmox Backup Server: Datastores
	Storages    []proxmox.PVEStorage `json:"storages,omitempty"` // nur Proxmox VE: Speicher
}

func (m *Module) pveJSON(ctx context.Context, sys *proxmox.System) pveSystemJSON {
	row := m.pveSysView(ctx, sys)
	out := pveSystemJSON{System: sys, HasSecret: sys.Secret != "", State: row.State, Error: row.Error, Nodes: row.Nodes, NodesOnline: row.NodesOnline,
		Guests: row.Guests, Running: row.Running, Bad: row.Bad}
	if s := row.Snap; s != nil {
		t := s.Time
		out.LastPoll, out.Version, out.Cluster, out.Quorate, out.Address, out.PBS = &t, s.Version, s.Cluster, s.Quorate, s.Address, s.PBS
		out.Storages = s.Storages
	}
	return out
}

// pveSystemIn ist der Body beim Anlegen/Aendern (Kind nur beim Anlegen und Testen: pve oder pbs).
type pveSystemIn struct {
	Kind      string   `json:"kind"`
	Name      *string  `json:"name"`
	Addresses []string `json:"addresses"`
	TokenID   *string  `json:"token_id"`
	Secret    string   `json:"secret"`
	PinSHA256 *string  `json:"pin_sha256"`
	Interval  *int     `json:"interval"`
	Enabled   *bool    `json:"enabled"`
}

func (in pveSystemIn) apply(sys *proxmox.System) {
	if in.Name != nil {
		sys.Name = *in.Name
	}
	if in.Addresses != nil {
		sys.Addresses = in.Addresses
	}
	if in.TokenID != nil {
		sys.TokenID = *in.TokenID
	}
	sys.Secret = in.Secret
	if in.PinSHA256 != nil {
		sys.PinSHA256 = *in.PinSHA256
	}
	if in.Interval != nil {
		sys.Interval = *in.Interval
	}
	if in.Enabled != nil {
		sys.Enabled = *in.Enabled
	}
}

// pveAPIErr antwortet mit Feldfehler (422), fehlendem Schluessel (409) bzw. 500.
func (m *Module) pveAPIErr(w http.ResponseWriter, err error) {
	var fe *proxmox.FieldError
	switch {
	case errors.As(err, &fe):
		writeJSON(w, http.StatusUnprocessableEntity, statusAPIError{Error: fe.Field + ": invalid", Field: fe.Field, Key: fe.Key})
	case errors.Is(err, proxmox.ErrNoBox):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, proxmox.ErrNotFound):
		writeErr(w, http.StatusNotFound, "proxmox system not found")
	default:
		m.log.Error("proxmox api", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
	}
}

func (m *Module) pveAPISystem(w http.ResponseWriter, r *http.Request) *proxmox.System {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusNotFound, "proxmox system not found")
		return nil
	}
	sys, err := m.pve.st.System(r.Context(), id)
	if err != nil {
		m.pveAPIErr(w, err)
		return nil
	}
	return sys
}

// apiPVESystems: Proxmox-Systeme, VE und Backup Server (?kind=pve, pbs, docker bzw. all: auch Docker-Hosts).
func (m *Module) apiPVESystems(w http.ResponseWriter, r *http.Request) {
	m.pveListJSON(w, r, r.URL.Query().Get("kind"))
}

// apiDockerSystems: Docker-Hosts.
func (m *Module) apiDockerSystems(w http.ResponseWriter, r *http.Request) {
	m.pveListJSON(w, r, proxmox.KindDocker)
}

func (m *Module) pveListJSON(w http.ResponseWriter, r *http.Request, kind string) {
	list, err := m.pve.st.Systems(r.Context())
	if err != nil {
		m.pveAPIErr(w, err)
		return
	}
	out := make([]pveSystemJSON, 0, len(list))
	for _, sys := range list {
		if kind == "all" || sys.Kind == kind || kind == "" && !sys.IsDocker() {
			out = append(out, m.pveJSON(r.Context(), sys))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// apiDockerCreate legt einen Docker-Host an (Standard: lokaler Socket bzw. NODE64_DOCKER_HOST).
func (m *Module) apiDockerCreate(w http.ResponseWriter, r *http.Request) {
	var in pveSystemIn
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	sys := &proxmox.System{Kind: proxmox.KindDocker, Interval: proxmox.DefaultInterval, Enabled: true}
	in.apply(sys)
	sys.Kind = proxmox.KindDocker
	if strings.TrimSpace(sys.Name) == "" {
		sys.Name = "Docker"
	}
	if err := m.pveSaveSystem(r, sys); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	if dockerIsLocal(sys) {
		_ = m.core.SetSetting(r.Context(), dockerSettingMonitor, "")
	}
	m.auditText(r, "proxmox.create", sys.Name)
	writeJSON(w, http.StatusCreated, m.pveJSON(r.Context(), sys))
}

func (m *Module) apiPVEGet(w http.ResponseWriter, r *http.Request) {
	if sys := m.pveAPISystem(w, r); sys != nil {
		writeJSON(w, http.StatusOK, m.pveJSON(r.Context(), sys))
	}
}

func (m *Module) apiPVECreate(w http.ResponseWriter, r *http.Request) {
	var in pveSystemIn
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	sys := &proxmox.System{Interval: proxmox.DefaultInterval, Enabled: true}
	if !pveKindIn(w, in.Kind, sys) {
		return
	}
	in.apply(sys)
	if strings.TrimSpace(sys.Name) == "" {
		sys.Name = pveHostOf(sys.Kind, sys.Addresses)
	}
	if err := m.pveSaveSystem(r, sys); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	m.auditText(r, "proxmox.create", sys.Name)
	writeJSON(w, http.StatusCreated, m.pveJSON(r.Context(), sys))
}

func (m *Module) apiPVEUpdate(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	var in pveSystemIn
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	in.apply(sys)
	if err := m.pveSaveSystem(r, sys); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	m.auditText(r, "proxmox.update", sys.Name)
	sys, _ = m.pve.st.System(r.Context(), sys.ID)
	writeJSON(w, http.StatusOK, m.pveJSON(r.Context(), sys))
}

func (m *Module) apiPVEDelete(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	if err := m.pveDeleteSystem(r, sys.ID); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	m.auditText(r, "proxmox.delete", sys.Name)
	w.WriteHeader(http.StatusNoContent)
}

// apiPVEProbe prueft eine Verbindung (Assistent): mit system_id ohne Secret wird das gespeicherte benutzt – nur mit
// den gespeicherten Adressen und dem gespeicherten Pin (sonst muss das Secret mitkommen). Ohne Pin und mit nicht
// vertrauenswuerdigem Zertifikat kommt nur der Fingerabdruck zurueck (need_confirm); danach mit ihm als pin_sha256.
func (m *Module) apiPVEProbe(w http.ResponseWriter, r *http.Request) {
	var in struct {
		pveSystemIn
		SystemID int64 `json:"system_id"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	sys := proxmox.System{Name: "probe", Interval: proxmox.DefaultInterval}
	if in.SystemID <= 0 && !pveKindIn(w, in.Kind, &sys) {
		return
	}
	var old *proxmox.System
	if in.SystemID > 0 {
		var err error
		if old, err = m.pve.st.System(r.Context(), in.SystemID); err != nil {
			m.pveAPIErr(w, err)
			return
		}
		sys = *old
	}
	in.apply(&sys)
	if sys.IsDocker() {
		m.pveAPIErr(w, &proxmox.FieldError{Field: "kind", Key: "pve.err.kind"}) // Docker-Hosts brauchen keinen Test
		return
	}
	if sys.Secret == "" && old != nil {
		if !proxmox.SameEndpoint(old, &sys) {
			m.pveAPIErr(w, &proxmox.FieldError{Field: "secret", Key: "pve.err.secret_reenter"})
			return
		}
		sys.Secret = old.Secret
	}
	if err := proxmox.ValidateSystem(&sys, true); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	m.auditText(r, "proxmox.probe", strings.Join(sys.Addresses, ", "))
	writeJSON(w, http.StatusOK, pveProbe(ctx, sys))
}

// pveResourceJSON ist ein Node bzw. Gast im Snapshot mit Einstellungen.
type pveResourceJSON struct {
	proxmox.Resource
	Key        string `json:"key"`
	Bad        bool   `json:"bad"`
	Excluded   bool   `json:"excluded"`
	Muted      bool   `json:"muted"`
	AsCheck    bool   `json:"as_check"`
	CheckToken string `json:"check_token,omitempty"`
}

func (m *Module) apiPVEResources(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	row := m.pveSysView(r.Context(), sys)
	out := struct {
		System    pveSystemJSON     `json:"system"`
		Resources []pveResourceJSON `json:"resources"`
	}{System: m.pveJSON(r.Context(), sys), Resources: []pveResourceJSON{}}
	if row.Snap != nil {
		for _, res := range row.Snap.Resources {
			x := pveRow(sys.ID, res, row.Settings)
			out.Resources = append(out.Resources, pveResourceJSON{Resource: res, Key: x.Key, Bad: x.Bad, Excluded: x.Excluded, Muted: x.Muted,
				AsCheck: x.AsCheck, CheckToken: x.CheckToken})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// pveRanges: Zeitraeume der Graphen.
var pveRanges = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour}

func (m *Module) apiPVESeries(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" || !proxmox.ValidKey(key) {
		writeErr(w, http.StatusBadRequest, "key must look like node/<name>, qemu/<vmid>, lxc/<vmid> or docker/<name>")
		return
	}
	rg := r.URL.Query().Get("range")
	span, ok := pveRanges[rg]
	if !ok {
		rg, span = "24h", pveRanges["24h"]
	}
	to := time.Now()
	from := to.Add(-span)
	pts, err := m.pve.st.Series(r.Context(), sys.ID, key, from, to)
	if err != nil {
		m.pveAPIErr(w, err)
		return
	}
	if pts == nil {
		pts = []proxmox.Point{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "range": rg, "step_seconds": int(m.pve.st.Resolution(from).Seconds()),
		"from": from.UTC(), "to": to.UTC(), "points": pts})
}

// apiPVESettings: alle Einstellungen eines Systems und die wirksame Regel je Ebene.
func (m *Module) apiPVESettings(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	set, err := m.pve.st.Settings(r.Context(), sys.ID)
	if err != nil {
		m.pveAPIErr(w, err)
		return
	}
	nodes := map[string]string{}
	if s := m.pveLast(sys.ID); s != nil {
		for _, res := range s.Resources {
			nodes[res.Key()] = res.Node
		}
	}
	eff := map[string]proxmox.Rule{"": set.Effective("", "")}
	for k := range set.Items {
		eff[k] = set.Effective(k, nodes[k])
	}
	for k, n := range nodes {
		eff[k] = set.Effective(k, n)
	}
	writeJSON(w, http.StatusOK, map[string]any{"system_id": sys.ID, "items": set.Items, "effective": eff, "defaults": proxmox.DefaultRule()})
}

// apiPVESettingsPut setzt die Einstellungen einer Ebene (?key=, leer = System). as_check legt den Check an bzw.
// loescht ihn; check_token wird nicht uebernommen.
func (m *Module) apiPVESettingsPut(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	key := r.URL.Query().Get("key")
	if !proxmox.ValidKey(key) {
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	var in struct {
		Muted         *bool            `json:"muted"`
		AsCheck       *bool            `json:"as_check"`
		ExpectRunning json.RawMessage  `json:"expect_running"` // true, false, null (automatisch); fehlt = unveraendert
		Rules         *proxmox.RuleSet `json:"rules"`
	}
	if err := readJSON(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	ctx := r.Context()
	if in.AsCheck != nil && key != "" {
		if err := m.pveSetAsCheck(r, sys, key, *in.AsCheck); err != nil {
			var fe *proxmox.FieldError
			if errors.As(err, &fe) {
				m.pveAPIErr(w, err)
			} else {
				writeErr(w, http.StatusUnprocessableEntity, err.Error())
			}
			return
		}
	}
	set, err := m.pve.st.Settings(ctx, sys.ID)
	if err != nil {
		m.pveAPIErr(w, err)
		return
	}
	it := set.Item(key)
	if it == nil {
		it = &proxmox.Settings{SystemID: sys.ID, Key: key}
	}
	if in.Muted != nil {
		it.Muted = *in.Muted
	}
	if key != "" && pveLevel(key) != "system" && len(in.ExpectRunning) > 0 { // Gast: gestoppt ist richtig; Node: Wartung
		var v *bool
		if err := json.Unmarshal(in.ExpectRunning, &v); err != nil {
			writeErr(w, http.StatusBadRequest, "expect_running must be true, false or null")
			return
		}
		it.ExpectRunning = v
		if v != nil && !*v { // „gestoppt ist richtig“: wie der Knopf in der Oberflaeche
			m.pveAckIncident(ctx, sys.ID, key)
		}
	}
	if in.Rules != nil {
		it.Rules = *in.Rules
	}
	if err := m.pve.st.SaveSettings(ctx, it); err != nil {
		m.pveAPIErr(w, err)
		return
	}
	m.pveSyncCheckChannels(ctx, sys.ID, m.actor(r)) // Checks „als Check“: Kanaele wie die Regeln
	m.auditText(r, "proxmox.settings", sys.Name+pveKeySuffix(key))
	set, _ = m.pve.st.Settings(ctx, sys.ID)
	writeJSON(w, http.StatusOK, map[string]any{"settings": set.Item(key), "effective": set.Effective(key, m.pveNodeOf(sys.ID, key))})
}

// apiPVESettingsDelete setzt eine Ebene auf „alles erben“ zurueck („als Check“ bleibt).
func (m *Module) apiPVESettingsDelete(w http.ResponseWriter, r *http.Request) {
	sys := m.pveAPISystem(w, r)
	if sys == nil {
		return
	}
	key := r.URL.Query().Get("key")
	if !proxmox.ValidKey(key) {
		writeErr(w, http.StatusBadRequest, "invalid key")
		return
	}
	set, err := m.pve.st.Settings(r.Context(), sys.ID)
	if err != nil {
		m.pveAPIErr(w, err)
		return
	}
	if set.Item(key) != nil {
		if err := m.pve.st.ResetSettings(r.Context(), sys.ID, key); err != nil {
			m.pveAPIErr(w, err)
			return
		}
		m.pveSyncCheckChannels(r.Context(), sys.ID, m.actor(r))
	}
	m.auditText(r, "proxmox.settings_reset", sys.Name+pveKeySuffix(key))
	w.WriteHeader(http.StatusNoContent)
}

// pveNodeOf: Node eines Gasts laut letztem Snapshot.
func (m *Module) pveNodeOf(id int64, key string) string {
	if s := m.pveLast(id); s != nil {
		for _, res := range s.Resources {
			if res.Key() == key {
				return res.Node
			}
		}
	}
	return ""
}

// pveKindIn setzt die Art eines neuen Systems aus der API ("" = pve; Docker-Hosts haben eigene Endpunkte).
func pveKindIn(w http.ResponseWriter, kind string, sys *proxmox.System) bool {
	switch kind {
	case "", proxmox.KindPVE:
		sys.Kind = proxmox.KindPVE
	case proxmox.KindPBS:
		sys.Kind = proxmox.KindPBS
	default:
		writeErr(w, http.StatusUnprocessableEntity, "kind must be pve or pbs (docker hosts: /api/healthchecks/docker)")
		return false
	}
	return true
}
