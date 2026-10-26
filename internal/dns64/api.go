package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/dns64/filter"
	"github.com/ipv64net/node64/internal/dns64/groups"
	"github.com/ipv64net/node64/internal/dns64/querylog"
	"github.com/ipv64net/node64/internal/module"
)

// Lokale JSON-API des Moduls (Doku: internal/web/static/openapi.json, Tag "DNS64"). Die Seiten des Moduls
// laden ihre Zahlen ueber dieselbe API.

func (m *Module) apiRoutes(mux *http.ServeMux, g module.Guards) {
	api := func(h func(http.ResponseWriter, *http.Request, *engine)) http.Handler {
		return g.Enabled(g.Auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			e := m.running()
			if e == nil {
				writeErr(w, http.StatusServiceUnavailable, errNotRunning.Error())
				return
			}
			h(w, r, e)
		})))
	}
	mux.Handle("GET /api/dns64/status", api(m.apiStatus))
	mux.Handle("GET /api/dns64/summary", api(m.apiSummary))
	mux.Handle("GET /api/dns64/timeline", api(m.apiTimeline))
	mux.Handle("GET /api/dns64/top", api(m.apiTop))
	mux.Handle("GET /api/dns64/log", api(m.apiLog))
	mux.Handle("GET /api/dns64/lists", api(m.apiLists))
	mux.Handle("GET /api/dns64/upstreams", api(m.apiUpstreams))
	mux.Handle("GET /api/dns64/cache", api(m.apiCache))
	mux.Handle("POST /api/dns64/cache/flush", api(m.apiCacheFlush))
	mux.Handle("GET /api/dns64/allowlist", api(m.apiAllowList))
	mux.Handle("POST /api/dns64/allowlist", api(m.apiAllowAdd))
	mux.Handle("DELETE /api/dns64/allowlist", api(m.apiAllowRemove))
	mux.Handle("GET /api/dns64/denylist", api(m.apiDenyList))
	mux.Handle("POST /api/dns64/denylist", api(m.apiDenyAdd))
	mux.Handle("DELETE /api/dns64/denylist", api(m.apiDenyRemove))
	// Einstellungen und eigene Eintraege gehen auch, wenn der DNS-Dienst gerade nicht laeuft
	plain := func(h http.HandlerFunc) http.Handler { return g.Enabled(g.Auth(h)) }
	mux.Handle("GET /api/dns64/settings", plain(m.apiSettings))
	mux.Handle("POST /api/dns64/pause", api(func(w http.ResponseWriter, r *http.Request, _ *engine) { m.apiPause(w, r) }))
	mux.Handle("POST /api/dns64/resume", api(func(w http.ResponseWriter, r *http.Request, _ *engine) { m.apiResume(w, r) }))
	mux.Handle("PUT /api/dns64/settings", plain(m.apiSettingsPut))
	mux.Handle("GET /api/dns64/records", plain(m.apiRecords))
	mux.Handle("POST /api/dns64/records", plain(m.apiRecordAdd))
	mux.Handle("DELETE /api/dns64/records/{id}", plain(m.apiRecordDelete))
	mux.Handle("PUT /api/dns64/records/{id}", plain(m.apiRecordUpdate))
	mux.Handle("POST /api/dns64/records/import", plain(m.apiRecordImport))
	mux.Handle("GET /api/dns64/records/export", plain(m.writeExport))
}

func (m *Module) apiSettings(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, m.loadConfig(r.Context()))
}

// apiSettingsPut uebernimmt die angegebenen Felder (fehlende bleiben) und startet den DNS-Dienst neu.
func (m *Module) apiSettingsPut(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	c := m.loadConfig(ctx)
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&c); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := m.saveConfig(ctx, c); err != nil {
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	}
	m.log.Info("settings saved", "via", "api", "by", m.g.Actor(r))
	m.audit(r, "dns64.settings", "", "")
	if err := m.restart(ctx); err != nil {
		writeErr(w, http.StatusConflict, m.g.T(r, "dns64.err.restart", "err", err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, m.loadConfig(ctx))
}

func (m *Module) apiRecords(w http.ResponseWriter, r *http.Request) {
	list, err := m.Records(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) apiRecordAdd(w http.ResponseWriter, r *http.Request) {
	var in Record
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	rec, err := m.AddRecord(r.Context(), in)
	var ce *cfgError
	if errors.As(err, &ce) {
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("record added", "name", rec.Name, "type", rec.Type, "value", rec.Value, "via", "api", "by", m.g.Actor(r))
	m.audit(r, "dns64.record.add", rec.Name, rec.Type+" "+rec.Value)
	writeJSON(w, http.StatusCreated, rec)
}

func (m *Module) apiRecordDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	err := m.DeleteRecord(r.Context(), id)
	if errors.Is(err, errNotFound) {
		writeErr(w, http.StatusNotFound, m.errText(r, err))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.audit(r, "dns64.record.delete", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func (m *Module) fail(w http.ResponseWriter, err error) {
	m.log.Error("api", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// ranges bildet den Zeitraum der Oberflaeche auf Rueckblick und Balkenbreite ab.
var ranges = map[string]struct{ window, step time.Duration }{
	"30m": {30 * time.Minute, time.Minute},
	"1h":  {time.Hour, 2 * time.Minute},
	"6h":  {6 * time.Hour, 10 * time.Minute},
	"24h": {24 * time.Hour, 30 * time.Minute},
	"7d":  {7 * 24 * time.Hour, 4 * time.Hour},
}

func rangeOf(r *http.Request) (time.Time, time.Duration) {
	rg, ok := ranges[r.URL.Query().Get("range")]
	if !ok {
		rg = ranges["24h"]
	}
	return time.Now().Add(-rg.window), rg.step
}

func intParam(r *http.Request, key string, def, max int) int {
	n, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || n <= 0 {
		return def
	}
	return min(n, max)
}

func (m *Module) apiStatus(w http.ResponseWriter, r *http.Request, e *engine) {
	writeJSON(w, http.StatusOK, map[string]any{
		"version": version, "listen": e.addr, "startedAt": e.started.UTC(),
		"router": e.local.Addr(), "routerSource": e.local.Source(), "retentionDays": m.retention(r.Context()),
		"blocking": m.pauseJSON(),
	})
}

func (m *Module) apiSummary(w http.ResponseWriter, r *http.Request, e *engine) {
	since, _ := rangeOf(r)
	sum, err := e.store.Summary(r.Context(), since)
	if err != nil {
		m.fail(w, err)
		return
	}
	_, updated := e.lists.Status()
	writeJSON(w, http.StatusOK, map[string]any{
		"summary":       sum,
		"blocklistSize": e.lists.Matcher().Size(),
		"listsLoadedAt": updated,
		"cache":         e.cache.Stats(),
		"uptimeSeconds": int(time.Since(e.started).Seconds()),
		"version":       version,
	})
}

func (m *Module) apiTimeline(w http.ResponseWriter, r *http.Request, e *engine) {
	since, step := rangeOf(r)
	b, err := e.store.Timeline(r.Context(), since, step)
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stepMs": step.Milliseconds(), "buckets": b})
}

func (m *Module) apiTop(w http.ResponseWriter, r *http.Request, e *engine) {
	since, _ := rangeOf(r)
	kind := r.URL.Query().Get("kind")
	items, err := e.store.Top(r.Context(), kind, since, intParam(r, "limit", 10, 100))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if kind == "clients" {
		ips := make([]string, len(items))
		for i, it := range items {
			ips[i] = it.Name
		}
		names := e.local.Hostnames(r.Context(), ips)
		for i := range items {
			items[i].Hostname = names[items[i].Name]
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func (m *Module) apiLog(w http.ResponseWriter, r *http.Request, e *engine) {
	f := querylog.LogFilter{
		Search: r.URL.Query().Get("q"),
		Limit:  intParam(r, "limit", 50, 500),
		Offset: max(0, intParam(r, "offset", 0, 1<<30)),
	}
	if st, ok := querylog.ParseStatus(r.URL.Query().Get("status")); ok {
		f.Status = &st
	}
	if r.URL.Query().Has("group") { // "" = ohne Gruppe
		g := r.URL.Query().Get("group")
		f.Group = &g
	}
	rows, total, err := e.store.Recent(r.Context(), f)
	if err != nil {
		m.fail(w, err)
		return
	}
	seen := map[string]bool{}
	var ips []string
	for _, row := range rows {
		if !seen[row.Client] {
			seen[row.Client] = true
			ips = append(ips, row.Client)
		}
	}
	names := e.local.Hostnames(r.Context(), ips)
	for i := range rows {
		rows[i].ClientName = names[rows[i].Client]
	}
	writeJSON(w, http.StatusOK, map[string]any{"rows": rows, "total": total, "capped": total >= querylog.CountCap}) // gedeckelt: "100.000+"
}

func (m *Module) apiLists(w http.ResponseWriter, r *http.Request, e *engine) {
	st, _ := e.lists.Status()
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) apiUpstreams(w http.ResponseWriter, r *http.Request, e *engine) {
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":        e.up.Mode(),
		"count":       e.up.Top(),
		"servers":     e.up.Stats(),
		"localDNS":    e.local.Addr(),
		"localSource": e.local.Source(),
	})
}

func (m *Module) apiCache(w http.ResponseWriter, r *http.Request, e *engine) {
	writeJSON(w, http.StatusOK, e.cache.Stats())
}

func (m *Module) apiCacheFlush(w http.ResponseWriter, r *http.Request, e *engine) {
	n := e.cache.Flush()
	m.log.Info("cache flushed", "entries", n, "by", m.g.Actor(r))
	m.audit(r, "dns64.cache.flush", strconv.Itoa(n)+" entries", "")
	writeJSON(w, http.StatusOK, map[string]int{"flushed": n})
}

func (m *Module) apiAllowList(w http.ResponseWriter, r *http.Request, e *engine) {
	writeJSON(w, http.StatusOK, e.lists.Allow.List())
}

func (m *Module) apiAllowAdd(w http.ResponseWriter, r *http.Request, e *engine) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	d, err := e.lists.Allow.Add(body.Domain)
	if err == nil && e.lists.Deny != nil { // Freigeben hebt die eigene Sperre derselben Domain auf
		if _, ok := e.lists.Deny.Match(d); ok {
			_ = e.lists.Deny.Remove(d)
			m.clChanged(r.Context(), ItemDeny)
		}
	}
	m.clChanged(r.Context(), ItemAllow)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeErr(w, http.StatusBadRequest, m.g.T(r, "dns64.err_domain"))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("domain released", "domain", d, "by", m.g.Actor(r))
	m.audit(r, "dns64.allowlist.add", d, "")
	writeJSON(w, http.StatusOK, map[string]string{"domain": d})
}

func (m *Module) apiAllowRemove(w http.ResponseWriter, r *http.Request, e *engine) {
	d := r.URL.Query().Get("domain")
	err := e.lists.Allow.Remove(d)
	m.clChanged(r.Context(), ItemAllow)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeErr(w, http.StatusBadRequest, m.g.T(r, "dns64.err_domain"))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("domain release removed", "domain", d, "by", m.g.Actor(r))
	m.audit(r, "dns64.allowlist.remove", d, "")
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) apiDenyList(w http.ResponseWriter, r *http.Request, e *engine) {
	if e.lists.Deny == nil {
		writeJSON(w, http.StatusOK, []filter.AllowEntry{})
		return
	}
	writeJSON(w, http.StatusOK, e.lists.Deny.List())
}

// apiDenyAdd: Domain (samt Subdomains) auf die eigene Sperrliste; eine gleiche Freigabe faellt dabei weg.
func (m *Module) apiDenyAdd(w http.ResponseWriter, r *http.Request, e *engine) {
	var body struct {
		Domain string `json:"domain"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if e.lists.Deny == nil {
		writeErr(w, http.StatusServiceUnavailable, "denylist not loaded")
		return
	}
	d, err := e.lists.Deny.Add(body.Domain)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeErr(w, http.StatusBadRequest, m.g.T(r, "dns64.err_domain"))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	if a, ok := e.lists.Allow.Match(d); ok && a == d {
		_ = e.lists.Allow.Remove(d)
		m.clChanged(r.Context(), ItemAllow)
	}
	m.clChanged(r.Context(), ItemDeny)
	e.cache.Flush() // sonst liefert der Cache die Domain noch bis zum Ablauf aus
	m.log.Info("domain blocked", "domain", d, "by", m.g.Actor(r))
	m.audit(r, "dns64.denylist.add", d, "")
	writeJSON(w, http.StatusOK, map[string]string{"domain": d})
}

func (m *Module) apiDenyRemove(w http.ResponseWriter, r *http.Request, e *engine) {
	d := r.URL.Query().Get("domain")
	if e.lists.Deny == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	err := e.lists.Deny.Remove(d)
	m.clChanged(r.Context(), ItemDeny)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeErr(w, http.StatusBadRequest, m.g.T(r, "dns64.err_domain"))
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	m.log.Info("domain block removed", "domain", d, "by", m.g.Actor(r))
	m.audit(r, "dns64.denylist.remove", d, "")
	w.WriteHeader(http.StatusNoContent)
}

// denylist liefert die eigene Sperrliste: vom laufenden Resolver oder direkt aus der Datei.
func (m *Module) denylist() (*filter.Allowlist, error) {
	if e := m.running(); e != nil && e.lists.Deny != nil {
		return e.lists.Deny, nil
	}
	if err := os.MkdirAll(m.dir(), 0o750); err != nil {
		return nil, err
	}
	return filter.LoadDenylist(filepath.Join(m.dir(), "denylist.txt"))
}

// ---- Export/Import (module.Exporter) ----

var exportSettings = []string{setPort, setBind, setRouter, setRetention, setUpstreams, setUpMode, setUpCount, setLists, setListHours,
	setBlockMode, setCacheSize, setAnonymize, setAllowNets, setCanary, setDoH, setDoT, setDoQ, setDoHPort, setDoTPort, setNames, setCertMode,
	setNotifyUpstream, setNotifyLists, setACMEDom, setACMEPre, setACMEMail, setACMEStage}

type exportData struct {
	Settings  map[string]string `json:"settings"`
	Allowlist []string          `json:"allowlist"`
	Denylist  []string          `json:"denylist,omitempty"` // eigene Sperrliste
	Records   []Record          `json:"records"`
	CertID    int64             `json:"cert_id,omitempty"` // Zertifikat aus der Verwaltung (bei "central")
	Groups    []groups.Group    `json:"groups,omitempty"`  // Geraetegruppen samt Mitgliedern, Regeln und Zeitplaenen
	Forwards  []Forward         `json:"forwards,omitempty"`
	Rewrites  []Rewrite         `json:"rewrites,omitempty"`
	Zones     []Zone            `json:"zones,omitempty"`
}

// allowlist liefert die Freigaben: vom laufenden Resolver oder direkt aus der Datei.
func (m *Module) allowlist() (*filter.Allowlist, error) {
	if e := m.running(); e != nil {
		return e.lists.Allow, nil
	}
	if err := os.MkdirAll(m.dir(), 0o750); err != nil {
		return nil, err
	}
	return filter.LoadAllowlist(filepath.Join(m.dir(), "allowlist.txt"))
}

// Export liefert Einstellungen und Freigaben (das Abfrage-Log bleibt lokal).
func (m *Module) Export(ctx context.Context) (any, error) {
	out := exportData{Settings: map[string]string{}, Allowlist: []string{}, Records: []Record{}}
	for _, k := range exportSettings {
		if v, ok, _ := m.core.Setting(ctx, k); ok {
			out.Settings[k] = v
		}
	}
	a, err := m.allowlist()
	if err != nil {
		return nil, err
	}
	for _, e := range a.List() {
		out.Allowlist = append(out.Allowlist, e.Domain)
	}
	if dl, err := m.denylist(); err == nil {
		for _, e := range dl.List() {
			out.Denylist = append(out.Denylist, e.Domain)
		}
	}
	if out.Records, err = m.Records(ctx); err != nil && !m.noTable(err) {
		return nil, err
	}
	if out.Records == nil {
		out.Records = []Record{}
	}
	out.CertID, _ = strconv.ParseInt(m.core.SettingOr(ctx, setCertID, "0"), 10, 64)
	if out.Groups, err = m.Groups(ctx); err != nil && !m.noTable(err) {
		return nil, err
	}
	for i := range out.Groups { // Knopf-Zustand bleibt auf der alten Node
		out.Groups[i].Hold, out.Groups[i].HoldUntil = "", ""
	}
	if out.Forwards, err = m.Forwards(ctx); err != nil && !m.noTable(err) {
		return nil, err
	}
	if out.Rewrites, err = m.Rewrites(ctx); err != nil && !m.noTable(err) {
		return nil, err
	}
	if out.Zones, err = m.Zones(ctx); err != nil && !m.noTable(err) {
		return nil, err
	}
	return out, nil
}

// Import uebernimmt Einstellungen und ergaenzt die Freigaben.
func (m *Module) Import(ctx context.Context, raw json.RawMessage) (int, error) {
	var in exportData
	if err := json.Unmarshal(raw, &in); err != nil {
		return 0, fmt.Errorf("dns64: %w", err)
	}
	n := 0
	for _, k := range exportSettings {
		if v, ok := in.Settings[k]; ok && m.core.SetSetting(ctx, k, v) == nil {
			n++
		}
	}
	// Zertifikat: nur, wenn es mit importiert wurde (Export mit Passwort); sonst waehlt DNS64 selbst
	if id, ok := module.MapCert(ctx, in.CertID); ok && m.core.SetSetting(ctx, setCertID, strconv.FormatInt(id, 10)) == nil {
		n++
	}
	a, err := m.allowlist()
	if err != nil {
		return n, err
	}
	for _, d := range in.Allowlist {
		if _, err := a.Add(d); err == nil {
			n++
		}
	}
	if dl, err := m.denylist(); err == nil {
		for _, d := range in.Denylist {
			if _, err := dl.Add(d); err == nil {
				n++
			}
		}
	}
	for _, rec := range in.Records { // vorhandene (gleicher Name, Typ, Wert) bleiben
		if _, err := m.AddRecord(ctx, rec); err == nil {
			n++
		} else if m.noTable(err) {
			break
		}
	}
	n += m.importGroups(ctx, in.Groups)
	for _, f := range in.Forwards { // vorhandene (gleiche Domain bzw. gleicher Name) bleiben
		if _, err := m.AddForward(ctx, f); err == nil {
			n++
		}
	}
	for _, x := range in.Rewrites {
		if _, err := m.AddRewrite(ctx, x); err == nil {
			n++
		}
	}
	for _, z := range in.Zones {
		if _, err := m.AddZone(ctx, z); err == nil {
			n++
		}
	}
	for _, it := range []string{ItemSettings, ItemLists, ItemAllow, ItemDeny} { // direkt gesetzt, nicht ueber saveConfig
		m.clChanged(ctx, it)
	}
	return n, m.restart(ctx)
}

// importGroups legt Gruppen mit Mitgliedern, Regeln, Freigaben/Sperren und Zeitplaenen an; eine Gruppe mit
// demselben Namen gibt es schon -> sie bleibt, wie sie ist. Liefert die Zahl der uebernommenen Teile.
func (m *Module) importGroups(ctx context.Context, list []groups.Group) int {
	n := 0
	for _, g := range list {
		ng, err := m.AddGroup(ctx, g.Name)
		if err != nil {
			continue // vorhanden, ungueltig oder Tabelle fehlt
		}
		n++
		_ = m.SetGroupRules(ctx, ng.ID, groups.Rules{ListsMode: g.ListsMode, Lists: g.Lists, Cats: g.Cats, SafeSearch: g.SafeSearch, YouTube: g.YouTube, Bypass: g.Bypass})
		for _, x := range g.Members {
			x.GroupID = ng.ID
			if _, err := m.AddMember(ctx, x); err == nil {
				n++
			}
		}
		for _, d := range g.Domains {
			d.GroupID = ng.ID
			if _, err := m.AddGroupDomain(ctx, d); err == nil {
				n++
			}
		}
		for _, s := range g.Schedules {
			s.GroupID = ng.ID
			if x, err := m.AddSchedule(ctx, s); err == nil {
				n++
				if !s.Enabled {
					_ = m.SetScheduleEnabled(ctx, x.ID, false)
				}
			}
		}
	}
	return n
}

// noTable: das Modul war noch nie an, die Tabelle der eigenen Eintraege fehlt.
func (m *Module) noTable(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no such table")
}
