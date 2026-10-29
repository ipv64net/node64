package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/peer"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// JSON-API fuer alles, was bisher nur die Oberflaeche konnte: Healthchecks-Sync mit ipv64 (Status, mit einem
// Klick verknuepfen, trennen, Konflikte, lokale Benachrichtigungen), zentraler ipv64-API-Key, lokale Gruppe,
// Log-Level und Datenhaltung. Gleiche Pruefungen und Audit-Eintraege wie in der Oberflaeche.

func (s *Server) apiLinkRoutes() {
	s.mux.Handle("GET /api/link", s.auth(s.apiLinkGet))
	s.mux.Handle("POST /api/link/apikey", s.auth(s.apiLinkAPIKey))
	s.mux.Handle("POST /api/link/unlink", s.auth(s.apiLinkUnlink))
	s.mux.Handle("GET /api/link/conflicts", s.auth(s.apiConflicts))
	s.mux.Handle("POST /api/link/conflicts/{id}", s.auth(s.apiConflictResolve))
	s.mux.Handle("PUT /api/link/settings", s.auth(s.apiLinkSettings))
	s.mux.Handle("GET /api/ipv64", s.auth(s.apiIPv64Get))
	s.mux.Handle("PUT /api/ipv64/key", s.auth(s.apiIPv64KeyPut))
	s.mux.Handle("DELETE /api/ipv64/key", s.auth(s.apiIPv64KeyDelete))
	s.mux.Handle("GET /api/group", s.auth(s.apiGroupGet))
	s.mux.Handle("POST /api/group/code", s.auth(s.apiGroupCode))
	s.mux.Handle("DELETE /api/group/code", s.auth(s.apiGroupCodeCancel))
	s.mux.Handle("POST /api/group/join", s.auth(s.apiGroupJoin))
	s.mux.Handle("POST /api/group/leave", s.auth(s.apiGroupLeave))
	s.mux.Handle("PUT /api/group/members/{id}", s.auth(s.apiGroupMemberURL))
	s.mux.Handle("DELETE /api/group/members/{id}", s.auth(s.apiGroupMemberRemove))
	s.mux.Handle("POST /api/group/members/{id}/resume", s.auth(s.apiGroupMemberResume))
	s.mux.Handle("PUT /api/group/sync", s.auth(s.apiGroupSync))
	s.mux.Handle("POST /api/group/acme", s.auth(s.apiGroupACME))
	s.mux.Handle("POST /api/group/users", s.auth(s.apiGroupUsers))
	s.mux.Handle("GET /api/logging", s.auth(s.apiLoggingGet))
	s.mux.Handle("PUT /api/logging", s.auth(s.apiLoggingPut))
	s.mux.Handle("GET /api/retention", s.auth(s.apiRetentionGet))
	s.mux.Handle("PUT /api/retention", s.auth(s.apiRetentionPut))
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.ContentLength == 0 {
		return true // leerer Body = Standardwerte
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(v); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return false
	}
	return true // io.EOF: leerer Body ohne Laenge (chunked) = Standardwerte
}

// ---------------------------------------------------------------- Healthchecks-Sync

func (s *Server) linkJSON(ctx context.Context) map[string]any {
	st := s.Sync.State()
	out := map[string]any{"linked": st.Linked, "connected": st.Connected, "account_id": st.AccountID, "plan": st.Plan,
		"node_name": st.NodeName, "location": st.Location, "remote_mgmt": st.RemoteMgmt, "hub": st.Hub, "last_sync_at": st.LastSyncAt,
		"connected_at": st.ConnectedAt, "linked_at": st.LinkedAt, "outbox": st.Outbox, "conflicts": st.Conflicts, "last_error": st.LastError,
		"pending_code": st.PendingCode, "requesting": st.Requesting, "online_limit": st.OnlineLimit, "checks_today": st.ChecksToday,
		"checks_limit": st.ChecksLimit, "locations_per_check": st.Locations,
		"local_notifications": s.Store.SettingOr(ctx, nodesync.SetLocalNotif, "0") == "1"}
	return out
}

func (s *Server) apiLinkGet(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil {
		writeErr(w, http.StatusServiceUnavailable, "sync not available")
		return
	}
	writeJSON(w, 200, s.linkJSON(r.Context()))
}

// apiLinkAPIKey verknuepft mit einem Klick ueber den zentralen ipv64-API-Key (wie /link/apikey).
func (s *Server) apiLinkAPIKey(w http.ResponseWriter, r *http.Request) {
	if s.Sync == nil {
		writeErr(w, http.StatusServiceUnavailable, "linking not available")
		return
	}
	var in struct {
		Location   string `json:"location"`
		RemoteMgmt string `json:"remote_mgmt"` // full (Standard), read, off
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	linked, err := s.linkViaAPIKey(ctx, r, in.Location, in.RemoteMgmt) // gleicher Weg wie die Oberflaeche
	switch {
	case errors.Is(err, errLinkUnavailable):
		writeErr(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, errAlreadyLinked):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, errNoIPv64Key):
		writeErr(w, http.StatusConflict, "no ipv64 api key stored (PUT /api/ipv64/key)")
	case errors.Is(err, ipv64api.ErrUnauthorized):
		writeErr(w, http.StatusUnauthorized, "ipv64 rejected the api key")
	case err != nil:
		writeErr(w, http.StatusBadGateway, err.Error())
	case linked:
		writeJSON(w, 200, s.linkJSON(r.Context()))
	default:
		writeJSON(w, http.StatusAccepted, s.linkJSON(r.Context())) // Token kommt im Hintergrund
	}
}

func (s *Server) apiLinkUnlink(w http.ResponseWriter, r *http.Request) {
	if s.Linker == nil {
		writeErr(w, http.StatusServiceUnavailable, "linking not available")
		return
	}
	var in struct {
		KeepChecks bool `json:"keep_checks"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.Linker.Unlink(r.Context(), in.KeepChecks); err != nil {
		s.log.Warn("unlink failed", "err", err)
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "sync.unlink", "", "keep_checks="+strconv.FormatBool(in.KeepChecks))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiConflicts(w http.ResponseWriter, r *http.Request) {
	if s.HC == nil {
		writeJSON(w, 200, []any{})
		return
	}
	list, err := s.HC.Conflicts(r.Context())
	if err != nil {
		s.log.Error("conflicts", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, map[string]any{"id": c.ID, "entity": c.Entity, "entity_id": c.EntityID, "name": healthchecks.ConflictName(c),
			"local_op": c.LocalOp, "local": json.RawMessage(orNull(c.LocalPayload)), "server": json.RawMessage(orNull(c.ServerPayload)),
			"server_revision": c.ServerRevision, "created_at": c.CreatedAt, "error": c.Error})
	}
	writeJSON(w, 200, out)
}

func orNull(s string) string {
	if strings.TrimSpace(s) == "" || !json.Valid([]byte(s)) {
		return "null"
	}
	return s
}

func (s *Server) apiConflictResolve(w http.ResponseWriter, r *http.Request) {
	if s.Linker == nil {
		writeErr(w, http.StatusServiceUnavailable, "linking not available")
		return
	}
	var in struct {
		Keep string `json:"keep"` // server (Standard), local (erneut senden) oder ignore (nur hier behalten)
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Keep != "local" && in.Keep != "ignore" {
		in.Keep = "server"
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err := s.Linker.Resolve(r.Context(), id, in.Keep); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.audit(r, "sync.conflict_resolved", r.PathValue("id"), "keep="+in.Keep)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiLinkSettings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		LocalNotifications *bool `json:"local_notifications"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.LocalNotifications != nil {
		v := "0"
		if *in.LocalNotifications {
			v = "1"
		}
		if err := s.Store.SetSetting(r.Context(), nodesync.SetLocalNotif, v); err != nil {
			s.log.Error("save setting", "err", err)
			writeErr(w, 500, "database error")
			return
		}
		if s.Dispatcher != nil {
			s.Dispatcher.SetSendServerChannels(v == "1") // sofort wirksam
		}
		s.audit(r, "sync.local_notifications", "", v)
	}
	writeJSON(w, 200, map[string]any{"local_notifications": s.Store.SettingOr(r.Context(), nodesync.SetLocalNotif, "0") == "1"})
}

// ---------------------------------------------------------------- zentraler ipv64-API-Key

func (s *Server) apiIPv64Get(w http.ResponseWriter, r *http.Request) {
	if s.IPv64 == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	ctx := r.Context()
	a := s.IPv64.Info(ctx)
	out := map[string]any{"key_stored": s.IPv64.Get(ctx) != "", "account": a.Account, "account_id": a.ID, "plan": a.Plan,
		"key_name": a.KeyName, "checked_at": a.CheckedAt}
	if !a.ExpiresAt.IsZero() {
		out["expires_at"], out["days_left"] = a.ExpiresAt, a.DaysLeft()
	}
	writeJSON(w, 200, out) // der Key selbst wird nie ausgegeben
}

func (s *Server) apiIPv64KeyPut(w http.ResponseWriter, r *http.Request) {
	if s.IPv64 == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		Key string `json:"key"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	me, err := s.IPv64.Set(ctx, in.Key)
	switch {
	case errors.Is(err, ipv64api.ErrFormat):
		writeErr(w, http.StatusUnprocessableEntity, "invalid api key format")
		return
	case errors.Is(err, ipv64api.ErrUnauthorized):
		writeErr(w, http.StatusUnprocessableEntity, "ipv64 rejected the api key")
		return
	case err != nil:
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "settings.ipv64_key", "", "account="+me.Account())
	s.apiIPv64Get(w, r)
}

func (s *Server) apiIPv64KeyDelete(w http.ResponseWriter, r *http.Request) {
	if s.IPv64 == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	if err := s.IPv64.Clear(r.Context()); err != nil {
		s.log.Error("ipv64 key delete", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "settings.ipv64_key_removed", "", "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- Cluster (frueher lokale Gruppe)

func (s *Server) apiGroupGet(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	ctx := r.Context()
	list, _ := s.Peer.Members(ctx)
	members := make([]map[string]any, 0, len(list))
	for _, x := range list {
		state := x.State
		if state == "" {
			state = "active"
		}
		members = append(members, map[string]any{"node_id": x.NodeID, "name": x.Name, "url": x.URL, "online": x.Online(), "linked": x.Linked,
			"version": x.Version, "last_seen": x.LastSeen, "last_error": x.LastError, "added_at": x.AddedAt,
			"state": state, "reason": x.Reason, "sync": x.Sync})
	}
	_, fwd, fwdSelf := s.Peer.Forwarder(ctx)
	out := map[string]any{"account_id": s.Peer.Account(), "linked": s.Peer.LinkedSelf(), "members": members, "forwarder": fwd, "forwarder_self": fwdSelf,
		"sync_modules": s.Peer.SyncModules(ctx), "https_port": s.Cfg.HTTPSPort, "acme_accounts": acmeAPI(s.acmeChoices(ctx, list))}
	if code, exp := s.Peer.PairingCode(); code != "" {
		out["code"], out["code_expires"] = code, exp
	}
	out["user_conflicts"] = userConflictsAPI(s.userChoices(ctx, list))
	writeJSON(w, 200, out)
}

func (s *Server) groupErrStatus(err error) int {
	switch {
	case errors.Is(err, peer.ErrNoAccount), errors.Is(err, peer.ErrSelf):
		return http.StatusConflict
	case errors.Is(err, peer.ErrAccountMismatch):
		return http.StatusForbidden
	case errors.Is(err, peer.ErrCode):
		return http.StatusUnprocessableEntity
	}
	return http.StatusBadGateway
}

func (s *Server) apiGroupCode(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	code, exp, err := s.Peer.StartPairing()
	if err != nil {
		writeErr(w, s.groupErrStatus(err), err.Error())
		return
	}
	s.audit(r, "peer.code", "", "")
	writeJSON(w, 201, map[string]any{"code": code, "expires": exp})
}

func (s *Server) apiGroupCodeCancel(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	s.Peer.CancelPairing()
	s.audit(r, "peer.code_cancel", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func validPeerURL(u string) bool {
	return strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")
}

func (s *Server) apiGroupJoin(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		Addr    string `json:"addr"`     // Adresse einer Node der Gruppe
		Code    string `json:"code"`     // Kopplungscode von dort
		SelfURL string `json:"self_url"` // Adresse dieser Node fuer die anderen
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.Addr, in.SelfURL = strings.TrimSpace(in.Addr), strings.TrimSpace(in.SelfURL)
	if !validPeerURL(in.Addr) || !validPeerURL(in.SelfURL) || in.Code == "" {
		writeErr(w, http.StatusUnprocessableEntity, "addr and self_url must start with http:// or https://, code is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Peer.Join(ctx, in.Addr, in.Code, in.SelfURL); err != nil {
		writeErr(w, s.groupErrStatus(err), err.Error())
		return
	}
	s.audit(r, "peer.join", in.Addr, "")
	s.apiGroupGet(w, r)
}

func (s *Server) apiGroupLeave(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Leave(ctx); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "peer.leave", "", "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiGroupMemberURL(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		URL string `json:"url"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in.URL = strings.TrimSpace(in.URL)
	if !validPeerURL(in.URL) {
		writeErr(w, http.StatusUnprocessableEntity, "url must start with http:// or https://")
		return
	}
	if err := s.Peer.SetURL(r.Context(), r.PathValue("id"), in.URL); err != nil {
		if errors.Is(err, peer.ErrUnknownMember) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		s.log.Error("peer url", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "peer.url", r.PathValue("id"), in.URL)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) apiGroupMemberRemove(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Remove(ctx, r.PathValue("id")); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	s.audit(r, "peer.remove", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// apiGroupMemberResume nimmt ein ausgesetztes Mitglied wieder auf (passt es weiterhin nicht, bleibt es ausgesetzt).
func (s *Server) apiGroupMemberResume(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Resume(ctx, r.PathValue("id")); err != nil {
		if errors.Is(err, peer.ErrUnknownMember) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		if s.suspendedMember(r.Context(), r.PathValue("id")) != nil { // passt weiterhin nicht
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		writeErr(w, s.groupErrStatus(err), err.Error())
		return
	}
	s.audit(r, "peer.resume", r.PathValue("id"), "")
	w.WriteHeader(http.StatusNoContent)
}

// apiGroupSync schaltet ein Modul (item leer) oder einen Bereich des Abgleichs.
func (s *Server) apiGroupSync(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		Module  string `json:"module"`
		Item    string `json:"item"` // leer = das Modul
		Enabled *bool  `json:"enabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Module == "" || in.Enabled == nil {
		writeErr(w, http.StatusUnprocessableEntity, "module and enabled are required")
		return
	}
	if err := s.Peer.SetSync(r.Context(), in.Module, in.Item, *in.Enabled); err != nil {
		if errors.Is(err, peer.ErrUnknownSync) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		s.log.Error("cluster sync", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "peer.sync", syncTarget(in.Module, in.Item), "enabled="+strconv.FormatBool(*in.Enabled))
	writeJSON(w, 200, map[string]any{"sync_modules": s.Peer.SyncModules(r.Context())})
}

// acmeAPI: verschiedene ACME-Konten im Cluster fuer die API (leer = keine Abweichung).
func acmeAPI(list []acmeRow) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, map[string]any{"thumbprint": c.Thumbprint, "node_id": c.Node, "node_name": c.Name, "email": c.Email, "ca": c.CA,
			"created_at": c.CreatedAt, "own": c.Own})
	}
	return out
}

// apiGroupACME waehlt bei verschiedenen ACME-Konten im Cluster eines fuer alle (Fingerabdruck aus acme_accounts).
func (s *Server) apiGroupACME(w http.ResponseWriter, r *http.Request) {
	if s.Peer == nil || s.Certs == nil {
		writeErr(w, http.StatusServiceUnavailable, "not available")
		return
	}
	var in struct {
		Thumbprint string `json:"thumbprint"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Thumbprint == "" {
		writeErr(w, http.StatusUnprocessableEntity, "thumbprint is required")
		return
	}
	dropped, err := s.chooseACME(r, in.Thumbprint)
	if errors.Is(err, certs.ErrAccountChoice) {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	if err != nil {
		s.log.Error("cluster acme choice", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(dropped))
	for _, d := range dropped {
		out = append(out, map[string]any{"thumbprint": d.Thumbprint, "node_id": d.Node, "email": d.Email})
	}
	writeJSON(w, 200, map[string]any{"chosen": in.Thumbprint, "dropped": out})
}

// ---------------------------------------------------------------- Log-Level und Datenhaltung

func (s *Server) apiLoggingGet(w http.ResponseWriter, r *http.Request) {
	mods := map[string]string{}
	for name, lvl := range s.Log.ModuleLevels() {
		mods[name] = logging.LevelName(lvl)
	}
	writeJSON(w, 200, map[string]any{"level": logging.LevelName(s.Log.Level()), "modules": mods, "known_modules": logModuleNames, "api_log": s.APILogMode()})
}

func (s *Server) apiLoggingPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Level        string            `json:"level"`         // global: debug, info, warn, error
		ResetMinutes int               `json:"reset_minutes"` // debug nach so vielen Minuten zuruecksetzen (0 = nie)
		Modules      map[string]string `json:"modules"`       // je Modul: Level oder "inherit"
		APILog       string            `json:"api_log"`       // jede API-Anfrage ins Log: off, keys, all (leer = unveraendert)
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if _, ok := apiLogMode(in.APILog); in.APILog != "" && !ok {
		writeErr(w, http.StatusUnprocessableEntity, "api_log must be off, keys or all")
		return
	}
	valid := func(l string) bool {
		switch l {
		case "debug", "info", "warn", "error":
			return true
		}
		return false
	}
	if in.Level != "" && !valid(in.Level) {
		writeErr(w, http.StatusUnprocessableEntity, "level must be debug, info, warn or error")
		return
	}
	for mod, l := range in.Modules {
		known := false
		for _, x := range logModuleNames {
			known = known || x == mod
		}
		if !known {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("unknown module %q (known: %s)", mod, strings.Join(logModuleNames, ", ")))
			return
		}
		if l != "inherit" && !valid(l) {
			writeErr(w, http.StatusUnprocessableEntity, "invalid level for module "+mod)
			return
		}
	}
	if in.Level != "" {
		lvl := logging.ParseLevel(in.Level)
		var reset time.Duration
		if lvl == slog.LevelDebug && in.ResetMinutes > 0 && in.ResetMinutes <= 1440 {
			reset = time.Duration(in.ResetMinutes) * time.Minute
		}
		s.Log.SetLevel(lvl, reset)
		s.audit(r, "logging.level", logging.LevelName(lvl), fmt.Sprintf("reset_minutes=%d", in.ResetMinutes))
	}
	for mod, l := range in.Modules {
		if l == "inherit" {
			s.Log.SetModuleLevel(mod, nil)
		} else {
			lvl := logging.ParseLevel(l)
			s.Log.SetModuleLevel(mod, &lvl)
		}
		s.audit(r, "logging.module", mod, l)
	}
	if in.APILog != "" {
		if err := s.setAPILog(r.Context(), in.APILog); err != nil {
			s.log.Error("api log setting", "err", err)
			writeErr(w, 500, "database error")
			return
		}
		s.audit(r, "logging.api", in.APILog, "")
	}
	s.apiLoggingGet(w, r)
}

func (s *Server) apiRetentionGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"raw_days":     healthchecks.RawDays(s.Store), // wirksame Werte (ohne Einstellung die Standardwerte)
		"hourly_days":  healthchecks.HourlyDays(s.Store),
		"chart_detail": healthchecks.ChartDetail(s.Store),
		"audit_days":   AuditDays(s.Store),
		"options": map[string]any{"raw_days": healthchecks.RawDayOptions, "hourly_days": healthchecks.HourlyDayOptions,
			"chart_detail": healthchecks.ChartDetailOptions, "audit_days": AuditDayOptions},
	})
}

func (s *Server) apiRetentionPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		RawDays     *int    `json:"raw_days"`
		HourlyDays  *int    `json:"hourly_days"`
		ChartDetail *string `json:"chart_detail"`
		AuditDays   *int    `json:"audit_days"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	in1 := func(n int, opts []int) bool {
		for _, o := range opts {
			if o == n {
				return true
			}
		}
		return false
	}
	set := map[string]string{}
	if in.RawDays != nil {
		if !in1(*in.RawDays, healthchecks.RawDayOptions) {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("raw_days must be one of %v", healthchecks.RawDayOptions))
			return
		}
		set[healthchecks.SettingRawDays] = strconv.Itoa(*in.RawDays)
	}
	if in.HourlyDays != nil {
		if !in1(*in.HourlyDays, healthchecks.HourlyDayOptions) {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("hourly_days must be one of %v", healthchecks.HourlyDayOptions))
			return
		}
		set[healthchecks.SettingHourlyDays] = strconv.Itoa(*in.HourlyDays)
	}
	if in.ChartDetail != nil {
		ok := false
		for _, o := range healthchecks.ChartDetailOptions {
			ok = ok || o == *in.ChartDetail
		}
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("chart_detail must be one of %v", healthchecks.ChartDetailOptions))
			return
		}
		set[healthchecks.SettingChartDetail] = *in.ChartDetail
	}
	if in.AuditDays != nil {
		if !in1(*in.AuditDays, AuditDayOptions) {
			writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("audit_days must be one of %v", AuditDayOptions))
			return
		}
		set[SettingAuditDays] = strconv.Itoa(*in.AuditDays)
	}
	for k, v := range set {
		if err := s.Store.SetSetting(r.Context(), k, v); err != nil {
			s.log.Error("save setting", "err", err)
			writeErr(w, 500, "database error")
			return
		}
	}
	if len(set) > 0 {
		s.audit(r, "settings.data", "", fmt.Sprintf("%v", set))
	}
	s.apiRetentionGet(w, r)
}
