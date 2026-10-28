package web

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/netstat"
)

// JSON-API fuer die Verwaltung, die bisher nur die Oberflaeche konnte: API-Keys, Wiederherstellung, Export und
// Import der Konfiguration, Werksreset und die Zahlen des Dashboards. Gleiche Wege und Audit-Eintraege wie dort.

func (s *Server) apiAdminRoutes() {
	s.mux.Handle("GET /api/keys", s.auth(s.apiKeysList))
	s.mux.Handle("POST /api/keys", s.auth(s.apiKeysCreate))
	s.mux.Handle("DELETE /api/keys/{id}", s.auth(s.apiKeysDelete))
	s.mux.Handle("POST /api/backup", s.auth(s.apiBackupArchive))
	s.mux.Handle("POST /api/backup/restore", s.auth(s.apiRestore))
	s.mux.Handle("POST /api/export", s.auth(s.apiExport))
	s.mux.Handle("POST /api/import", s.auth(s.apiImport))
	s.mux.Handle("POST /api/reset", s.auth(s.apiReset))
	s.mux.Handle("GET /api/overview", s.auth(s.apiOverview))
	s.mux.Handle("GET /api/dashboard/layout", s.auth(s.apiDashLayoutGet))
	s.mux.Handle("PUT /api/dashboard/layout", s.auth(s.apiDashLayoutPut))
	s.mux.Handle("DELETE /api/dashboard/layout", s.auth(s.apiDashLayoutDelete))
}

// ---------------------------------------------------------------- API-Keys

func (s *Server) apiKeysList(w http.ResponseWriter, r *http.Request) {
	keys, err := s.Store.APIKeys(r.Context(), currentUser(r).ID)
	if err != nil {
		s.log.Error("api keys", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		item := map[string]any{"id": k.ID, "name": k.Name, "hint": k.Hint, "created_at": k.CreatedAt}
		if !k.LastUsedAt.IsZero() {
			item["last_used_at"] = k.LastUsedAt
		}
		out = append(out, item)
	}
	writeJSON(w, 200, out) // die Keys selbst gibt es nur einmal beim Anlegen
}

func (s *Server) apiKeysCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" || len(name) > 100 {
		writeErr(w, http.StatusUnprocessableEntity, "name is required (max 100 characters)")
		return
	}
	key, k, err := s.Store.NewAPIKey(r.Context(), currentUser(r).ID, name)
	if err != nil {
		s.log.Error("api key create", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	s.audit(r, "apikey.create", name, k.Hint)
	writeJSON(w, 201, map[string]any{"id": k.ID, "name": k.Name, "hint": k.Hint, "created_at": k.CreatedAt, "key": key})
}

func (s *Server) apiKeysDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	deleted, err := s.Store.DeleteAPIKey(r.Context(), currentUser(r).ID, id)
	if err != nil {
		s.log.Error("api key delete", "err", err)
		writeErr(w, 500, "database error")
		return
	}
	if !deleted {
		writeErr(w, http.StatusNotFound, "unknown api key")
		return
	}
	s.audit(r, "apikey.delete", strconv.FormatInt(id, 10), "")
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- Wiederherstellen, Export, Import, Reset

// apiRestore nimmt eine Datenbank oder ein Archiv (Body roh oder multipart-Feld "file"; Passwort des Archivs im
// Feld "password" oder Header X-Backup-Password) und startet neu.
func (s *Server) apiRestore(w http.ResponseWriter, r *http.Request) {
	longTransfer(w)
	src := io.Reader(r.Body)
	pw := r.Header.Get("X-Backup-Password")
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		f, _, err := r.FormFile("file")
		if err != nil {
			writeErr(w, http.StatusBadRequest, "multipart field \"file\" missing")
			return
		}
		defer f.Close()
		src = f
		if p := r.PostFormValue("password"); p != "" {
			pw = p
		}
	}
	n, err := s.restoreAny(r.Context(), src, pw)
	switch {
	case errors.Is(err, errPasswordNeeded):
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	case errors.Is(err, errPasswordWrong):
		writeErr(w, http.StatusForbidden, err.Error())
		return
	case errors.Is(err, errRestoreInvalid):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	case err != nil:
		s.log.Error("restore", "err", err)
		writeErr(w, 500, "could not store the upload")
		return
	}
	s.audit(r, "backup.restore", "", strconv.FormatInt(n, 10)+" bytes")
	writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true, "bytes": n})
	s.restartSoon("restarting for database restore")
}

func (s *Server) apiExport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Secrets  string `json:"secrets"`  // none (Standard) oder password
		Password string `json:"password"` // bei password: mind. 8 Zeichen
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	cf, err := s.buildExport(r.Context(), in.Secrets, in.Password)
	if errors.Is(err, errPasswordShort) {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if err != nil {
		s.log.Error("export", "err", err)
		writeErr(w, 500, "export failed")
		return
	}
	s.audit(r, "config.export", "", "secrets="+cf.Secrets.Mode)
	writeJSON(w, 200, cf)
}

// apiImport nimmt die exportierte Datei als Body; das Passwort fuer verschluesselte Geheimnisse im Kopf
// X-Config-Password.
func (s *Server) apiImport(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxImport))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "body could not be read")
		return
	}
	count, problems, err := s.applyImport(r.Context(), raw, r.Header.Get("X-Config-Password"))
	switch {
	case errors.Is(err, errConfigInvalid), errors.Is(err, errPasswordNeeded), errors.Is(err, errPasswordWrong):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	case err != nil:
		s.log.Error("import", "err", err)
		writeErr(w, 500, "import failed")
		return
	}
	s.audit(r, "config.import", "", strconv.Itoa(count)+" items")
	if problems == nil {
		problems = []string{}
	}
	writeJSON(w, 200, map[string]any{"imported": count, "problems": problems})
}

// apiReset setzt den Node zurueck; wie in der Oberflaeche nur mit dem Passwort des Benutzers (auch per API-Key).
func (s *Server) apiReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password   string `json:"password"`
		KeepChecks bool   `json:"keep_checks"` // bei Verknuepfung: Checks bei ipv64 behalten
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u := currentUser(r)
	if !VerifyPassword(u.PasswordHash, in.Password) {
		s.audit(r, "node.reset_denied", "", "wrong password")
		writeErr(w, http.StatusForbidden, "wrong password")
		return
	}
	problems, err := s.requestReset(r.Context(), in.KeepChecks)
	if err != nil {
		s.log.Error("reset", "err", err)
		writeErr(w, 500, "reset could not be requested")
		return
	}
	s.audit(r, "node.reset", "", strings.Join(problems, "; "))
	s.log.Warn("factory reset requested", "user", u.Username)
	if problems == nil {
		problems = []string{}
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"restarting": true, "cleanup_problems": problems})
	s.restartSoon("restarting for factory reset")
}

// ---------------------------------------------------------------- Zahlen des Dashboards

func (s *Server) apiOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	out := map[string]any{
		"node": map[string]any{"id": s.Store.SettingOr(ctx, SettingNodeID, ""), "name": s.Store.SettingOr(ctx, SettingNodeName, ""), "location": s.Store.SettingOr(ctx, SettingNodeLocation, ""), "version": s.Version, "started_at": s.StartedAt, "db_bytes": s.Store.Size()},
	}
	var mods []map[string]any
	for _, m := range s.Modules.List(ctx) {
		mods = append(mods, map[string]any{"name": m.Info.Name, "version": m.Info.Version, "enabled": m.Enabled, "running": m.Running, "last_error": m.LastError})
	}
	out["modules"] = mods
	rx, tx, ok := netstat.Read()
	trx, ttx, since := netstat.Totals(ctx, s.Store)
	if trx < rx {
		trx, ttx = rx, tx
	}
	out["traffic"] = map[string]any{"available": ok, "rx_since_start": rx, "tx_since_start": tx, "rx_total": trx, "tx_total": ttx, "since": since}
	if s.Modules.IsRunning(healthchecks.Name) && s.HC != nil {
		hc := map[string]int{}
		if list, err := s.HC.AllChecks(ctx); err == nil {
			for _, c := range list {
				hc[strings.TrimPrefix(c.Where().Key, "hc.where.")]++
			}
		}
		peers, online := 0, 0
		for _, p := range s.HC.Peers(ctx) {
			peers++
			if p.Online {
				online++
			}
		}
		out["healthchecks"] = map[string]any{"checks_by_location": hc, "nodes": peers, "nodes_online": online}
	}
	if s.IPv64 != nil {
		if ov := s.IPv64.Overview(ctx, 5*time.Minute); ov != nil {
			limits := make([]map[string]any, 0, len(ov.Limits))
			for _, l := range ov.Limits {
				limits = append(limits, map[string]any{"key": l.Key, "used": l.Used, "max": l.Max, "unlimited": l.Unlimited, "pct": l.Pct()})
			}
			acc := map[string]any{"account": ov.Account, "plan": ov.Plan, "limits": limits, "checked_at": ov.At}
			if !ov.PlanUntil.IsZero() {
				acc["plan_until"] = ov.PlanUntil
			}
			if ov.Err != "" {
				acc["error"] = ov.Err
			}
			out["account"] = acc
		}
	}
	if raw := s.Store.SettingOr(ctx, "updates.latest", ""); raw != "" && json.Valid([]byte(raw)) {
		out["update"] = json.RawMessage(raw)
	}
	writeJSON(w, 200, out)
}
