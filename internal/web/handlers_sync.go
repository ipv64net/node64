package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/ipv64api"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// Seite "ipv64-Verknuepfung": Code holen, Status abfragen, trennen, Konflikte loesen.

func (s *Server) syncRoutes() {
	s.mux.Handle("GET /link", s.auth(s.linkPage))
	s.mux.Handle("POST /link/start", s.auth(s.linkStart))
	s.mux.Handle("GET /link/status", s.auth(s.linkStatus))
	s.mux.Handle("POST /link/cancel", s.auth(s.linkCancel))
	s.mux.Handle("POST /link/unlink", s.auth(s.linkUnlink))
	s.mux.Handle("POST /link/apikey", s.auth(s.linkAPIKey))
	s.mux.Handle("POST /link/conflicts/{id}", s.auth(s.linkResolve))
	s.mux.Handle("POST /link/settings", s.auth(s.linkSettings))
}

type linkData struct {
	State      nodesync.State
	Available  bool
	Conflicts  []conflictRow
	LocalNotif bool
	Peers      []healthchecks.PeerRow // Nodes des Accounts
	Own, Other int                    // Checks nur dieser Node / uebrige im Account (Trennen)
	Key        ipv64api.AccountInfo   // zentraler API-Key (Account leer = keiner hinterlegt)
	KeyOK      bool                   // Key hinterlegt: Verknuepfen mit einem Klick
	Location   string                 // Vorgabe Standort
	Mismatch   bool                   // Key gehoert zu einem anderen Account als die Verknuepfung
	Group      groupData              // lokale Gruppe (handlers_peer.go)
}

type conflictRow struct {
	ID       int64
	Entity   string
	Name     string
	Local    string
	Server   string
	Deleted  bool
	Created  time.Time
	LocalOp  string
	Revision int64
}

func (s *Server) linkPage(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "link.title")
	d := linkData{State: s.Sync.State(), Available: s.Linker != nil}
	if s.HC != nil {
		if list, err := s.HC.Conflicts(r.Context()); err == nil {
			for _, c := range list {
				d.Conflicts = append(d.Conflicts, conflictRow{ID: c.ID, Entity: c.Entity, Name: healthchecks.ConflictName(c), Local: pretty(c.LocalPayload), Server: pretty(c.ServerPayload),
					Deleted: c.ServerPayload == "", Created: c.CreatedAt, LocalOp: c.LocalOp, Revision: c.ServerRevision})
			}
		}
	}
	d.LocalNotif = s.Store.SettingOr(r.Context(), nodesync.SetLocalNotif, "0") == "1"
	if s.IPv64 != nil && s.IPv64.Get(r.Context()) != "" {
		d.Key, d.KeyOK = s.IPv64.Info(r.Context()), true
		d.Mismatch = d.State.Linked && d.Key.ID != 0 && d.State.AccountID != "" && d.State.AccountID != strconv.Itoa(d.Key.ID)
	}
	d.Location = s.Store.SettingOr(r.Context(), SettingNodeLocation, "")
	d.Group = s.groupView(r)
	if s.HC != nil && d.State.Linked {
		d.Peers = s.HC.Peers(r.Context())
		d.Own, d.Other = s.HC.LinkScope(r.Context())
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "link", v)
}

func pretty(raw string) string {
	if raw == "" {
		return ""
	}
	var v any
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return raw
	}
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func (s *Server) linkStart(w http.ResponseWriter, r *http.Request) {
	if s.Linker == nil {
		s.flash(w, r, "danger", s.tr(r, "link.unavailable"))
		http.Redirect(w, r, "/link", http.StatusSeeOther)
		return
	}
	// Im Hintergrund anfordern: bei blockiertem Netz wuerde die Seite sonst minutenlang laden
	linker := s.Linker
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		defer cancel()
		_, _, _ = linker.LinkStart(ctx)
	}()
	s.audit(r, "sync.link_start", "", "")
	time.Sleep(300 * time.Millisecond) // kurz warten, damit die Seite bei schneller Antwort direkt den Code zeigt
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}

// linkStatus wird von der Seite per JS abgefragt; solange ein Code offen ist, wird beim hub nachgefragt.
func (s *Server) linkStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Sync.State()
	out := map[string]any{"linked": st.Linked, "connected": st.Connected, "code": st.PendingCode, "hub": st.Hub, "error": st.LastError, "requesting": st.Requesting}
	if !st.Linked && st.PendingCode != "" && s.Linker != nil {
		linked, err := s.Linker.LinkPoll(r.Context())
		if err != nil {
			out["error"] = err.Error()
		}
		if linked {
			out["linked"] = true
			s.audit(r, "sync.linked", "", "")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// linkAPIKey verknuepft mit einem Klick: Code beim hub holen, direkt mit dem zentralen API-Key ueber die
// API v2 einloesen und gleich den Node-Token abholen (ohne Umweg ueber die Webseite).
func (s *Server) linkAPIKey(w http.ResponseWriter, r *http.Request) {
	back := func(kind, msg string) {
		s.flash(w, r, kind, msg)
		http.Redirect(w, r, "/link", http.StatusSeeOther)
	}
	if s.Linker == nil || s.IPv64 == nil {
		back("danger", s.tr(r, "link.unavailable"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	key := s.IPv64.Get(ctx)
	if key == "" {
		back("warning", s.tr(r, "link.key_missing"))
		return
	}
	loc := strings.TrimSpace(r.PostFormValue("location"))
	if len(loc) > 100 {
		loc = loc[:100]
	}
	rm := r.PostFormValue("remote_mgmt")
	if rm != "off" && rm != "read" {
		rm = "full"
	}
	code, _, err := s.Linker.LinkStart(ctx)
	if err != nil {
		back("danger", s.tr(r, "link.start_failed")+": "+err.Error())
		return
	}
	if err := s.IPv64.Client().LinkNode(ctx, key, code, loc, rm); err != nil {
		s.Linker.LinkCancel()
		if errors.Is(err, ipv64api.ErrUnauthorized) {
			back("danger", s.tr(r, "link.key_invalid"))
		} else {
			back("danger", s.tr(r, "link.key_failed", "err", err.Error()))
		}
		return
	}
	s.audit(r, "sync.link_apikey", "", "remote_mgmt="+rm)
	for i := 0; i < 20; i++ { // Token sofort abholen (der Hintergrund-Poll fragt zusaetzlich)
		if ok, _ := s.Linker.LinkPoll(ctx); ok {
			s.audit(r, "sync.linked", "", "")
			back("success", s.tr(r, "link.key_done", "account", s.IPv64.Info(ctx).Account))
			return
		}
		select {
		case <-ctx.Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	back("info", s.tr(r, "link.key_pending"))
}

func (s *Server) linkCancel(w http.ResponseWriter, r *http.Request) {
	if s.Linker != nil {
		s.Linker.LinkCancel()
		s.audit(r, "sync.link_cancel", "", "")
	}
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}

func (s *Server) linkUnlink(w http.ResponseWriter, r *http.Request) {
	if s.Linker == nil {
		http.Redirect(w, r, "/link", http.StatusSeeOther)
		return
	}
	keep := r.PostFormValue("keep_checks") == "on"
	if err := s.Linker.Unlink(r.Context(), keep); err != nil {
		s.flash(w, r, "danger", err.Error())
	} else {
		s.flash(w, r, "success", s.tr(r, "link.unlinked"))
		s.audit(r, "sync.unlink", "", "keep_checks="+strconv.FormatBool(keep))
	}
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}

func (s *Server) linkResolve(w http.ResponseWriter, r *http.Request) {
	if s.Linker == nil {
		http.Redirect(w, r, "/link", http.StatusSeeOther)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	keepServer := r.PostFormValue("keep") != "local"
	if err := s.Linker.Resolve(r.Context(), id, keepServer); err != nil {
		s.flash(w, r, "danger", err.Error())
	} else {
		s.flash(w, r, "success", s.tr(r, "link.conflict_resolved"))
		s.audit(r, "sync.conflict_resolved", r.PathValue("id"), "keep="+r.PostFormValue("keep"))
	}
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}

func (s *Server) linkSettings(w http.ResponseWriter, r *http.Request) {
	v := "0"
	if r.PostFormValue("local_notifications") == "on" {
		v = "1"
	}
	if err := s.Store.SetSetting(r.Context(), nodesync.SetLocalNotif, v); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "sync.local_notifications", "", v)
	s.flash(w, r, "success", s.tr(r, "common.saved"))
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}
