package web

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// Seite "ipv64-Verknuepfung": Code holen, Status abfragen, trennen, Konflikte loesen.

func (s *Server) syncRoutes() {
	s.mux.Handle("GET /link", s.auth(s.linkPage))
	s.mux.Handle("POST /link/start", s.auth(s.linkStart))
	s.mux.Handle("GET /link/status", s.auth(s.linkStatus))
	s.mux.Handle("POST /link/cancel", s.auth(s.linkCancel))
	s.mux.Handle("POST /link/unlink", s.auth(s.linkUnlink))
	s.mux.Handle("POST /link/conflicts/{id}", s.auth(s.linkResolve))
	s.mux.Handle("POST /link/settings", s.auth(s.linkSettings))
}

type linkData struct {
	State      nodesync.State
	Available  bool
	Conflicts  []conflictRow
	LocalNotif bool
	Peers      []healthchecks.PeerRow // Nodes des Accounts
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
	if s.HC != nil && d.State.Linked {
		d.Peers = s.HC.Peers(r.Context())
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

func (s *Server) linkCancel(w http.ResponseWriter, r *http.Request) {
	if s.Linker != nil {
		s.Linker.LinkCancel()
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
	_ = s.Store.SetSetting(r.Context(), nodesync.SetLocalNotif, v)
	s.flash(w, r, "success", s.tr(r, "common.saved"))
	http.Redirect(w, r, "/link", http.StatusSeeOther)
}
