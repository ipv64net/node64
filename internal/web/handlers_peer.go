package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/peer"
)

// Lokale Gruppe auf der Seite "Healthchecks-Sync": Code fuer eine weitere Node zeigen, einer Gruppe beitreten,
// Nodes entfernen, Adresse aendern, Gruppe verlassen. Die Nodes selbst sprechen ueber /peer/v1/ (peer-Paket).

type groupData struct {
	Available bool
	Account   int64 // 0 = ohne ipv64-Account keine Gruppe
	Members   []peer.Member
	Code      string
	CodeExp   time.Time
	SelfURL   string // Adresse, unter der der Browser diese Node gerade erreicht
	Linked    bool   // diese Node ist mit ipv64 verknuepft
	Forwarder string // Node, die Aenderungen der Nodes ohne Sync an ipv64 weiterreicht ("" = keine)
	FwdSelf   bool   // das ist diese Node
}

func (s *Server) peerRoutes() {
	if s.Peer == nil {
		return
	}
	s.Peer.Register(s.mux)
	s.mux.Handle("POST /link/group/code", s.auth(s.groupCode))
	s.mux.Handle("POST /link/group/join", s.auth(s.groupJoin))
	s.mux.Handle("POST /link/group/leave", s.auth(s.groupLeave))
	s.mux.Handle("POST /link/group/{id}/remove", s.auth(s.groupRemove))
	s.mux.Handle("POST /link/group/{id}/url", s.auth(s.groupURL))
}

func (s *Server) groupView(r *http.Request) groupData {
	g := groupData{Available: s.Peer != nil}
	if s.Peer == nil {
		return g
	}
	g.Account = s.Peer.Account()
	g.Members, _ = s.Peer.Members(r.Context())
	g.Code, g.CodeExp = s.Peer.PairingCode()
	g.Linked = s.Peer.LinkedSelf()
	_, g.Forwarder, g.FwdSelf = s.Peer.Forwarder(r.Context())
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	g.SelfURL = scheme + "://" + r.Host
	return g
}

func (s *Server) groupBack(w http.ResponseWriter, r *http.Request, kind, msg string) {
	if msg != "" {
		s.flash(w, r, kind, msg)
	}
	http.Redirect(w, r, "/link#group", http.StatusSeeOther)
}

func (s *Server) groupErr(r *http.Request, err error) string {
	switch {
	case errors.Is(err, peer.ErrNoAccount):
		return s.tr(r, "peer.err_no_account")
	case errors.Is(err, peer.ErrAccountMismatch):
		return s.tr(r, "peer.err_account")
	case errors.Is(err, peer.ErrCode):
		return s.tr(r, "peer.err_code")
	case errors.Is(err, peer.ErrSelf):
		return s.tr(r, "peer.err_self")
	}
	return s.tr(r, "peer.err_other", "err", err.Error())
}

func (s *Server) groupCode(w http.ResponseWriter, r *http.Request) {
	if r.PostFormValue("cancel") != "" {
		s.Peer.CancelPairing()
		s.audit(r, "peer.code_cancel", "", "")
		s.groupBack(w, r, "", "")
		return
	}
	if _, _, err := s.Peer.StartPairing(); err != nil {
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.code", "", "")
	s.groupBack(w, r, "", "")
}

func (s *Server) groupJoin(w http.ResponseWriter, r *http.Request) {
	addr, code, self := strings.TrimSpace(r.PostFormValue("addr")), r.PostFormValue("code"), strings.TrimSpace(r.PostFormValue("self_url"))
	if addr == "" || code == "" || self == "" {
		s.groupBack(w, r, "danger", s.tr(r, "errors.validation"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Peer.Join(ctx, addr, code, self); err != nil {
		s.log.Warn("join local group failed", "addr", addr, "err", err)
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.join", addr, "")
	s.groupBack(w, r, "success", s.tr(r, "peer.joined"))
}

func (s *Server) groupRemove(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Remove(ctx, r.PathValue("id")); err != nil {
		s.groupBack(w, r, "danger", s.groupErr(r, err))
		return
	}
	s.audit(r, "peer.remove", r.PathValue("id"), "")
	s.groupBack(w, r, "success", s.tr(r, "peer.removed"))
}

func (s *Server) groupURL(w http.ResponseWriter, r *http.Request) {
	u := strings.TrimSpace(r.PostFormValue("url"))
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		s.groupBack(w, r, "danger", s.tr(r, "peer.err_url"))
		return
	}
	if err := s.Peer.SetURL(r.Context(), r.PathValue("id"), u); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "peer.url", r.PathValue("id"), u)
	s.groupBack(w, r, "success", s.tr(r, "common.saved"))
}

func (s *Server) groupLeave(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	if err := s.Peer.Leave(ctx); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "peer.leave", "", "")
	s.groupBack(w, r, "success", s.tr(r, "peer.left"))
}
