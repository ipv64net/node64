package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/ipv64net/node64/internal/edge"
)

// Oberflaeche von Node64 unter einem eigenen Namen ueber den gemeinsamen Eingang (443, mit Zertifikat aus der
// Verwaltung). Standard: nur aus dem eigenen Netz; "von ueberall" muss ausdruecklich eingeschaltet werden.

const (
	setUIName   = "edge.ui_name"
	setUIPublic = "edge.ui_public"
	edgeOwnerUI = "web"
)

var cgnatNet = netip.MustParsePrefix("100.64.0.0/10")

// lanOnly: private Netze, Loopback, Link-local, ULA und 100.64.0.0/10 (Tailscale u. a.).
func lanOnly(ip netip.Addr) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || cgnatNet.Contains(ip)
}

// uiRoute meldet die Oberflaeche beim Eingang an bzw. ab.
func (s *Server) uiRoute(ctx context.Context) error {
	if s.Edge == nil {
		return nil
	}
	name := s.Store.SettingOr(ctx, setUIName, "")
	if name == "" {
		s.Edge.Remove(edgeOwnerUI)
		return nil
	}
	rt := edge.Route{Names: []string{name}, Handler: s.handler, HTTP3: true}
	if s.Store.SettingOr(ctx, setUIPublic, "0") != "1" {
		rt.Allow = lanOnly
	}
	return s.Edge.Set(edgeOwnerUI, []edge.Route{rt})
}

// saveUIRoute prueft und speichert Name und Freigabe, dann neu anmelden.
func (s *Server) saveUIRoute(r *http.Request, name string, public bool) error {
	name = strings.TrimSpace(name)
	if name != "" {
		n, err := edge.NormalizeName(name)
		if err != nil || strings.HasPrefix(n, "*") {
			return errors.New("invalid name")
		}
		name = n
	}
	ctx := context.WithoutCancel(r.Context())
	oldName, oldPub := s.Store.SettingOr(ctx, setUIName, ""), s.Store.SettingOr(ctx, setUIPublic, "0")
	pub := "0"
	if public {
		pub = "1"
	}
	if err := s.Store.SetSetting(ctx, setUIName, name); err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, setUIPublic, pub); err != nil {
		return err
	}
	if err := s.uiRoute(ctx); err != nil { // z. B. Name gehoert schon einem Proxy-Host: alten Stand zurueck
		_ = s.Store.SetSetting(ctx, setUIName, oldName)
		_ = s.Store.SetSetting(ctx, setUIPublic, oldPub)
		_ = s.uiRoute(ctx)
		return err
	}
	if name != oldName || pub != oldPub {
		s.audit(r, "edge.ui", name, fmt.Sprintf("public=%v", public))
	}
	return nil
}

// apiEdgeUI: GET/PUT /api/edge/ui {name, public}.
func (s *Server) apiEdgeUIGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"name": s.Store.SettingOr(r.Context(), setUIName, ""),
		"public": s.Store.SettingOr(r.Context(), setUIPublic, "0") == "1"})
}

func (s *Server) apiEdgeUIPut(w http.ResponseWriter, r *http.Request) {
	in := struct {
		Name   *string `json:"name"`
		Public *bool   `json:"public"`
	}{}
	if !decodeJSON(w, r, &in) {
		return
	}
	name, pub := s.Store.SettingOr(r.Context(), setUIName, ""), s.Store.SettingOr(r.Context(), setUIPublic, "0") == "1"
	if in.Name != nil {
		name = *in.Name
	}
	if in.Public != nil {
		pub = *in.Public
	}
	if err := s.saveUIRoute(r, name, pub); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	s.apiEdgeUIGet(w, r)
}
