package web

import (
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

// E-Mail- und SMS-Kanaele bei ipv64 per API (wie Benachrichtigungen › E-Mail/SMS ueber ipv64): Node64 reicht die
// Aenderungen mit dem zentralen API-Key an ipv64 weiter. Neue Kanaele und neue Adressen/Nummern muessen mit einem Code
// bestaetigt werden (verify/send, dann verify).

func (s *Server) apiIPv64ChRoutes() {
	const p = "/api/ipv64/channels"
	s.mux.Handle("GET "+p, s.auth(s.apiIPv64Channels))
	s.mux.Handle("POST "+p, s.auth(s.apiIPv64ChCreate))
	s.mux.Handle("GET "+p+"/{id}", s.auth(s.apiIPv64ChGet))
	s.mux.Handle("PUT "+p+"/{id}", s.auth(s.apiIPv64ChUpdate))
	s.mux.Handle("DELETE "+p+"/{id}", s.auth(s.apiIPv64ChDelete))
	s.mux.Handle("POST "+p+"/{id}/test", s.auth(s.apiIPv64ChTest))
	s.mux.Handle("POST "+p+"/{id}/verify/send", s.auth(s.apiIPv64ChVerifySend))
	s.mux.Handle("POST "+p+"/{id}/verify", s.auth(s.apiIPv64ChVerify))
}

// apiIPv64Key: zentraler API-Key; leer = Antwort 409 geschrieben.
func (s *Server) apiIPv64Key(w http.ResponseWriter, r *http.Request) string {
	key := ""
	if s.IPv64 != nil {
		key = s.IPv64.Get(r.Context())
	}
	if key == "" {
		writeErr(w, http.StatusConflict, "no ipv64 api key stored (PUT /api/ipv64/key)")
	}
	return key
}

// writeIPv64Err gibt einen Fehler von ipv64 weiter: Pruef- und Nicht-gefunden-Fehler mit ihrem Status, ein
// abgelehnter Key oder andere Fehler als 502 (der Aufrufer selbst ist angemeldet).
func writeIPv64Err(w http.ResponseWriter, err error) {
	var ae *ipv64api.APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Code == "invalid_code":
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid code", "code": ae.Code})
			return
		case ae.Status == http.StatusNotFound || ae.Status == http.StatusConflict || ae.Status == http.StatusUnprocessableEntity ||
			ae.Status == http.StatusBadRequest || ae.Status == http.StatusTooManyRequests:
			writeJSON(w, ae.Status, map[string]string{"error": err.Error(), "code": ae.Code})
			return
		}
	}
	writeErr(w, http.StatusBadGateway, err.Error())
}

// ipv64ChIn: Eingabe fuer Anlegen und Aendern; Config nur mit den Feldern des Typs.
type ipv64ChIn struct {
	Type       string            `json:"type"`
	Name       *string           `json:"name"`
	Lang       *string           `json:"lang"`
	Config     map[string]string `json:"config"`
	Enabled    *bool             `json:"enabled"`
	Default    *bool             `json:"default"`
	NotifyDown *bool             `json:"notify_down"`
	NotifyUp   *bool             `json:"notify_up"`
}

func (in ipv64ChIn) input(typ notify.Type) (ipv64api.ChannelInput, error) {
	out := ipv64api.ChannelInput{Enabled: in.Enabled, Default: in.Default, NotifyDown: in.NotifyDown, NotifyUp: in.NotifyUp}
	if in.Name != nil {
		out.Name = strings.TrimSpace(*in.Name)
		if out.Name == "" || len(out.Name) > 100 {
			return out, errors.New("name must be 1-100 characters")
		}
	}
	if in.Lang != nil {
		out.Lang = strings.TrimSpace(*in.Lang)
	}
	if len(in.Config) > 0 {
		out.Config = map[string]string{}
		for k, v := range in.Config {
			if !slices.ContainsFunc(notify.Fields[typ], func(f notify.Field) bool { return f.Key == k }) {
				return out, errors.New("unknown config field " + k + " for " + string(typ))
			}
			out.Config[k] = strings.TrimSpace(v)
		}
	}
	return out, nil
}

// GET /api/ipv64/channels: E-Mail-, SMS- und App-Kanaele des Accounts (auch unbestaetigte).
func (s *Server) apiIPv64Channels(w http.ResponseWriter, r *http.Request) {
	if s.apiIPv64Key(w, r) == "" {
		return
	}
	list, err := s.IPv64.AccountChannels(r.Context())
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	if list == nil {
		list = []ipv64api.RemoteChannel{}
	}
	writeJSON(w, 200, list)
}

func (s *Server) apiIPv64ChGet(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	rc, err := s.IPv64.Client().Channel(ctx, key, ipv64ChID(r))
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	writeJSON(w, 200, rc)
}

// POST /api/ipv64/channels {type: ipv64_mail|ipv64_sms, name, config, ...}: danach unbestaetigt (verify/send).
func (s *Server) apiIPv64ChCreate(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	var in ipv64ChIn
	if !decodeJSON(w, r, &in) {
		return
	}
	typ := notify.Type(in.Type)
	if !slices.Contains(ipv64ChTypes, typ) {
		writeErr(w, http.StatusUnprocessableEntity, "type must be ipv64_mail or ipv64_sms")
		return
	}
	if in.Name == nil {
		writeErr(w, http.StatusUnprocessableEntity, "name is required")
		return
	}
	ci, err := in.input(typ)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	ci.Type = string(typ)
	ctx, cancel := apiCtx(r)
	defer cancel()
	rc, err := s.IPv64.Client().CreateChannel(ctx, key, ci)
	ipv64api.ResetChannels()
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	s.audit(r, "channel.create", ci.Name, string(typ)+" (ipv64)")
	writeJSON(w, http.StatusCreated, rc)
}

// PUT /api/ipv64/channels/{id}: fehlende Felder bleiben; neue Adresse/Nummer = wieder unbestaetigt.
func (s *Server) apiIPv64ChUpdate(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	var in ipv64ChIn
	if !decodeJSON(w, r, &in) {
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	cur, err := s.IPv64.Client().Channel(ctx, key, id)
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	if in.Type != "" && in.Type != cur.Type {
		writeErr(w, http.StatusUnprocessableEntity, "type cannot be changed")
		return
	}
	ci, err := in.input(notify.Type(cur.Type))
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	rc, err := s.IPv64.Client().UpdateChannel(ctx, key, id, ci)
	ipv64api.ResetChannels()
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	s.audit(r, "channel.update", rc.Name, cur.Type+" (ipv64)")
	writeJSON(w, 200, rc)
}

func (s *Server) apiIPv64ChDelete(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	err := s.IPv64.Client().DeleteChannel(ctx, key, id)
	ipv64api.ResetChannels()
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	s.audit(r, "channel.delete", r.PathValue("id"), "ipv64")
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/ipv64/channels/{id}/test: Testnachricht (nur bestaetigte Kanaele).
func (s *Server) apiIPv64ChTest(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	if err := s.IPv64.Client().TestChannel(ctx, key, ipv64ChID(r)); err != nil {
		writeIPv64Err(w, err)
		return
	}
	s.audit(r, "channel.test", r.PathValue("id"), "ipv64")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// POST /api/ipv64/channels/{id}/verify/send: Bestaetigungscode an Adresse bzw. Nummer schicken.
func (s *Server) apiIPv64ChVerifySend(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	if err := s.IPv64.Client().VerifySend(ctx, key, ipv64ChID(r)); err != nil {
		writeIPv64Err(w, err)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"sent": true})
}

// POST /api/ipv64/channels/{id}/verify {code}: Kanal bestaetigen (falscher Code = 422).
func (s *Server) apiIPv64ChVerify(w http.ResponseWriter, r *http.Request) {
	key := s.apiIPv64Key(w, r)
	if key == "" {
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Code) == "" {
		writeErr(w, http.StatusUnprocessableEntity, "code is required")
		return
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	err := s.IPv64.Client().VerifyCheck(ctx, key, id, strings.TrimSpace(in.Code))
	ipv64api.ResetChannels()
	if err != nil {
		writeIPv64Err(w, err)
		return
	}
	s.audit(r, "channel.verify", r.PathValue("id"), "ipv64")
	rc, err := s.IPv64.Client().Channel(ctx, key, id)
	if err != nil {
		writeJSON(w, 200, map[string]bool{"verified": true})
		return
	}
	writeJSON(w, 200, rc)
}
