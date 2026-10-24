package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/notify"
)

// E-Mail und SMS ueber ipv64: Kanaele des Accounts, die Node64 mit dem API-Key verwaltet wie die eigenen (anlegen,
// aendern, an/aus, Standard, Test, Bestaetigen per Code, loeschen). Gespeichert sind sie bei ipv64.

const ipv64ChPath = "/notifications/ipv64"

// ipv64ChTypes: Kanaltypen, die Node64 bei ipv64 anlegt.
var ipv64ChTypes = []notify.Type{notify.TypeIPv64Mail, notify.TypeIPv64SMS}

// chanRow ist eine Zeile der Kanaltabelle: eigener Kanal der Node oder Kanal bei ipv64.
type chanRow struct {
	*notify.Channel
	Base       string // Adresse der Aktionen (/notifications/<id> bzw. /notifications/ipv64/<id>)
	Remote     bool   // bei ipv64 gespeichert
	Unverified bool   // E-Mail/SMS noch nicht per Code bestaetigt
}

// remoteChannel macht aus einem ipv64-Kanal eine Zeile der Tabelle.
func remoteChannel(rc ipv64api.RemoteChannel) chanRow {
	cfg := map[string]string{}
	for k, v := range rc.Config {
		if s, ok := v.(string); ok {
			cfg[k] = s
		}
	}
	ch := &notify.Channel{ID: rc.ID, Type: notify.Type(rc.Type), Name: rc.Name, Config: cfg, Enabled: rc.Enabled, Default: rc.Default, Lang: rc.Lang,
		NotifyDown: rc.NotifyDown, NotifyUp: rc.NotifyUp, Execution: "server", RemoteID: rc.ID, LastError: rc.LastError}
	return chanRow{Channel: ch, Base: ipv64ChPath + "/" + strconv.FormatInt(rc.ID, 10), Remote: true, Unverified: !rc.Verified}
}

func (s *Server) ipv64ChRoutes() {
	s.mux.Handle("GET "+ipv64ChPath+"/new", s.auth(s.ipv64ChForm))
	s.mux.Handle("POST "+ipv64ChPath+"/new", s.auth(s.ipv64ChSubmit))
	s.mux.Handle("GET "+ipv64ChPath+"/{id}/edit", s.auth(s.ipv64ChForm))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/edit", s.auth(s.ipv64ChSubmit))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/toggle", s.auth(s.ipv64ChToggle))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/test", s.auth(s.ipv64ChTest))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/delete", s.auth(s.ipv64ChDelete))
	s.mux.Handle("GET "+ipv64ChPath+"/{id}/verify", s.auth(s.ipv64ChVerify))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/verify/send", s.auth(s.ipv64ChVerifySend))
	s.mux.Handle("POST "+ipv64ChPath+"/{id}/verify", s.auth(s.ipv64ChVerifyCheck))
}

// ipv64Key liefert den API-Key (leer = keiner: Hinweis und zurueck zur Uebersicht).
func (s *Server) ipv64Key(w http.ResponseWriter, r *http.Request) string {
	key := ""
	if s.IPv64 != nil {
		key = s.IPv64.Get(r.Context())
	}
	if key == "" {
		s.flash(w, r, "warning", s.view(r, "nf.title").T("nf.ipv64_no_key"))
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
	}
	return key
}

func ipv64ChID(r *http.Request) int64 {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id
}

func apiCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 20*time.Second)
}

func (s *Server) ipv64ChForm(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.new")
	d := channelFormData{Types: ipv64ChTypes, TypeBase: ipv64ChPath + "/new", Action: ipv64ChPath + "/new", IPv64: true, Langs: s.I18n.Languages(),
		Form: map[string]string{"enabled": "on", "default": "on", "notify_down": "on", "notify_up": "on", "lang": v.Lang}}
	if id := ipv64ChID(r); id > 0 {
		ctx, cancel := apiCtx(r)
		rc, err := s.IPv64.Client().Channel(ctx, key, id)
		cancel()
		if err != nil {
			s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
			http.Redirect(w, r, "/notifications", http.StatusSeeOther)
			return
		}
		row := remoteChannel(*rc)
		v.Title = v.T("nf.edit")
		d.Edit, d.ID, d.Type, d.Action = true, id, row.Type, row.Base+"/edit"
		d.Form = map[string]string{"name": row.Name, "lang": row.Lang}
		for k, on := range map[string]bool{"enabled": row.Enabled, "default": row.Default, "notify_down": row.NotifyDown, "notify_up": row.NotifyUp} {
			if on {
				d.Form[k] = "on"
			}
		}
		for k, val := range row.Config {
			d.Form["cfg_"+k] = val
		}
	} else {
		d.Type = notify.Type(r.URL.Query().Get("type"))
		if d.Type != notify.TypeIPv64SMS {
			d.Type = notify.TypeIPv64Mail
		}
	}
	d.Fields = notify.Fields[d.Type]
	v.Data = d
	s.render(w, r, http.StatusOK, "channel_form", v)
}

func (s *Server) ipv64ChSubmit(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.new")
	_ = r.ParseForm()
	id := ipv64ChID(r)
	typ := notify.Type(r.PostFormValue("type"))
	if typ != notify.TypeIPv64SMS {
		typ = notify.TypeIPv64Mail
	}
	b := func(k string) *bool { on := r.PostFormValue(k) == "on"; return &on }
	in := ipv64api.ChannelInput{Name: strings.TrimSpace(r.PostFormValue("name")), Lang: r.PostFormValue("lang"), Config: map[string]string{},
		Enabled: b("enabled"), Default: b("default"), NotifyDown: b("notify_down"), NotifyUp: b("notify_up")}
	for _, f := range notify.Fields[typ] {
		in.Config[f.Key] = strings.TrimSpace(r.PostFormValue("cfg_" + f.Key))
	}
	ctx, cancel := apiCtx(r)
	defer cancel()
	var rc *ipv64api.RemoteChannel
	var err error
	if id > 0 {
		rc, err = s.IPv64.Client().UpdateChannel(ctx, key, id, in)
	} else {
		in.Type = string(typ)
		rc, err = s.IPv64.Client().CreateChannel(ctx, key, in)
	}
	ipv64api.ResetChannels()
	if err != nil {
		d := channelFormData{Edit: id > 0, ID: id, Type: typ, Types: ipv64ChTypes, TypeBase: ipv64ChPath + "/new", IPv64: true, Fields: notify.Fields[typ],
			Form: map[string]string{}, Error: err.Error(), Langs: s.I18n.Languages(), Action: ipv64ChPath + "/new"}
		if id > 0 {
			d.Action = ipv64ChPath + "/" + strconv.FormatInt(id, 10) + "/edit"
		}
		for k := range r.PostForm {
			d.Form[k] = r.PostFormValue(k)
		}
		v.Data = d
		s.render(w, r, http.StatusUnprocessableEntity, "channel_form", v)
		return
	}
	s.audit(r, map[bool]string{true: "channel.update", false: "channel.create"}[id > 0], in.Name, string(typ)+" (ipv64)")
	if !rc.Verified { // neu oder neue Adresse/Nummer: zuerst bestaetigen
		http.Redirect(w, r, ipv64ChPath+"/"+strconv.FormatInt(rc.ID, 10)+"/verify", http.StatusSeeOther)
		return
	}
	s.flash(w, r, "success", v.T("nf.saved"))
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) ipv64ChToggle(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	rc, err := s.IPv64.Client().Channel(ctx, key, id)
	if err == nil {
		var in ipv64api.ChannelInput
		switch r.PostFormValue("field") {
		case "enabled":
			on := !rc.Enabled
			in.Enabled = &on
		case "default":
			on := !rc.Default
			in.Default = &on
		}
		_, err = s.IPv64.Client().UpdateChannel(ctx, key, id, in)
		ipv64api.ResetChannels()
	}
	if err != nil {
		s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
	} else {
		s.audit(r, "channel.update", rc.Name, "ipv64 "+r.PostFormValue("field"))
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) ipv64ChTest(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	name := strconv.FormatInt(id, 10)
	if rc, err := s.IPv64.Client().Channel(ctx, key, id); err == nil {
		name = rc.Name
	}
	if err := s.IPv64.Client().TestChannel(ctx, key, id); err != nil {
		s.flash(w, r, "danger", v.T("nf.test_failed", "name", name, "error", err.Error()))
	} else {
		s.flash(w, r, "success", v.T("nf.test_ok", "name", name))
	}
	s.audit(r, "channel.test", name, "ipv64")
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) ipv64ChDelete(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	err := s.IPv64.Client().DeleteChannel(ctx, key, id)
	ipv64api.ResetChannels()
	if err != nil {
		s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
	} else {
		s.audit(r, "channel.delete", strconv.FormatInt(id, 10), "ipv64")
		s.flash(w, r, "success", v.T("nf.deleted"))
	}
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

type ipv64VerifyData struct {
	ID   int64
	Name string
	To   string
	Type notify.Type
}

func (s *Server) ipv64ChVerify(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.verify_title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	rc, err := s.IPv64.Client().Channel(ctx, key, ipv64ChID(r))
	if err != nil {
		s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
		return
	}
	if rc.Verified {
		s.flash(w, r, "success", v.T("nf.verify_ok"))
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
		return
	}
	row := remoteChannel(*rc)
	v.Data = ipv64VerifyData{ID: rc.ID, Name: rc.Name, To: row.Summary(), Type: row.Type}
	s.render(w, r, http.StatusOK, "ipv64_verify", v)
}

func (s *Server) ipv64ChVerifySend(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.verify_title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	if err := s.IPv64.Client().VerifySend(ctx, key, id); err != nil {
		s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
	} else {
		s.flash(w, r, "info", v.T("nf.verify_sent"))
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d/verify", ipv64ChPath, id), http.StatusSeeOther)
}

func (s *Server) ipv64ChVerifyCheck(w http.ResponseWriter, r *http.Request) {
	key := s.ipv64Key(w, r)
	if key == "" {
		return
	}
	v := s.view(r, "nf.verify_title")
	ctx, cancel := apiCtx(r)
	defer cancel()
	id := ipv64ChID(r)
	err := s.IPv64.Client().VerifyCheck(ctx, key, id, strings.TrimSpace(r.PostFormValue("code")))
	ipv64api.ResetChannels()
	var ae *ipv64api.APIError
	switch {
	case err == nil:
		s.audit(r, "channel.verify", strconv.FormatInt(id, 10), "ipv64")
		s.flash(w, r, "success", v.T("nf.verify_ok"))
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
		return
	case errors.As(err, &ae) && ae.Code == "invalid_code":
		s.flash(w, r, "danger", v.T("nf.verify_failed"))
	default:
		s.flash(w, r, "danger", v.T("nf.ipv64_error", "error", err.Error()))
	}
	http.Redirect(w, r, fmt.Sprintf("%s/%d/verify", ipv64ChPath, id), http.StatusSeeOther)
}
