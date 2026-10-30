package web

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Seiten fuer Benachrichtigungskanaele, Ruhezeiten und Zustellprotokoll.

type notifyData struct {
	Channels   []*notify.Channel
	Deliveries []notify.Delivery
	NextBefore int64
	Types      []notify.Type
	Planned    []notify.Type
	Quiet      map[string]string
	Days       []int
	HasBrowser bool // es gibt schon einen Browser-Kanal
	SMS        *smsQuota
	Linked     bool      // Healthchecks-Sync mit ipv64 verknuepft (Server-Kanaele kommen als Platzhalter)
	APIKey     bool      // API-Key eingetragen: E-Mail/SMS des Accounts anlegen und verwalten ueber die API
	Rows       []chanRow // Tabelle: eigene Kanaele und (ohne Verknuepfung) E-Mail/SMS/App bei ipv64
	RemoteErr  string    // ipv64 nicht erreichbar (Kanaele bei ipv64 fehlen in der Tabelle)
}

// smsQuota: SMS des ipv64-Accounts heute (nur verknuepft; Stand der letzten Abfrage, hoechstens 5 min alt).
// Limit 0 = unbegrenzt (Business/Company, wie user_class.sms_limit bei ipv64).
type smsQuota struct{ Left, Limit int }

func (s *Server) smsQuota(ctx context.Context) *smsQuota {
	if s.Sync == nil || !s.Sync.State().Linked {
		return nil
	}
	var acc struct {
		Limits map[string]int `json:"limits"`
		Usage  map[string]int `json:"usage"`
	}
	if json.Unmarshal([]byte(s.Store.SettingOr(ctx, "sync.account", "")), &acc) != nil || acc.Limits == nil {
		return nil
	}
	q := &smsQuota{Limit: acc.Limits["sms_per_day"]}
	q.Left = max(0, q.Limit-acc.Usage["sms_today"])
	return q
}

func (s *Server) notifyRoutes() {
	s.mux.Handle("GET /notifications", s.auth(s.notifyIndex))
	s.mux.Handle("POST /notifications/settings", s.auth(s.notifySettings))
	s.mux.Handle("GET /notifications/new", s.auth(s.channelForm))
	s.mux.Handle("POST /notifications/new", s.auth(s.channelSubmit))
	s.mux.Handle("GET /notifications/{id}/edit", s.auth(s.channelForm))
	s.mux.Handle("POST /notifications/{id}/edit", s.auth(s.channelSubmit))
	s.mux.Handle("POST /notifications/{id}/test", s.auth(s.channelTest))
	s.mux.Handle("POST /notifications/{id}/delete", s.auth(s.channelDelete))
	s.mux.Handle("POST /notifications/{id}/toggle", s.auth(s.channelToggle))
	s.mux.Handle("GET /notifications/stream", s.auth(s.notifyStream))
	s.ipv64ChRoutes()
}

// notifyStream liefert Browser-Benachrichtigungen als Server-Sent Events an die geoeffnete Seite.
func (s *Server) notifyStream(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	events, cancel := notify.Browser.Subscribe()
	defer cancel()
	write := func(s string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := io.WriteString(w, s); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !write(": connected\nretry: 5000\n\n") {
		return
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if !write(": ping\n\n") {
				return
			}
		case e, ok := <-events:
			if !ok {
				return
			}
			b, _ := json.Marshal(e)
			if !write("event: notify\ndata: " + string(b) + "\n\n") {
				return
			}
		}
	}
}

func (s *Server) notifyIndex(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "nf.title")
	chans, err := s.Notify.Channels(ctx)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	before, _ := strconv.ParseInt(r.URL.Query().Get("before"), 10, 64)
	dl, err := s.Notify.Deliveries(ctx, 50, before, 0)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := notifyData{Channels: chans, Deliveries: dl, Types: notify.Types, Planned: notify.Planned, Days: []int{1, 2, 3, 4, 5, 6, 7}, SMS: s.smsQuota(r.Context())}
	for _, ch := range chans {
		if ch.Type == notify.TypeBrowser {
			d.HasBrowser = true
		}
	}
	d.Linked = s.Sync != nil && s.Sync.State().Linked
	d.APIKey = s.IPv64 != nil && s.IPv64.Get(ctx) != ""
	for _, ch := range chans {
		d.Rows = append(d.Rows, chanRow{Channel: ch, Base: "/notifications/" + strconv.FormatInt(ch.ID, 10)})
	}
	if d.APIKey && !d.Linked { // verknuepft kommen sie als Platzhalter ueber den Sync (schon in chans)
		list, err := s.IPv64.AccountChannels(ctx)
		if err != nil {
			d.RemoteErr = err.Error()
		}
		for _, rc := range list {
			d.Rows = append(d.Rows, remoteChannel(rc))
		}
	}
	if len(dl) == 50 {
		d.NextBefore = dl[len(dl)-1].ID
	}
	tz := v.User.Timezone
	if tz == "" {
		tz = DefaultTimezone
	}
	d.Quiet = map[string]string{
		"enabled": s.Store.SettingOr(ctx, notify.SetQuietEnabled, "0"), "from": s.Store.SettingOr(ctx, notify.SetQuietFrom, "22:00"),
		"to": s.Store.SettingOr(ctx, notify.SetQuietTo, "07:00"), "days": "," + s.Store.SettingOr(ctx, notify.SetQuietDays, "1,2,3,4,5,6,7") + ",",
		"tz": s.Store.SettingOr(ctx, notify.SetQuietTZ, tz), "base_url": s.Store.SettingOr(ctx, notify.SetBaseURL, ""),
		"rate": s.Store.SettingOr(ctx, notify.SetRatePerHour, "60"), "batch_threshold": s.Store.SettingOr(ctx, notify.SetBatchThreshold, "3"),
		"batch_window": s.Store.SettingOr(ctx, notify.SetBatchWindow, "10"),
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "notifications", v)
}

func (s *Server) notifySettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	f := s.formValues(r, "quiet_enabled", "quiet_from", "quiet_to", "quiet_tz", "base_url", "rate", "batch_threshold", "batch_window")
	_ = r.ParseForm()
	v := s.view(r, "nf.title")
	for _, k := range []string{"quiet_from", "quiet_to"} {
		if _, err := parseClock(f[k]); err != nil {
			s.flash(w, r, "danger", v.T("errors.validation")+" ("+k+")")
			http.Redirect(w, r, "/notifications", http.StatusSeeOther)
			return
		}
	}
	if f["base_url"] != "" && !strings.HasPrefix(f["base_url"], "http://") && !strings.HasPrefix(f["base_url"], "https://") {
		s.flash(w, r, "danger", v.T("errors.validation")+" (base_url)")
		http.Redirect(w, r, "/notifications", http.StatusSeeOther)
		return
	}
	var days []string
	for _, d := range r.PostForm["quiet_days"] {
		if n, err := strconv.Atoi(d); err == nil && n >= 1 && n <= 7 {
			days = append(days, d)
		}
	}
	enabled := "0"
	if f["quiet_enabled"] == "on" {
		enabled = "1"
	}
	tz := f["quiet_tz"]
	if tz == "" || !validTimezone(tz) {
		tz = DefaultTimezone
	}
	set := map[string]string{
		notify.SetQuietEnabled: enabled, notify.SetQuietFrom: f["quiet_from"], notify.SetQuietTo: f["quiet_to"], notify.SetQuietDays: strings.Join(days, ","),
		notify.SetQuietTZ: tz, notify.SetBaseURL: strings.TrimRight(f["base_url"], "/"),
		notify.SetRatePerHour: clampStr(f["rate"], 0, 1000, "60"), notify.SetBatchThreshold: clampStr(f["batch_threshold"], 0, 100, "3"), notify.SetBatchWindow: clampStr(f["batch_window"], 0, 600, "10"),
	}
	for k, val := range set {
		if err := s.Store.SetSetting(ctx, k, val); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if s.Linker != nil {
		s.Linker.NotifySettingsChanged() // gelten fuer den Account: an ipv64 und die anderen Nodes
	}
	s.audit(r, "notify.settings", "", fmt.Sprintf("quiet=%s %s-%s days=%s", enabled, f["quiet_from"], f["quiet_to"], strings.Join(days, ",")))
	s.flash(w, r, "success", v.T("common.saved"))
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func parseClock(s string) (int, error) {
	var h, m int
	if _, err := fmt.Sscanf(s, "%d:%d", &h, &m); err != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, fmt.Errorf("invalid time %q", s)
	}
	return h*60 + m, nil
}

func clampStr(s string, lo, hi int, def string) string {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < lo {
		n = lo
	}
	if n > hi {
		n = hi
	}
	return strconv.Itoa(n)
}

type channelFormData struct {
	Server   bool   // Kanal des Portals (Geheimnisse bei ipv64)
	IPv64    bool   // E-Mail/SMS bei ipv64, ueber die API verwaltet
	Action   string // Ziel des Formulars ("" = eigener Kanal)
	TypeBase string // Adresse der Typ-Auswahl ("" = /notifications/new)
	Edit     bool
	ID       int64
	Type     notify.Type
	Types    []notify.Type
	Fields   []notify.Field
	Form     map[string]string
	Error    string
	Langs    []string
}

func (s *Server) loadChannel(w http.ResponseWriter, r *http.Request) *notify.Channel {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ch, err := s.Notify.Channel(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return nil
	}
	if ch == nil {
		s.errorPage(w, r, http.StatusNotFound, "nf.missing")
		return nil
	}
	return ch
}

func (s *Server) channelForm(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "nf.new")
	d := channelFormData{Types: notify.Types, Form: map[string]string{"enabled": "on", "notify_down": "on", "notify_up": "on", "lang": v.Lang}, Langs: s.I18n.Languages()}
	server := false
	if r.PathValue("id") != "" {
		ch := s.loadChannel(w, r)
		if ch == nil {
			return
		}
		v.Title = v.T("nf.edit")
		d.Edit, d.ID, d.Type = true, ch.ID, ch.Type
		server = ch.Execution == "server"
		d.Form = map[string]string{"name": ch.Name, "lang": ch.Lang}
		if ch.Enabled {
			d.Form["enabled"] = "on"
		}
		if ch.Default {
			d.Form["default"] = "on"
		}
		if ch.NotifyDown {
			d.Form["notify_down"] = "on"
		}
		if ch.NotifyUp {
			d.Form["notify_up"] = "on"
		}
		for k, val := range ch.Config {
			if notify.IsSecret(ch.Type, k) {
				continue // Geheimnisse werden nicht ins Formular geschrieben
			}
			d.Form["cfg_"+k] = val
		}
	} else {
		d.Type = notify.Type(r.URL.Query().Get("type"))
		if _, ok := notify.Fields[d.Type]; !ok {
			d.Type = notify.TypeSMTP
		}
		for _, f := range notify.Fields[d.Type] {
			if f.Default != "" {
				d.Form["cfg_"+f.Key] = f.Default
			}
		}
	}
	d.Fields = notify.Fields[d.Type]
	d.Server = server // Kanal des Portals: Geheimnisse liegen bei ipv64 (leer = unveraendert)
	v.Data = d
	s.render(w, r, http.StatusOK, "channel_form", v)
}

func (s *Server) channelSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "nf.new")
	_ = r.ParseForm()
	var ch *notify.Channel
	edit := r.PathValue("id") != ""
	if edit {
		if ch = s.loadChannel(w, r); ch == nil {
			return
		}
		v.Title = v.T("nf.edit")
	} else {
		ch = &notify.Channel{Type: notify.Type(r.PostFormValue("type")), Config: map[string]string{}}
	}
	ch.Name = strings.TrimSpace(r.PostFormValue("name"))
	ch.Enabled = r.PostFormValue("enabled") == "on"
	ch.Default = r.PostFormValue("default") == "on"
	ch.NotifyDown = r.PostFormValue("notify_down") == "on"
	ch.NotifyUp = r.PostFormValue("notify_up") == "on"
	if l := r.PostFormValue("lang"); s.I18n.Has(l) {
		ch.Lang = l
	}
	// Kanal des Portals: die Node kennt nur die nicht geheimen Werte; leere Geheimnisse bleiben bei ipv64
	server := edit && ch.Execution == "server"
	for _, f := range notify.Fields[ch.Type] {
		val := r.PostFormValue("cfg_" + f.Key)
		if f.Kind == "bool" {
			val = map[bool]string{true: "true", false: "false"}[val == "on"]
		}
		if f.Secret && strings.TrimSpace(val) == "" && edit {
			continue // leer = gespeichertes Geheimnis behalten
		}
		ch.Config[f.Key] = strings.TrimSpace(val)
	}
	var err error
	if server {
		err = ch.ValidateKeepSecrets()
	} else {
		err = ch.Validate()
	}
	if err == nil {
		if edit {
			err = s.Notify.Update(ctx, ch)
		} else {
			err = s.Notify.Insert(ctx, ch)
		}
	}
	if err != nil {
		d := channelFormData{Edit: edit, ID: ch.ID, Type: ch.Type, Types: notify.Types, Fields: notify.Fields[ch.Type], Form: map[string]string{}, Error: err.Error(), Langs: s.I18n.Languages()}
		for k := range r.PostForm {
			d.Form[k] = r.PostFormValue(k)
		}
		for _, f := range notify.Fields[ch.Type] {
			if f.Secret {
				delete(d.Form, "cfg_"+f.Key)
			}
		}
		v.Data = d
		s.render(w, r, http.StatusUnprocessableEntity, "channel_form", v)
		return
	}
	s.audit(r, map[bool]string{true: "channel.update", false: "channel.create"}[edit], ch.Name, string(ch.Type))
	s.flash(w, r, "success", v.T("nf.saved"))
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) channelTest(w http.ResponseWriter, r *http.Request) {
	ch := s.loadChannel(w, r)
	if ch == nil {
		return
	}
	v := s.view(r, "nf.title")
	var err error
	if serverOnly(ch) && s.Linker != nil {
		// Mail, SMS und App stellt nur ipv64 zu: Test ueber den hub
		err = s.Linker.TestServerChannel(r.Context(), ch.RemoteID, v.Lang)
	} else {
		err = s.Dispatcher.Test(r.Context(), ch)
	}
	if err != nil {
		s.flash(w, r, "danger", v.T("nf.test_failed", "name", ch.Name, "error", err.Error()))
	} else {
		s.flash(w, r, "success", v.T("nf.test_ok", "name", ch.Name))
	}
	s.audit(r, "channel.test", ch.Name, "")
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) channelDelete(w http.ResponseWriter, r *http.Request) {
	ch := s.loadChannel(w, r)
	if ch == nil {
		return
	}
	if err := s.Notify.Delete(r.Context(), ch.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	v := s.view(r, "nf.title")
	s.audit(r, "channel.delete", ch.Name, string(ch.Type))
	s.flash(w, r, "success", v.T("nf.deleted"))
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

func (s *Server) channelToggle(w http.ResponseWriter, r *http.Request) {
	ch := s.loadChannel(w, r)
	if ch == nil {
		return
	}
	switch r.PostFormValue("field") {
	case "enabled":
		ch.Enabled = !ch.Enabled
	case "default":
		ch.Default = !ch.Default
	}
	if err := s.Notify.Update(r.Context(), ch); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "channel.update", ch.Name, fmt.Sprintf("enabled=%v default=%v", ch.Enabled, ch.Default))
	http.Redirect(w, r, "/notifications", http.StatusSeeOther)
}

// serverOnly: Kanaele, die nur der ipv64-hub zustellen kann.
func serverOnly(ch *notify.Channel) bool {
	switch ch.Type {
	case notify.TypeIPv64Mail, notify.TypeIPv64SMS:
		return true
	}
	return ch.Execution == "server"
}
