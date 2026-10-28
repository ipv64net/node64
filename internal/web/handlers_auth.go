package web

import (
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/totp"
)

// Zweite Stufe der Anmeldung, 2FA-Einrichtung und API-Keys.

const pendingKey = "totp:pending:" // Praefix fuer das Geheimnis waehrend der Einrichtung (in settings, kurzlebig)

func (s *Server) authRoutes() {
	s.mux.HandleFunc("GET /login/totp", s.loginTOTPForm)
	s.mux.HandleFunc("POST /login/totp", s.loginTOTPSubmit)
	s.mux.Handle("GET /settings/2fa", s.auth(s.twoFASetup))
	s.mux.Handle("POST /settings/2fa/enable", s.auth(s.twoFAEnable))
	s.mux.Handle("POST /settings/2fa/disable", s.auth(s.twoFADisable))
	s.mux.Handle("POST /settings/api-keys", s.auth(s.apiKeyCreate))
	s.mux.Handle("POST /settings/api-keys/{id}/delete", s.auth(s.apiKeyDelete))
	s.mux.Handle("GET /settings/certificate", s.auth(s.certificateDownload))
	s.ssoRoutes()                                   // SSO, Forward-Auth, Passkeys (auth_page.go)
	s.mux.Handle("GET /plans", s.auth(s.plansPage)) // Account-Klassen von ipv64 (plans.go)
}

// ---------------------------------------------------------------- Login, zweite Stufe

func (s *Server) loginTOTPForm(w http.ResponseWriter, r *http.Request) {
	if pendingSession(r) == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	v := s.view(r, "login.title")
	v.Form["next"] = safeNext(r.URL.Query().Get("next"))
	s.render(w, r, http.StatusOK, "login_totp", v)
}

func (s *Server) loginTOTPSubmit(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := pendingSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	u, err := s.Store.UserByID(ctx, sess.UserID)
	if err != nil || u == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip := s.clientIP(r)
	keys := []string{"totp:" + ipKey(ip), "totp:user:" + strconv.FormatInt(u.ID, 10)}
	v := s.view(r, "login.title")
	v.Form["next"] = safeNext(r.PostFormValue("next"))
	if wait := s.limiter.retryAfter(keys...); wait > 0 {
		secs := int(wait.Seconds()) + 1
		v.Flash = &Flash{Kind: "warning", Text: v.T("login.ratelimited", "seconds", secs)}
		s.render(w, r, http.StatusTooManyRequests, "login_totp", v)
		return
	}
	code := strings.TrimSpace(r.PostFormValue("code"))
	ok := totp.Verify(u.TOTPSecret, code, time.Now())
	if !ok && len(code) >= 10 {
		// Wiederherstellungscode
		rec, _ := s.Store.UserTOTPRecovery(ctx, u.ID)
		hashes := strings.Split(rec, ",")
		if rest, used := totp.UseRecovery(code, hashes); used {
			// nur anmelden, wenn der verbrauchte Code auch gespeichert ist (sonst waere er wiederverwendbar)
			if err := s.Store.SetUserTOTP(ctx, u.ID, u.TOTPSecret, strings.Join(rest, ",")); err != nil {
				s.fail(w, r, err)
				return
			}
			ok = true
			s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login.recovery_code", IP: ip})
		}
	}
	if !ok {
		s.limiter.fail(keys...)
		s.loginFailed(r, ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login.totp_failed", IP: ip})
		v.Flash = &Flash{Kind: "danger", Text: v.T("login.totp_failed")}
		s.render(w, r, http.StatusUnauthorized, "login_totp", v)
		return
	}
	if err := s.Store.SetSessionTOTP(ctx, sess.ID, true); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.TouchUserLogin(ctx, u.ID)
	s.auditEntry(ctx, store.AuditEntry{Actor: u.Username, Action: "login", Details: "2fa", IP: ip})
	http.Redirect(w, r, v.Form["next"], http.StatusSeeOther)
}

// ---------------------------------------------------------------- 2FA einrichten

type twoFAData struct {
	Secret   string
	QR       template.URL // data-URI, als sichere URL markiert
	URL      string
	Enabled  bool
	Recovery []string
}

func (s *Server) twoFASetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := currentUser(r)
	v := s.view(r, "twofa.title")
	d := twoFAData{Enabled: u.TOTPSecret != ""}
	if !d.Enabled {
		key := pendingKey + strconv.FormatInt(u.ID, 10)
		secret := s.Store.SettingOr(ctx, key, "")
		if secret == "" {
			secret = totp.NewSecret()
			_ = s.Store.SetSetting(ctx, key, secret)
		}
		d.Secret = secret
		d.URL = totp.URL("Node64", u.Username+"@"+s.Store.SettingOr(ctx, SettingNodeName, "node"), secret)
		if png, err := qrcode.Encode(d.URL, qrcode.Medium, 220); err == nil {
			d.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png)) //nolint:gosec // selbst erzeugtes PNG
		}
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "twofa", v)
}

func (s *Server) twoFAEnable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := currentUser(r)
	v := s.view(r, "twofa.title")
	key := pendingKey + strconv.FormatInt(u.ID, 10)
	secret := s.Store.SettingOr(ctx, key, "")
	if secret == "" || !totp.Verify(secret, r.PostFormValue("code"), time.Now()) {
		s.flash(w, r, "danger", v.T("twofa.code_wrong"))
		http.Redirect(w, r, "/settings/2fa", http.StatusSeeOther)
		return
	}
	codes, hashes := totp.NewRecoveryCodes(8)
	if err := s.Store.SetUserTOTP(ctx, u.ID, secret, strings.Join(hashes, ",")); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.SetSetting(ctx, key, "")
	_ = s.Store.DeleteUserSessions(ctx, u.ID, sessionID(r))
	s.audit(r, "twofa.enable", u.Username, "")
	v.Data = twoFAData{Enabled: true, Recovery: codes}
	v.Flash = &Flash{Kind: "success", Text: v.T("twofa.enabled")}
	s.render(w, r, http.StatusOK, "twofa", v)
}

func (s *Server) twoFADisable(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u := currentUser(r)
	v := s.view(r, "twofa.title")
	if !VerifyPassword(u.PasswordHash, r.PostFormValue("password")) {
		s.flash(w, r, "danger", v.T("settings.password_wrong"))
		http.Redirect(w, r, "/settings/2fa", http.StatusSeeOther)
		return
	}
	if err := s.Store.SetUserTOTP(ctx, u.ID, "", ""); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "twofa.disable", u.Username, "")
	s.flash(w, r, "success", v.T("twofa.disabled"))
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

// ---------------------------------------------------------------- API-Keys

func (s *Server) apiKeyCreate(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	v, err := s.apiDocsView(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	if name == "" || len(name) > 100 {
		s.flash(w, r, "danger", v.T("errors.validation"))
		http.Redirect(w, r, "/api/docs#keys", http.StatusSeeOther)
		return
	}
	key, k, err := s.Store.NewAPIKey(r.Context(), u.ID, name)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "apikey.create", name, k.Hint)
	d := v.Data.(map[string]any)
	d["NewAPIKey"] = key // nur in dieser Antwort sichtbar
	d["APIKeys"], _ = s.Store.APIKeys(r.Context(), u.ID)
	v.Flash = &Flash{Kind: "success", Text: v.T("apikey.created")}
	s.render(w, r, http.StatusOK, "api_docs", v)
}

func (s *Server) apiKeyDelete(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	deleted, err := s.Store.DeleteAPIKey(r.Context(), u.ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v := s.view(r, "api.title")
	if !deleted { // gab es nicht (z. B. schon geloescht): kein Audit-Eintrag
		s.flash(w, r, "warning", v.T("apikey.not_found"))
		http.Redirect(w, r, "/api/docs#keys", http.StatusSeeOther)
		return
	}
	s.audit(r, "apikey.delete", strconv.FormatInt(id, 10), "")
	s.flash(w, r, "success", v.T("apikey.deleted"))
	http.Redirect(w, r, "/api/docs#keys", http.StatusSeeOther)
}

// certificateDownload liefert das selbstsignierte Zertifikat zum Import.
func (s *Server) certificateDownload(w http.ResponseWriter, r *http.Request) {
	file := s.Cfg.TLSCertFile
	if file == "" {
		file = s.Cfg.TLSDir() + "/cert.pem"
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="node64.pem"`)
	http.ServeFile(w, r, file)
}
