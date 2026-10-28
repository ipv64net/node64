package cdn64

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Login-Seite fuer Zugriffslisten (AccessList.LoginPage): statt des Browser-Dialogs (Basic Auth) ein Formular im Stil
// der Anmeldung von Node64. Nach der Anmeldung haelt ein signiertes Cookie die Sitzung (HMAC mit eigenem Schluessel,
// Benutzer und Ablauf); ein neues Passwort oder ein entfernter Benutzer beendet sie. Basic Auth bleibt fuer Programme
// moeglich. Die Pfade /.node64/login und /.node64/logout gehoeren auf solchen Hosts PROXY64; das Cookie geht nie an
// das Ziel. Fehlversuche zaehlen wie bei Basic Auth (failLimiter, Honeypot-Meldung).

const (
	loginPath       = "/.node64/login"
	logoutPath      = "/.node64/logout"
	setLoginKey     = "cdn64.login_key" // Schluessel der Sitzungs-Cookies (base64, 32 Byte)
	loginSession    = 12 * time.Hour
	loginRemember   = 30 * 24 * time.Hour
	loginCookieBase = "n64_auth_"
)

//go:embed access_login.html
var accessLoginHTML string

// loginKeyOf liefert den Schluessel der Sitzungs-Cookies (beim ersten Mal erzeugt und gespeichert).
func (m *Module) loginKeyOf(ctx context.Context) []byte {
	if k := m.loginKey.Load(); k != nil {
		return *k
	}
	m.loginKeyMu.Lock()
	defer m.loginKeyMu.Unlock()
	if k := m.loginKey.Load(); k != nil {
		return *k
	}
	key, err := base64.StdEncoding.DecodeString(m.core.SettingOr(ctx, setLoginKey, ""))
	if err != nil || len(key) < 32 {
		key = make([]byte, 32)
		_, _ = rand.Read(key)
		if err := m.core.SetSetting(ctx, setLoginKey, base64.StdEncoding.EncodeToString(key)); err != nil {
			m.log.Warn("access list login: key not saved, sessions end with the restart", "err", err)
		}
	}
	m.loginKey.Store(&key)
	return key
}

func loginCookieName(listID int64) string { return loginCookieBase + strconv.FormatInt(listID, 10) }

// userGen: Kennung des Passworts eines Benutzers (aendert sich mit dem Passwort).
func userGen(hash string) string {
	s := sha256.Sum256([]byte("n64-login:" + hash))
	return hex.EncodeToString(s[:8])
}

func loginSign(key []byte, payload string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// loginToken: "<payload base64>.<hmac>" mit payload "liste|benutzer|ablauf|passwort-kennung".
func (g *guard) loginToken(key []byte, user string, until time.Time) string {
	gen := ""
	for _, u := range g.list.Users {
		if u.Username == user {
			gen = userGen(u.Hash)
		}
	}
	p := strconv.FormatInt(g.list.ID, 10) + "|" + user + "|" + strconv.FormatInt(until.Unix(), 10) + "|" + gen
	return base64.RawURLEncoding.EncodeToString([]byte(p)) + "." + loginSign(key, p)
}

// cookieOK: gueltige Sitzung dieser Liste im Cookie.
func (g *guard) cookieOK(r *http.Request, key []byte) bool { return g.cookieUser(r, key) != "" }

// cookieUser: Benutzer der gueltigen Sitzung dieser Liste im Cookie ("" = keine).
func (g *guard) cookieUser(r *http.Request, key []byte) string {
	c, err := r.Cookie(loginCookieName(g.list.ID))
	if err != nil || key == nil {
		return ""
	}
	enc, sig, ok := strings.Cut(c.Value, ".")
	if !ok {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil || !hmac.Equal([]byte(sig), []byte(loginSign(key, string(raw)))) {
		return ""
	}
	f := strings.Split(string(raw), "|")
	if len(f) != 4 || f[0] != strconv.FormatInt(g.list.ID, 10) {
		return ""
	}
	if exp, err := strconv.ParseInt(f[2], 10, 64); err != nil || time.Now().Unix() > exp {
		return ""
	}
	for _, u := range g.list.Users {
		if u.Username == f[1] && userGen(u.Hash) == f[3] {
			return u.Username
		}
	}
	return ""
}

// loginEndpoint beantwortet /.node64/login (POST) und /.node64/logout.
func (m *Module) loginEndpoint(w http.ResponseWriter, r *http.Request, h *Host, g *guard, ip netip.Addr) {
	name := loginCookieName(g.list.ID)
	if r.URL.Path == logoutPath {
		if r.Method != http.MethodPost { // nur per Formular: ein fremdes <img> soll niemanden abmelden
			logoutPage(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if r.URL.Path != loginPath || r.Method != http.MethodPost {
		page(w, http.StatusNotFound)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	_ = r.ParseForm()
	user, next := r.PostFormValue("username"), safeNext(r.PostFormValue("next"))
	if g.checkUser(user, r.PostFormValue("password")) {
		until := time.Now().Add(loginSession)
		ck := &http.Cookie{Name: name, Value: g.loginToken(m.loginKeyOf(r.Context()), user, until), Path: "/", HttpOnly: true, Secure: r.TLS != nil,
			SameSite: http.SameSiteLaxMode}
		if r.PostFormValue("remember") != "" {
			ck.Value = g.loginToken(m.loginKeyOf(r.Context()), user, time.Now().Add(loginRemember))
			ck.MaxAge = int(loginRemember.Seconds())
		}
		http.SetCookie(w, ck)
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	setAuthFail(r)
	if m.authFail.failed(ip) {
		m.log.Warn("access list: too many failed logins, ip blocked", "host", h.Names[0], "ip", ip, "minutes", int(authBlockFor.Minutes()))
		if m.g.Audit != nil {
			m.g.Audit(r, "cdn64.access.blocked", h.Names[0], "ip="+ip.String())
		}
	}
	loginPage(w, r, g, next, user, true)
}

// checkUser prueft Benutzer und Passwort der Liste.
func (g *guard) checkUser(user, pass string) bool {
	if user == "" || pass == "" {
		return false
	}
	req := &http.Request{Header: http.Header{}}
	req.SetBasicAuth(user, pass)
	ok, _ := g.authOK(req)
	return ok
}

// safeNext: nur ein Pfad dieses Namens (kein fremder Host, kein Protokoll).
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") || strings.HasPrefix(next, "/.node64/") {
		return "/"
	}
	return next
}

// loginPage zeigt das Formular (401), Sprache nach dem Browser.
func loginPage(w http.ResponseWriter, r *http.Request, g *guard, next, user string, failed bool) {
	de := strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "de")
	t := func(d, e string) string {
		if de {
			return d
		}
		return e
	}
	errBox := ""
	if failed {
		errBox = `<div class="err">` + t("Benutzername oder Passwort ist falsch.", "Wrong username or password.") + `</div>`
	}
	repl := strings.NewReplacer("{{LANG}}", t("de", "en"), "{{TITLE}}", t("Anmeldung erforderlich", "Sign-in required"),
		"{{HOST}}", html.EscapeString(hostOnly(r.Host)), "{{SUB}}", html.EscapeString(g.list.Name), "{{ERROR}}", errBox,
		"{{ACTION}}", loginPath, "{{NEXT}}", html.EscapeString(next), "{{USER}}", t("Benutzername", "Username"),
		"{{USERNAME}}", html.EscapeString(user), "{{PASS}}", t("Passwort", "Password"),
		"{{REMEMBER}}", t("Angemeldet bleiben (30 Tage)", "Stay signed in (30 days)"), "{{SUBMIT}}", t("Anmelden", "Sign in"),
		"{{FOOT}}", t("Geschützt mit PROXY64 · Node64", "Protected by PROXY64 · Node64"))
	hd := w.Header()
	hd.Set("Content-Type", "text/html; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("X-Robots-Tag", "noindex")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(repl.Replace(accessLoginHTML)))
}

// logoutPage: Knopf zum Abmelden (GET /.node64/logout), das Abmelden selbst nur per POST.
func logoutPage(w http.ResponseWriter, r *http.Request) {
	de := strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "de")
	label := "Sign out"
	if de {
		label = "Abmelden"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = io.WriteString(w, `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">`+
		`<title>`+label+`</title></head><body style="font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;height:90vh">`+
		`<form method="post" action="`+logoutPath+`"><button type="submit" style="font:inherit;padding:10px 24px;border:0;border-radius:6px;background:#0d6efd;color:#fff;cursor:pointer">`+
		label+`</button></form></body></html>`)
}

// stripLoginCookie entfernt das Sitzungs-Cookie, bevor die Anfrage zum Ziel geht.
func stripLoginCookie(r *http.Request, listID int64) {
	name := loginCookieName(listID)
	cs := r.Cookies()
	keep := cs[:0]
	found := false
	for _, c := range cs {
		if c.Name == name {
			found = true
			continue
		}
		keep = append(keep, c)
	}
	if !found {
		return
	}
	r.Header.Del("Cookie")
	if len(keep) > 0 {
		parts := make([]string, len(keep))
		for i, c := range keep {
			parts[i] = c.Name + "=" + c.Value
		}
		r.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}
