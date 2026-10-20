package honeypot

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// HTTP/HTTPS-Falle: neutrale Login-Koeder (ohne Markennamen, Logos oder Nachbau echter Seiten) nach Pfad-Gruppen,
// jede Anfrage wird eingeordnet (sensor_classify.go) und gemeldet. Antworten wie ein ueblicher Webserver.
const (
	sensorHTTPHeader  = 8 << 10  // Kopfzeilen
	sensorHTTPBody    = 16 << 10 // gelesener Body
	sensorHTTPTimeout = 15 * time.Second
	sensorHTTPServer  = "nginx"
)

type sensorConnKey struct{}

// httpServer baut den Server eines HTTP/HTTPS-Dienstes (ohne Keep-Alive und HTTP/2: eine Anfrage je Verbindung).
func (s *Sensor) httpServer(t *trapService, cert *tls.Certificate) *http.Server {
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.serveHTTP(t, w, r) }),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       sensorHTTPTimeout,
		WriteTimeout:      sensorHTTPTimeout,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    sensorHTTPHeader,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSNextProto:      map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if tc := sensorTrapConn(c); tc != nil {
				return context.WithValue(ctx, sensorConnKey{}, tc)
			}
			return ctx
		},
		ConnState: func(c net.Conn, st http.ConnState) {
			// Verbindung ohne bearbeitete Anfrage (TLS-Abbruch, kaputte Anfrage, nur Verbindungsaufbau)
			if st != http.StateClosed && st != http.StateHijacked {
				return
			}
			if tc := sensorTrapConn(c); tc != nil && !tc.handled.Swap(true) {
				s.emit(tc.event(KindProbe))
			}
		},
	}
	if cert != nil {
		srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
	}
	srv.SetKeepAlivesEnabled(false)
	return srv
}

func sensorTrapConn(c net.Conn) *trapConn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	tc, _ := c.(*trapConn)
	return tc
}

func (s *Sensor) serveHTTP(t *trapService, w http.ResponseWriter, r *http.Request) {
	tc, _ := r.Context().Value(sensorConnKey{}).(*trapConn)
	var e Event
	if tc != nil {
		tc.handled.Store(true)
		e = tc.event(KindHTTPScan)
	} else {
		e = Event{Time: time.Now(), Service: t.key.Service, Port: t.key.Port, Kind: KindHTTPScan}
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
			e.Src, e.SrcPort = ap.Addr().Unmap(), int(ap.Port())
		}
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, sensorHTTPBody))
	e.Method = r.Method
	e.Path = r.RequestURI
	e.Host = r.Host
	if e.Host == "" && r.TLS != nil {
		e.Host = r.TLS.ServerName
	}
	e.UA = r.UserAgent()
	if len(body) > 0 {
		e.Payload = body[:min(len(body), MaxPayload)]
	}

	kind, tags := sensorClassify(r, body)
	owasp := strings.HasPrefix(kind, KindHTTPExploit+":")
	user, pass, isLogin := sensorHTTPCreds(r, body)
	page := ""
	if !owasp && kind != KindHTTPExploit {
		page = sensorPageFor(t.key.Page, r.URL.Path)
	}
	switch {
	case isLogin && !owasp:
		kind = KindHTTPBrute
	case kind == "":
		kind = KindHTTPScan
	}
	e.Kind, e.Page, e.Detail = kind, page, strings.Join(tags, ",")
	if isLogin {
		e.Username, e.Password = user, pass
		s.login(e)
	} else {
		s.emit(e)
	}

	h := w.Header()
	h.Set("Server", sensorHTTPServer)
	switch {
	case page != "":
		h.Set("Content-Type", "text/html; charset=UTF-8")
		h.Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, sensorPageHTML(page, isLogin))
	case strings.HasPrefix(r.URL.Path, "/."):
		sensorHTTPError(w, http.StatusForbidden)
	default:
		sensorHTTPError(w, http.StatusNotFound)
	}
}

// sensorHTTPError schreibt eine schlichte Fehlerseite wie ein ueblicher Webserver.
func sensorHTTPError(w http.ResponseWriter, code int) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	st := fmt.Sprintf("%d %s", code, http.StatusText(code))
	_, _ = fmt.Fprintf(w, "<html>\r\n<head><title>%s</title></head>\r\n<body>\r\n<center><h1>%s</h1></center>\r\n<hr><center>%s</center>\r\n</body>\r\n</html>\r\n", st, st, sensorHTTPServer)
}

// Feldnamen fuer Zugangsdaten (WordPress, phpMyAdmin, uebliche Formulare).
var (
	sensorUserKeys = []string{"log", "pma_username", "username", "user", "login", "email", "uname", "usr"}
	sensorPassKeys = []string{"pwd", "pma_password", "password", "pass", "passwd", "pw"}
)

// sensorHTTPCreds findet Zugangsdaten: Basic-Auth, Formular oder JSON im Body, Passwort in der Abfrage.
func sensorHTTPCreds(r *http.Request, body []byte) (user, pass string, ok bool) {
	if u, p, ok := r.BasicAuth(); ok {
		return u, p, true
	}
	if len(body) > 0 {
		vals := map[string]string{}
		ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch {
		case strings.HasSuffix(ct, "json"):
			var m map[string]any
			if json.Unmarshal(body, &m) == nil {
				for k, v := range m {
					if s, isStr := v.(string); isStr {
						vals[strings.ToLower(k)] = s
					}
				}
			}
		case ct == "" || ct == "application/x-www-form-urlencoded" || ct == "text/plain":
			if q, err := url.ParseQuery(string(body)); err == nil {
				for k := range q {
					vals[strings.ToLower(k)] = q.Get(k)
				}
			}
		}
		user, pass = sensorPick(vals, sensorUserKeys), sensorPick(vals, sensorPassKeys)
		if user != "" || pass != "" {
			return user, pass, true
		}
	}
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			q[strings.ToLower(k)] = v[0]
		}
	}
	if pass = sensorPick(q, sensorPassKeys); pass != "" {
		return sensorPick(q, sensorUserKeys), pass, true
	}
	return "", "", false
}

func sensorPick(vals map[string]string, keys []string) string {
	for _, k := range keys {
		if v := vals[k]; v != "" {
			return v
		}
	}
	return ""
}

// sensorPageFor liefert den Koeder fuer einen Pfad ("" = kein Koeder, 404). fixed != "" beantwortet alle
// Koeder-Pfade mit diesem Koeder.
func sensorPageFor(fixed, path string) string {
	g := sensorPageGroup(path)
	if g == "" || fixed == "" {
		return g
	}
	return fixed
}

// sensorPageGroup ordnet einen Pfad einer Koeder-Gruppe zu (Pages).
func sensorPageGroup(path string) string {
	p := strings.ToLower(path)
	switch p {
	case "/", "/index.html", "/index.htm", "/index.php":
		return "generic"
	}
	if strings.HasSuffix(p, "/wp-login.php") || strings.Contains(p, "/wp-admin") {
		return "wp-login"
	}
	seg, rest, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	switch rest {
	case "", "index.php", "login", "login.php":
	default:
		return ""
	}
	switch seg {
	case "phpmyadmin", "pma", "myadmin", "phpmyadmin2", "mysqladmin", "dbadmin", "sqladmin", "mysql":
		if rest == "" || rest == "index.php" {
			return "phpmyadmin"
		}
	case "admin", "administrator", "login", "login.php", "login.html", "admin.php", "admin.html", "signin", "panel", "adminpanel", "user":
		return "admin"
	}
	return ""
}

// sensorPageHTML liefert einen schlichten, neutralen Login-Koeder.
func sensorPageHTML(page string, failed bool) string {
	title, action, userLabel, uf, pf, extra := "Sign in", "", "Username", "username", "password", ""
	switch page {
	case "wp-login":
		title, action, userLabel, uf, pf = "Log In", "/wp-login.php", "Username or Email Address", "log", "pwd"
		extra = `<p><label><input name="rememberme" type="checkbox" value="forever"> Remember Me</label></p>` +
			`<input type="hidden" name="redirect_to" value="/wp-admin/"><input type="hidden" name="testcookie" value="1">`
	case "phpmyadmin":
		title, action, uf, pf = "Login", "index.php", "pma_username", "pma_password"
		extra = `<input type="hidden" name="server" value="1">`
	case "admin":
		title = "Administration"
	}
	msg := ""
	if failed {
		msg = `<p class="err">Invalid username or password.</p>`
	}
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>` + title + `</title>
<style>body{font-family:sans-serif;background:#f2f2f2;margin:0}form{max-width:320px;margin:12vh auto;background:#fff;padding:24px;border:1px solid #ddd}
label{display:block;margin:8px 0 4px}input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:8px}
button{margin-top:16px;padding:8px 16px}.err{color:#b00}</style>
</head>
<body>
<form method="post" action="` + action + `">
<h1>` + title + `</h1>
` + msg + `
<label for="u">` + userLabel + `</label><input type="text" id="u" name="` + uf + `" autocomplete="username">
<label for="p">Password</label><input type="password" id="p" name="` + pf + `" autocomplete="current-password">
` + extra + `
<button type="submit">` + title + `</button>
</form>
</body>
</html>
`
}
