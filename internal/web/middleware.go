package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

const (
	sessionCookie = "node64_session"
	csrfCookie    = "node64_csrf"
	flashCookie   = "node64_flash"
	themeCookie   = "node64_theme"
	fontCookie    = "node64_fs"  // Schriftgroesse: sm, lg, xl (leer = normal)
	navCookie     = "node64_nav" // "mini" = Seitenleiste eingeklappt (ab lg)
	langCookie    = "node64_lang"

	sessionIdle = 12 * time.Hour
	sessionMax  = 7 * 24 * time.Hour
)

type ctxKey int

const (
	ctxSession ctxKey = iota
	ctxUser
	ctxCSRF
	ctxPending // Sitzung wartet auf die zweite Stufe (TOTP)
	ctxAPIKey  // Anfrage per API-Key authentifiziert
)

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				if rec == http.ErrAbortHandler { // Abbruch (z. B. unvollstaendiges Archiv): Verbindung schliessen statt Fehlerseite anhaengen
					panic(rec)
				}
				s.log.Error("panic in handler", "err", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				s.errorPage(w, r, http.StatusInternalServerError, "errors.internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimit schuetzt UI und API vor Ueberlastung (je IP).
func (s *Server) rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/static/") && !s.ipLimit.allow(ipKey(s.clientIP(r))) {
			s.log.Warn("request rate limited", "ip", s.clientIP(r), "path", r.URL.Path)
			w.Header().Set("Retry-After", "10")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimitFor(r.URL.Path))
		}
		next.ServeHTTP(w, r)
	})
}

// session laedt Sitzung und Benutzer, stellt den CSRF-Token bereit und prueft
// ihn bei allen aendernden Anfragen.
func (s *Server) session(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		// API-Key: Authorization: Bearer node64_... (nur fuer /api/)
		if strings.HasPrefix(r.URL.Path, "/api/") {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer node64_") {
				lk := "apikey:" + ipKey(s.clientIP(r))
				if wait := s.limiter.retryAfter(lk); wait > 0 { // zu viele Fehlversuche: ohne Abfrage und ohne Log abweisen
					w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
					http.Error(w, `{"error":"too many invalid api keys, try again later"}`, http.StatusTooManyRequests)
					return
				}
				key, err := s.Store.APIKeyByValue(ctx, strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
				if err == nil && key != nil {
					if u, err := s.Store.UserByID(ctx, key.UserID); err == nil && u != nil {
						_ = s.Store.TouchAPIKey(ctx, key.ID)
						ctx = context.WithValue(ctx, ctxUser, u)
						ctx = context.WithValue(ctx, ctxAPIKey, key)
						next.ServeHTTP(w, r.WithContext(ctx))
						return
					}
				}
				s.limiter.fail(lk)
				s.loginFailed(r, s.clientIP(r))
				s.log.Warn("invalid api key", "ip", s.clientIP(r), "path", r.URL.Path) // hoechstens ~5 + 2/min je IP
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, `{"error":"invalid api key"}`, http.StatusUnauthorized)
				return
			}
		}
		var sess *store.Session
		// Der Browser kann mehrere Cookies gleichen Namens schicken (z. B. ein altes von http neben dem neuen von https
		// auf demselben Host): die erste gueltige Sitzung zaehlt, sonst endete jede Anmeldung wieder auf /login.
		tried := 0 // hoechstens 3 Werte pruefen (sonst eine Datenbankabfrage je mitgeschicktem Cookie)
		for _, c := range r.Cookies() {
			if c.Name != cookieName(r, sessionCookie) || c.Value == "" {
				continue
			}
			if tried++; tried > 3 {
				break
			}
			x, _ := s.Store.SessionByID(ctx, c.Value)
			if x != nil && time.Since(x.CreatedAt) > sessionMax {
				_ = s.Store.DeleteSession(ctx, x.ID)
				x = nil
			}
			if x != nil {
				sess = x
				break
			}
		}
		if sess != nil {
			u, err := s.Store.UserByID(ctx, sess.UserID)
			if err != nil || u == nil {
				sess = nil
			} else if ok, _ := s.Store.SessionTOTPOK(ctx, sess.ID); !ok {
				// Passwort stimmt, zweiter Faktor fehlt noch
				ctx = context.WithValue(ctx, ctxPending, sess)
			} else {
				ctx = context.WithValue(ctx, ctxSession, sess)
				ctx = context.WithValue(ctx, ctxUser, u)
				if time.Since(sess.LastSeenAt) > 5*time.Minute {
					_ = s.Store.TouchSession(ctx, sess.ID, time.Now().Add(sessionIdle))
				}
			}
		}
		if sess == nil && ctx.Value(ctxPending) == nil {
			if u := s.forwardUser(r); u != nil { // Benutzer vom vorgeschalteten Proxy (auth_forward.go)
				ctx = context.WithValue(ctx, ctxUser, u)
			}
		}
		if sess == nil {
			if c, err := cookie(r, sessionCookie); err == nil && c.Value != "" {
				s.clearCookie(w, r, sessionCookie)
			}
		}

		// CSRF: Double-Submit-Cookie, bei Sitzung zusaetzlich an die Sitzung gebunden
		csrf := ""
		if sess != nil && ctx.Value(ctxPending) == nil {
			csrf = sess.CSRF
		} else if c, err := cookie(r, csrfCookie); err == nil && len(c.Value) >= 32 {
			csrf = c.Value
		}
		if csrf == "" {
			csrf = randomToken(32)
		}
		if c, err := cookie(r, csrfCookie); err != nil || c.Value != csrf {
			s.setCookie(w, r, csrfCookie, csrf, 0)
		}
		ctx = context.WithValue(ctx, ctxCSRF, csrf)
		r = r.WithContext(ctx)

		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
			if viaAPIKey(r) {
				break // API-Key-Auth braucht kein CSRF (ein anderer Authorization-Kopf, z. B. Basic vom Proxy, zaehlt nicht)
			}
			if r.URL.Path == "/mcp" && strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
				break // MCP: nur mit Schluessel im Kopf (mcp.go), keine Sitzung
			}
			if strings.HasPrefix(r.URL.Path, "/api/push/") {
				break // Push-URL: oeffentlich, der Token in der URL ist die Berechtigung (keine Sitzung)
			}
			if strings.HasPrefix(r.URL.Path, "/status/") {
				break // Passwortformular der oeffentlichen Statusseite (keine Sitzung, eigene Drosselung)
			}
			if strings.HasPrefix(r.URL.Path, "/peer/") {
				break // Cluster: signierte Anfragen der anderen Nodes bzw. Kopplungscode (peer-Paket, alle Versionen)
			}
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" && bodyLimitFor(r.URL.Path) > maxBody {
				// Uploads (bis 1 GB): Formular erst lesen, wenn angemeldet, und nur als multipart (Datei auf Platte statt
				// alles im Speicher); sonst muss der Token im Kopf stehen
				if currentUser(r) != nil && strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
					longTransfer(w)
					tok = r.PostFormValue("_csrf")
				}
			} else if tok == "" {
				tok = r.PostFormValue("_csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(csrf)) != 1 {
				s.log.Warn("csrf check failed", "path", r.URL.Path, "ip", s.clientIP(r))
				s.errorPage(w, r, http.StatusForbidden, "errors.csrf")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// auth verlangt eine Sitzung; sonst Weiterleitung zu Login oder Setup.
func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if currentUser(r) == nil {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json")
				http.Error(w, `{"error":"authentication required"}`, http.StatusUnauthorized)
				return
			}
			if pendingSession(r) != nil {
				http.Redirect(w, r, "/login/totp?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			if n, _ := s.Store.UserCount(r.Context()); n == 0 {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		h(w, r)
	})
}

func pendingSession(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxPending).(*store.Session)
	return s
}

func viaAPIKey(r *http.Request) bool { return r.Context().Value(ctxAPIKey) != nil }

func currentUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func currentSession(r *http.Request) *store.Session {
	s, _ := r.Context().Value(ctxSession).(*store.Session)
	return s
}

// sessionID der aktuellen Sitzung; leer ohne Sitzung (Forward-Auth), dann enden beim Abmelden anderer Sitzungen alle.
func sessionID(r *http.Request) string {
	if s := currentSession(r); s != nil {
		return s.ID
	}
	return ""
}

func csrfToken(r *http.Request) string {
	t, _ := r.Context().Value(ctxCSRF).(string)
	return t
}

// cookieName: eigener Name fuer unverschluesselte Aufrufe. Ein Browser darf ein sicheres Cookie (von https) nicht von
// http aus ueberschreiben – mit gleichem Namen endete eine Anmeldung per http dann immer wieder auf /login.
// Betrifft nur Sitzung und CSRF; Sprache, Darstellung, Hinweise u. ae. behalten ihren Namen.
func cookieName(r *http.Request, name string) string {
	if r.TLS == nil && (name == sessionCookie || name == csrfCookie) {
		return name + "_h"
	}
	return name
}

// cookie liest das Cookie unter dem Namen fuer diese Verbindung (http/https).
func cookie(r *http.Request, name string) (*http.Cookie, error) { return r.Cookie(cookieName(r, name)) }

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	name = cookieName(r, name)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true, Secure: r.TLS != nil,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{Name: cookieName(r, name), Value: "", Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}

// clientIP liefert die Adresse des Aufrufers; X-Forwarded-For nur, wenn
// NODE64_TRUST_PROXY gesetzt ist und die Verbindung von einem Proxy im eigenen Netz kommt.
func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.Cfg.TrustProxyHeaders && localAddr(host) {
		if ip := forwardedFor(r.Header.Values("X-Forwarded-For")); ip != "" {
			return ip
		}
	}
	return host
}

// localAddr: Loopback oder privates Netz (dort steht der eigene Reverse Proxy).
func localAddr(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

// forwardedFor nimmt aus X-Forwarded-For die rechte Adresse: die haengt der eigene Proxy an; alles links davon
// kann der Client selbst geschickt haben.
func forwardedFor(values []string) string {
	if len(values) == 0 {
		return ""
	}
	list := strings.Split(values[len(values)-1], ",")
	last := strings.TrimSpace(list[len(list)-1])
	if net.ParseIP(last) == nil {
		return ""
	}
	return last
}

// longTransfer verlaengert die Zeitlimits der Verbindung fuer Backup-Download und Wiederherstellung (sonst brechen
// grosse Dateien nach ReadTimeout/WriteTimeout des Servers ab).
func longTransfer(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	until := time.Now().Add(transferTimeout)
	_ = rc.SetReadDeadline(until)
	_ = rc.SetWriteDeadline(until)
}

// startSession legt nach erfolgreichem Login eine neue Sitzung an. Mit
// totpPending wartet sie noch auf den zweiten Faktor.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, userID int64, totpPending bool) error {
	now := time.Now()
	sess := &store.Session{
		ID: randomToken(32), UserID: userID, CSRF: randomToken(32),
		CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(sessionIdle),
		IP: s.clientIP(r), UserAgent: truncate(r.UserAgent(), 200),
	}
	if err := s.Store.CreateSession(r.Context(), sess); err != nil {
		return err
	}
	if totpPending {
		if err := s.Store.SetSessionTOTP(r.Context(), sess.ID, false); err != nil {
			return err
		}
	}
	s.setCookie(w, r, sessionCookie, sess.ID, int(sessionMax.Seconds()))
	s.setCookie(w, r, csrfCookie, sess.CSRF, 0)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
