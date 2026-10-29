package web

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/store"
)

// API-Log (Opt-in, Einstellungen > Logging): jede Anfrage an /api/ als eine Zeile im Log (Logs-Seite und
// Container-Ausgabe), unabhaengig vom Log-Level. Nur Methode, Pfad, Status, Dauer, Groesse und Herkunft; keine
// Inhalte, Geheimnisse in der Query und Check-Tokens im Pfad werden maskiert. Aus kostet es nur einen atomaren Vergleich je Anfrage.

const (
	settingAPILog = "web.api_log" // off, keys (nur per API-Key), all (auch die Oberflaeche)

	apiLogOff  = 0
	apiLogKeys = 1
	apiLogAll  = 2
)

var apiLogModes = []string{"off", "keys", "all"}

func apiLogMode(s string) (int32, bool) {
	for i, m := range apiLogModes {
		if m == s {
			return int32(i), true
		}
	}
	return apiLogOff, false
}

// loadAPILog liest den Schalter beim Start.
func (s *Server) loadAPILog(ctx context.Context) {
	m, _ := apiLogMode(s.Store.SettingOr(ctx, settingAPILog, "off"))
	s.apiLogOn.Store(m)
}

// APILogMode: aktueller Schalter (off, keys, all).
func (s *Server) APILogMode() string { return apiLogModes[s.apiLogOn.Load()] }

// setAPILog speichert den Schalter und schaltet sofort um.
func (s *Server) setAPILog(ctx context.Context, mode string) error {
	m, ok := apiLogMode(mode)
	if !ok {
		return errors.New("api_log must be off, keys or all")
	}
	if err := s.Store.SetSetting(ctx, settingAPILog, mode); err != nil {
		return err
	}
	s.apiLogOn.Store(m)
	return nil
}

// apiLog liegt hinter session (Benutzer und API-Key sind bekannt).
func (s *Server) apiLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mode := s.apiLogOn.Load()
		if mode == apiLogOff || !strings.HasPrefix(r.URL.Path, "/api/") || (mode == apiLogKeys && !viaAPIKey(r)) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &apiLogWriter{ResponseWriter: w}
		defer func() {
			status := rec.status
			if status == 0 {
				status = http.StatusOK
			}
			attrs := []slog.Attr{slog.String("module", "api"), slog.String("method", r.Method), slog.String("path", apiLogPath(r.URL.Path))}
			if q := apiLogQuery(r.URL.Query()); q != "" {
				attrs = append(attrs, slog.String("query", q))
			}
			attrs = append(attrs, slog.Int("status", status), slog.Int64("ms", time.Since(start).Milliseconds()), slog.Int64("bytes", rec.bytes),
				slog.String("ip", s.clientIP(r)))
			if k, _ := r.Context().Value(ctxAPIKey).(*store.APIKey); k != nil {
				attrs = append(attrs, slog.String("key_name", k.Name))
			}
			if u := currentUser(r); u != nil {
				attrs = append(attrs, slog.String("user", u.Username))
			}
			s.Log.Record(r.Context(), "api request", attrs...)
		}()
		next.ServeHTTP(rec, r)
	})
}

// apiLogPath: Pfad fuer das Log, Check-Tokens gekuerzt (/api/push/{token}, /api/checks/{token} ...: der Token ist
// zugleich die Push-Berechtigung). Gekuerzt wird jedes lange Segment aus Buchstaben/Ziffern, wie checks.TokenHint.
func apiLogPath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		if len(s) >= 20 && strings.IndexFunc(s, func(r rune) bool {
			return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
		}) < 0 {
			parts[i] = checks.TokenHint(s)
		}
	}
	return strings.Join(parts, "/")
}

// apiLogQuery: Query fuer das Log, Werte geheimer Parameter (token, key, secret ...) maskiert.
func apiLogQuery(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	out := url.Values{}
	for k, vs := range q {
		for _, v := range vs {
			if logging.IsSecretKey(k) {
				v = logging.Masked
			}
			out.Add(k, v)
		}
	}
	return out.Encode()
}

// apiLogWriter merkt Status und Groesse der Antwort (Flush und Hijack bleiben ueber Unwrap erreichbar).
type apiLogWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *apiLogWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *apiLogWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *apiLogWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *apiLogWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("hijack not supported")
}

func (w *apiLogWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// settingsAPILog: Schalter aus der Karte Logging.
func (s *Server) settingsAPILog(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("api_log")
	if err := s.setAPILog(r.Context(), mode); err != nil {
		s.flash(w, r, "danger", s.tr(r, "errors.validation"))
		http.Redirect(w, r, "/settings#logging", http.StatusSeeOther)
		return
	}
	s.audit(r, "logging.api", mode, "")
	s.flash(w, r, "success", s.tr(r, "settings.log_changed"))
	http.Redirect(w, r, "/settings#logging", http.StatusSeeOther)
}
