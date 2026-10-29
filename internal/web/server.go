// Package web ist die lokale Oberflaeche und API des Nodes.
//
// Go html/template, Bootstrap 5.3 und wenig Vanilla-JS, alles eingebettet.
// Sitzungen liegen in der Datenbank, Formulare sind CSRF-geschuetzt, der
// Login ist ratenbegrenzt, Antworten tragen Security-Header.
package web

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/certsui"
	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/mcp"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/usercluster"
)

// Deps sind die Abhaengigkeiten der Oberflaeche.
type Deps struct {
	Cfg        *config.Config
	Store      *store.Store
	Log        *logging.Logger
	I18n       *i18n.Bundle
	Modules    *module.Registry
	Notify     *notify.Store
	Dispatcher *notify.Dispatcher
	Sync       nodesync.Client
	Linker     nodesync.Linker      // nil = Verknuepfung nicht verfuegbar
	HC         *healthchecks.Module // fuer Konflikte auf der Verknuepfungsseite
	IPv64      *ipv64api.Key        // zentraler ipv64-API-Key (nil = nicht verfuegbar)
	Peer       *peer.Manager        // lokale Gruppe (nil = nicht verfuegbar)
	Ports      *ports.Registry      // belegte Ports (nil = keine Uebersicht)
	Edge       *edge.Edge           // gemeinsamer Eingang 80/443 (nil = nicht verfuegbar)
	Certs      *certs.Manager       // Zertifikatsverwaltung (nil = nicht verfuegbar)
	Box        *secrets.Box         // Verschluesselung von Geheimnissen (z. B. OIDC-Client-Secret)
	Updater    *selfupdate.Updater  // Selbst-Update (nil = nicht verfuegbar)
	Users      *usercluster.Cluster // Benutzer & Anmeldung im Cluster (nil = ohne; Wahl bei gleichnamigen Benutzern)
	Version    string
	StartedAt  time.Time
	// Restart beendet den Node kontrolliert (Docker startet ihn neu), z. B.
	// nach einer Wiederherstellung der Datenbank.
	Restart func()
}

type Server struct {
	Deps
	log     *slog.Logger
	mux     *http.ServeMux
	handler http.Handler
	pages   map[string]*template.Template
	certsUI *certsui.UI // Seite „Zertifikate“ (nil ohne Verwaltung)

	uiCertSel    atomic.Int64     // Zertifikat der Oberflaeche: -1 selbst signiert, 0 automatisch, sonst Kennung
	fallbackCert *tls.Certificate // NODE64_TLS_CERT bzw. selbst signiert
	limiter      *loginLimiter
	ipLimit      *ipLimiter
	fwd          fwdCache // Forward-Auth: Einrichtung und letzte Audit-Eintraege (auth_forward.go)

	mcpHandler http.Handler // MCP-Schnittstelle /mcp (mcp.go)
	mcpCounter *mcp.Counter
	mcpLimit   *ipLimiter // Rate-Limit je MCP-Schluessel

	loginWatch atomic.Pointer[LoginWatcher] // Fehlversuche an Honeypot64 (login_watch.go), nil = keiner
	apiLogOn   atomic.Int32                 // API-Log: apiLogOff, apiLogKeys, apiLogAll (api_log.go)

	mu      sync.Mutex
	servers []*http.Server
}

const maxBody = 1 << 20 // 1 MB fuer Formulare und JSON

// New baut Router und Templates.
func New(d Deps) (*Server, error) {
	s := &Server{Deps: d, log: d.Log.Slog().With("module", "web"), mux: http.NewServeMux(), limiter: newLoginLimiter(), ipLimit: newIPLimiter(300, 600)}
	if d.Certs != nil {
		s.certsUI = certsui.New(d.Certs)
		d.Certs.SetUsers("web", s.uiCertUsers)
	}
	s.loadUICert(context.Background())
	s.loadAPILog(context.Background())
	if err := s.parseTemplates(); err != nil {
		return nil, err
	}
	s.routes()
	s.handler = s.recoverer(s.securityHeaders(s.rateLimit(s.bodyLimit(s.session(s.apiLog(s.mux))))))
	if err := s.uiRoute(context.Background()); err != nil { // Oberflaeche unter eigenem Namen (Eingang)
		s.log.Warn("web interface not registered at the edge", "err", err)
	}
	return s, nil
}

// Handler liefert den fertigen HTTP-Handler (auch fuer Tests).
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) parseTemplates() error {
	funcs := template.FuncMap{
		"add":      func(a, b int) int { return a + b },
		"sub":      func(a, b int) int { return a - b },
		"pct":      func(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) },
		"ms":       func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
		"join":     strings.Join,
		"split":    strings.Fields,
		"contains": strings.Contains,
		"darkimg":  darkImage,
		"seq": func(n int) []int {
			out := make([]int, n)
			for i := range out {
				out[i] = i
			}
			return out
		},
	}
	pages, err := fs.Glob(templateFS, "templates/pages/*.html")
	if err != nil {
		return err
	}
	s.pages = map[string]*template.Template{}
	for _, p := range pages {
		name := p[len("templates/pages/") : len(p)-len(".html")]
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials/*.html", p)
		if err != nil {
			return fmt.Errorf("template %s: %w", name, err)
		}
		s.pages[name] = t
	}
	// Seiten der Module: "<modul>/<name>" mit demselben Layout; die Zertifikatsseite des Kerns ebenso ("certs/<name>")
	type named struct {
		name string
		tp   module.Templater
	}
	var parts []named
	for _, m := range s.Modules.Modules() {
		if tp, ok := m.(module.Templater); ok {
			parts = append(parts, named{m.Info().Name, tp})
		}
	}
	if s.certsUI != nil {
		parts = append(parts, named{certsui.Name, s.certsUI})
	}
	for _, part := range parts {
		mfs := part.tp.Templates()
		mpages, err := fs.Glob(mfs, "pages/*.html")
		if err != nil {
			return err
		}
		for _, p := range mpages {
			name := part.name + "/" + p[len("pages/"):len(p)-len(".html")]
			t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials/*.html")
			if err != nil {
				return err
			}
			if _, err := t.ParseFS(mfs, p); err != nil {
				return fmt.Errorf("module template %s: %w", name, err)
			}
			s.pages[name] = t
		}
	}
	return nil
}

func (s *Server) routes() {
	static, _ := fs.Sub(staticFS, "static")
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", cacheControl(http.FileServerFS(static))))
	s.mux.HandleFunc("GET /api/health", s.apiHealth)

	s.mux.HandleFunc("GET /setup", s.setupForm)
	s.mux.HandleFunc("POST /setup", s.setupSubmit)
	s.mux.HandleFunc("GET /login", s.loginForm)
	s.mux.HandleFunc("POST /login", s.loginSubmit)
	s.mux.HandleFunc("POST /logout", s.logout)
	s.authRoutes()
	s.backupRoutes()
	s.apiRoutes()
	s.apiLinkRoutes()
	s.apiAdminRoutes()
	s.syncRoutes()
	s.peerRoutes()
	s.portRoutes()
	s.settingsPageRoutes() // Einstellungen › Ports und › Daten & Sicherung
	s.certRoutes()
	s.mcpRoutes()

	s.mux.Handle("GET /{$}", s.auth(s.dashboard))
	s.mux.Handle("GET /settings", s.auth(s.settings))
	s.mux.Handle("POST /settings/node", s.auth(s.settingsNode))
	s.mux.Handle("POST /settings/user", s.auth(s.settingsUser))
	s.mux.Handle("POST /settings/password", s.auth(s.settingsPassword))
	s.mux.Handle("POST /settings/modules", s.auth(s.settingsModules))
	s.mux.Handle("POST /settings/logging", s.auth(s.settingsLogging))
	s.mux.Handle("POST /settings/api-log", s.auth(s.settingsAPILog))
	s.mux.Handle("POST /settings/data", s.auth(s.settingsData))
	s.mux.Handle("POST /settings/updates", s.auth(s.settingsUpdates))
	s.updateRoutes()
	s.ipv64Routes()
	if s.Notify != nil {
		s.notifyRoutes()
	}
	s.mux.Handle("GET /audit", s.auth(s.auditLog))
	s.mux.Handle("GET /logs", s.auth(s.logs))
	s.mux.Handle("GET /logs/download", s.auth(s.logsDownload))

	// Module registrieren ihre Pfade selbst; deaktiviert = 404
	guards := module.Guards{
		Auth: s.authHandler, Render: s.renderModule, T: s.tr, Flash: s.flash, Actor: s.actor, ClientIP: s.clientIP, Audit: s.audit, CSRF: csrfToken, Lang: s.lang, Timezone: s.location,
		Translate: s.I18n.T,
	}
	s.Modules.Routes(s.mux, http.HandlerFunc(s.notFound), guards)
	if s.certsUI != nil { // Kern: immer da, unabhaengig von den Modulen
		s.certsUI.Routes(s.mux, guards)
	}
	s.mux.HandleFunc("/", s.notFound)
}

// authHandler ist auth fuer beliebige Handler (Module).
func (s *Server) authHandler(next http.Handler) http.Handler { return s.auth(next.ServeHTTP) }

func cacheControl(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800")
		next.ServeHTTP(w, r)
	})
}

// Run startet HTTP und optional HTTPS und blockiert bis ctx endet.
func (s *Server) Run(ctx context.Context) error {
	errc := make(chan error, 2)
	newServer := func(port int, tlsCfg *tls.Config) (*http.Server, net.Listener, error) {
		addr := net.JoinHostPort(s.Cfg.BindAddr, strconv.Itoa(port))
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return nil, nil, fmt.Errorf("listen %s: %w", addr, err)
		}
		srv := &http.Server{
			Handler:           s.handler,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		}
		return srv, ln, nil
	}

	// Zertifikat der Oberflaeche: gewaehltes aus der Verwaltung, sonst passendes nach Namen, sonst selbst signiert
	cert, err := loadOrCreateCertificate(s.Cfg, s.log)
	if err != nil {
		return err
	}
	s.fallbackCert = &cert
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.uiCertificate}
	if s.Cfg.HTTPPort > 0 {
		srv, ln, err := newServer(s.Cfg.HTTPPort, nil)
		if err != nil {
			return err
		}
		s.track(srv)
		// HTTP und HTTPS auf demselben Port (dualport.go): https://<node>:<port> geht ohne eigenen HTTPS-Port
		dl := newDualListener(ln, &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: s.uiCertificate, NextProtos: []string{"http/1.1"}})
		s.log.Info("http listening", "addr", ln.Addr().String(), "https", "same port")
		go func() { errc <- srv.Serve(dl) }()
	}
	if s.Cfg.HTTPSPort > 0 {
		srv, ln, err := newServer(s.Cfg.HTTPSPort, tlsCfg)
		if err != nil {
			return err
		}
		s.track(srv)
		s.log.Info("https listening", "addr", ln.Addr().String())
		go func() { errc <- srv.ServeTLS(ln, "", "") }()
	}

	// Abgelaufene Sitzungen regelmaessig entfernen
	go s.housekeeping(ctx)

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.shutdown()
			return err
		}
	}
	s.shutdown()
	return nil
}

func (s *Server) track(srv *http.Server) {
	s.mu.Lock()
	s.servers = append(s.servers, srv)
	s.mu.Unlock()
}

func (s *Server) shutdown() {
	s.mu.Lock()
	servers := s.servers
	s.servers = nil
	s.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(ctx)
	}
}

func (s *Server) housekeeping(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.Store.PurgeSessions(ctx); err == nil && n > 0 {
				s.log.Debug("expired sessions removed", "count", n)
			}
			s.limiter.cleanup()
			s.ipLimit.cleanup()
			s.mcpLimit.cleanup()
			if s.Notify != nil {
				_ = s.Notify.PruneDeliveries(ctx, 90*24*time.Hour)
			}
			if n, err := s.Store.PruneAudit(ctx, auditKeep(s.Store)); err == nil && n > 0 { // Audit-Log (audit.keep_days)
				s.log.Debug("old audit entries removed", "count", n)
			}
		}
	}
}
