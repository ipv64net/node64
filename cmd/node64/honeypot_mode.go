package main

// Modus ohne Oberflaeche (NODE64_MODE=honeypot, Plan docs/PLAN-NODE64-HONEYPOT64.md Abschnitt 2): nur die
// Fallen-Dienste von Honeypot64, keine Weboberflaeche, keine anderen Module, kein Anmelden. Einstellungen nur aus der
// Umgebung; Zustand ueber Log, Info-Seite, /metrics und /health auf einem eigenen Port (getrennt von den Fallen).
// Anleitung: docs/HONEYPOT64.md.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/caps"
	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/metrics"
	"github.com/ipv64net/node64/internal/store"
)

// Standardwerte des Modus ohne Oberflaeche.
const (
	hpDefaultProfile  = "standard"
	hpDefaultInfoPort = 9064
	hpMinTokenLen     = 16
	hpStatsCache      = 10 * time.Second // Info-Seite und /metrics fragen die Datenbank hoechstens so oft
)

// hpModeConfig ist die Einstellung des Modus ohne Oberflaeche (nur aus der Umgebung).
type hpModeConfig struct {
	Profile   string          // minimal, standard, full ("" bei eigener Dienste-Liste nicht leer, nur Anzeige)
	Custom    bool            // Dienste aus NODE64_HONEYPOT_SERVICES statt aus dem Profil
	Sensor    honeypot.Config // Dienste und Port-Scan-Erkennung
	Retention time.Duration   // lokale Aufbewahrung
	InfoPort  int             // 0 = keine Info-Seite
	InfoToken string          // leer = Info-Seite nur aus privaten Netzen
	IPv64Key  string          // fuer die Meldung an ipv64 (H2)
	Report    bool            // Meldung an ipv64: an, wenn ein Key gesetzt ist und NODE64_HONEYPOT_REPORT nicht 0 ist
	APIBase   string          // NODE64_IPV64_API (leer = ipv64.net; nur fuer Tests)
}

// runMode startet einen besonderen Betriebsmodus (NODE64_MODE). Bisher gibt es nur "honeypot".
func runMode(cfg *config.Config, mode string) error {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "honeypot":
		return runHoneypotMode(cfg)
	}
	return fmt.Errorf("NODE64_MODE %q is unknown (leave it empty or use honeypot)", mode)
}

// isHoneypotMode: NODE64_MODE=honeypot (auch fuer den Healthcheck).
func isHoneypotMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("NODE64_MODE")), "honeypot")
}

// runHoneypotMode ist der Einstieg aus run(): Logger, Rechte, Signale, dann honeypotRun.
func runHoneypotMode(cfg *config.Config) error {
	hc, err := honeypotModeFromEnv(os.Getenv)
	if err != nil {
		return err
	}
	logger := logging.New(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	defer logger.Close()
	log := logger.Slog().With("module", honeypot.Name)
	if raised, err := caps.Raise(); err != nil { // Ports unter 1024 (22, 23, 80, 443) ohne Root, siehe Dockerfile
		log.Warn("capabilities could not be raised", "err", err)
	} else if raised {
		log.Debug("capabilities raised")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return honeypotRun(ctx, cfg, hc, logger.Slog(), nil)
}

// honeypotRun laeuft bis ctx endet und raeumt dann auf (Info-Server, Sensor, Rest in die Datenbank).
// ready (optional) bekommt die Adresse des Info-Servers ("" = aus), sobald alles offen ist.
func honeypotRun(ctx context.Context, cfg *config.Config, hc *hpModeConfig, base *slog.Logger, ready func(info string)) error {
	log := base.With("module", honeypot.Name)
	source := "profile " + hc.Profile
	if hc.Custom {
		source = "NODE64_HONEYPOT_SERVICES"
	}
	log.Info("node64 starting in honeypot mode (no web interface)", "version", Version, "data", cfg.DataDir, "services", source,
		"scan", hc.Sensor.Scan, "retention", hc.Retention.String())
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir %s: %w", cfg.DataDir, err)
	}
	ensureTempDir(cfg, log)
	dir := filepath.Join(cfg.DataDir, honeypot.Name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("honeypot dir %s: %w", dir, err)
	}

	st, err := store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), base)
	if err != nil {
		return err
	}
	defer st.Close()
	core, err := store.CoreMigrations() // Einstellungen usw.: dieselbe Datenbank kann spaeter als normale Node laufen
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "core", core); err != nil {
		return err
	}
	if err := st.Migrate(ctx, honeypot.Name, honeypot.Migrations()); err != nil {
		return err
	}
	hpStore := honeypot.NewStore(st, base)
	hpStore.SetLimits(hc.Retention, 0)
	storeCtx, storeStop := context.WithCancel(context.Background()) // erst nach dem Sensor beenden (Rest schreiben)
	storeDone := make(chan struct{})
	go func() { hpStore.Run(storeCtx); close(storeDone) }()
	defer func() {
		storeStop()
		select {
		case <-storeDone:
		case <-time.After(15 * time.Second):
			log.Warn("honeypot: store did not finish in time")
		}
	}()

	api := ipv64api.NewClient(hc.APIBase, "node64/"+Version)
	rep := honeypot.NewReporter(honeypot.ReporterConfig{Store: hpStore, Mode: "headless", Version: Version, Log: log,
		API: func(context.Context) (*ipv64api.Client, string) {
			if !hc.Report {
				return nil, ""
			}
			return api, hc.IPv64Key
		},
		Enabled:  func(context.Context) bool { return hc.Report },
		Profile:  func(context.Context) string { return hpProfileLabel(hc) },
		SensorID: func(context.Context) (string, error) { return honeypot.SensorIDFromFile(dir) },
		State:    honeypot.FileReportState(dir)})
	repCtx, repStop := context.WithCancel(ctx)
	repDone := make(chan struct{})
	defer func() { repStop(); <-repDone }() // vor dem Speicher beenden
	repState := honeypot.FileReportState(dir)
	switch {
	case hc.Report:
		id, err := honeypot.SensorIDFromFile(dir)
		if err != nil {
			close(repDone)
			return fmt.Errorf("honeypot sensor id: %w", err)
		}
		if rs, err := repState.Load(ctx); err != nil || rs.LastEnd.IsZero() { // erste Meldung: ab jetzt
			_ = rep.ResetWindow(ctx)
		}
		log.Info("reporting to ipv64 every 10 minutes", "sensor_id", id)
		go func() { rep.Run(repCtx); close(repDone) }()
	case hc.IPv64Key != "":
		log.Info("NODE64_HONEYPOT_REPORT=0; events stay local")
		close(repDone)
	default:
		log.Info("NODE64_IPV64_KEY is not set; events stay local")
		close(repDone)
	}
	if !hc.Report { // spaeter wieder eingeschaltet: nichts aus der Zeit ohne Meldung nachholen
		if rs, err := repState.Load(ctx); err == nil && !rs.LastEnd.IsZero() {
			rs.LastEnd = time.Time{}
			_ = repState.Save(ctx, rs)
		}
	}

	sink := honeypot.CountEvents(hpStore.Sink()) // Zaehler fuer /metrics
	sensor := honeypot.NewSensor(base, dir)
	trap := hc.Sensor
	trap.Log = honeypot.LogConfig{} // Log-Sensor laeuft getrennt (unten)
	status := sensor.Apply(ctx, trap, sink)
	logServiceStatus(log, hc.Sensor.Services, status)
	defer sensor.Stop() // laeuft vor dem Beenden des Speichers (defer in umgekehrter Reihenfolge)
	logs := honeypot.NewLogSensor(base)
	logLogStatus(log, hc.Sensor.Log, logs.Apply(ctx, hc.Sensor.Log, sink)) // leer = aus, oeffnet nichts
	defer logs.Stop()

	info := ""
	var srv *http.Server
	if hc.InfoPort > 0 {
		ln, err := net.Listen("tcp", net.JoinHostPort(cfg.BindAddr, strconv.Itoa(hc.InfoPort)))
		if err != nil {
			return fmt.Errorf("honeypot info port %d: %w", hc.InfoPort, err)
		}
		h := newHPInfo(hc, sensor, hpStore, st, rep, Version)
		h.logs = logs
		srv = &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 60 * time.Second, MaxHeaderBytes: 8 << 10, ErrorLog: slog.NewLogLogger(base.Handler(), slog.LevelDebug)}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("honeypot info server stopped", "err", err)
			}
		}()
		info = ln.Addr().String()
		access := "private networks only"
		if hc.InfoToken != "" {
			access = "private networks, elsewhere with token"
		}
		log.Info("honeypot info page listening", "addr", info, "paths", "/ /metrics /health", "access", access)
	} else {
		log.Info("honeypot info page off (NODE64_HONEYPOT_INFO_PORT=0)")
	}
	if ready != nil {
		ready(info)
	}

	<-ctx.Done()
	log.Info("honeypot mode stopping")
	if srv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(sctx)
		cancel()
	}
	return nil
}

// logServiceStatus fasst beim Start zusammen, welche Dienste offen sind und welche nicht (mit Grund). Jeden
// einzelnen Dienst meldet der Sensor beim Oeffnen schon selbst.
func logServiceStatus(log *slog.Logger, want []honeypot.Service, status []honeypot.ServiceStatus) {
	var open, closed []string
	for _, w := range want {
		name := w.Service + ":" + strconv.Itoa(w.Port)
		i := slices.IndexFunc(status, func(s honeypot.ServiceStatus) bool { return s.Port == w.Port })
		switch {
		case i < 0:
			closed = append(closed, name+" (no status from sensor)")
		case status[i].Listen:
			open = append(open, name)
		default:
			reason := status[i].Error
			if reason == "" {
				reason = "unknown"
			}
			closed = append(closed, name+" ("+reason+")")
		}
	}
	if len(open) == 0 {
		log.Error("honeypot: no service is open", "not_open", strings.Join(closed, ", "))
		return
	}
	if len(closed) > 0 {
		log.Warn("honeypot services ready, some not open", "open", strings.Join(open, ", "), "not_open", strings.Join(closed, ", "))
		return
	}
	log.Info("honeypot services ready", "open", strings.Join(open, ", "))
}

// logLogStatus fasst beim Start den Log-Sensor und den Syslog-Empfaenger zusammen (nichts eingestellt = eine Zeile).
func logLogStatus(log *slog.Logger, cfg honeypot.LogConfig, st honeypot.LogStatus) {
	if len(cfg.Files) == 0 && cfg.SyslogPort == 0 {
		log.Info("log sensor and syslog receiver off (NODE64_HONEYPOT_LOGS, NODE64_HONEYPOT_SYSLOG_PORT)")
		return
	}
	var ok, bad []string
	for _, f := range st.Files {
		if f.OK {
			ok = append(ok, f.Path)
		} else {
			bad = append(bad, f.Path+" ("+f.Error+")")
		}
	}
	switch {
	case len(bad) > 0:
		log.Warn("log sensor: some files not readable (mount -v /var/log:/host/log:ro, --group-add 4 for auth.log)",
			"ok", strings.Join(ok, ", "), "not_ok", strings.Join(bad, ", "))
	case len(cfg.Files) > 0:
		log.Info("log sensor reading", "files", strings.Join(ok, ", "))
	}
	if sl := st.Syslog; cfg.SyslogPort > 0 && sl != nil {
		if sl.Error != "" {
			log.Error("syslog receiver not open", "port", cfg.SyslogPort, "err", sl.Error)
		} else {
			log.Info("syslog receiver listening", "port", sl.Port, "udp", sl.UDP, "tcp", sl.TCP, "allow", strings.Join(cfg.SyslogAllow, ","))
		}
	}
}

// honeypotModeFromEnv liest die Einstellung aus der Umgebung (getenv: os.Getenv, in Tests eine Tabelle).
func honeypotModeFromEnv(getenv func(string) string) (*hpModeConfig, error) {
	get := func(k string) string { return strings.TrimSpace(getenv(k)) }
	hc := &hpModeConfig{Profile: strings.ToLower(get("NODE64_HONEYPOT_PROFILE")), InfoToken: get("NODE64_HONEYPOT_INFO_TOKEN"), IPv64Key: get("NODE64_IPV64_KEY")}
	if hc.Profile == "" {
		hc.Profile = hpDefaultProfile
	}
	prof, ok := honeypot.Profiles[hc.Profile]
	if !ok {
		return nil, fmt.Errorf("NODE64_HONEYPOT_PROFILE %q is not one of minimal, standard, full", hc.Profile)
	}
	if v := get("NODE64_HONEYPOT_SERVICES"); v != "" {
		svcs, err := parseHPServices(v)
		if err != nil {
			return nil, err
		}
		hc.Sensor.Services, hc.Custom = svcs, true
	} else {
		hc.Sensor.Services = slices.Clone(prof)
	}
	switch strings.ToLower(get("NODE64_HONEYPOT_SCAN")) {
	case "", "1", "true", "yes", "on":
		hc.Sensor.Scan = true
	case "0", "false", "no", "off":
	default:
		return nil, fmt.Errorf("NODE64_HONEYPOT_SCAN %q is not 1 or 0", get("NODE64_HONEYPOT_SCAN"))
	}
	var err error
	if hc.Retention, err = parseHPRetention(get("NODE64_HONEYPOT_RETENTION")); err != nil {
		return nil, err
	}
	hc.InfoPort = hpDefaultInfoPort
	if v := get("NODE64_HONEYPOT_INFO_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("NODE64_HONEYPOT_INFO_PORT must be a port number between 0 and 65535, got %q", v)
		}
		hc.InfoPort = n
	}
	if hc.InfoPort > 0 && slices.ContainsFunc(hc.Sensor.Services, func(s honeypot.Service) bool { return s.Port == hc.InfoPort }) {
		return nil, fmt.Errorf("NODE64_HONEYPOT_INFO_PORT %d is also a honeypot port", hc.InfoPort)
	}
	if hc.InfoToken != "" && len(hc.InfoToken) < hpMinTokenLen {
		return nil, fmt.Errorf("NODE64_HONEYPOT_INFO_TOKEN must have at least %d characters", hpMinTokenLen)
	}
	hc.APIBase = get("NODE64_IPV64_API")
	switch strings.ToLower(get("NODE64_HONEYPOT_REPORT")) {
	case "", "1", "true", "yes", "on":
		hc.Report = hc.IPv64Key != ""
	case "0", "false", "no", "off":
	default:
		return nil, fmt.Errorf("NODE64_HONEYPOT_REPORT %q is not 1 or 0", get("NODE64_HONEYPOT_REPORT"))
	}
	if hc.Report && !ipv64api.KeyRe.MatchString(hc.IPv64Key) {
		return nil, errors.New("NODE64_IPV64_KEY is not a valid ipv64 API key (16 to 64 letters and digits)")
	}
	if err := parseHPLogs(get, hc); err != nil {
		return nil, err
	}
	return hc, nil
}

// parseHPLogs liest Log-Sensor und Syslog-Empfaenger (H5): NODE64_HONEYPOT_LOGS ("pfad[=format],…"),
// NODE64_HONEYPOT_SYSLOG_PORT (leer/0 = aus), NODE64_HONEYPOT_SYSLOG_ALLOW (CIDR-Liste, leer = private Netze).
// Kein Profil schaltet den Log-Sensor ein: ohne Mount gaebe es nur Fehler.
func parseHPLogs(get func(string) string, hc *hpModeConfig) error {
	lc := &hc.Sensor.Log
	for _, item := range strings.Split(get("NODE64_HONEYPOT_LOGS"), ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		f := honeypot.LogFile{Path: item}
		if i := strings.LastIndexByte(item, '='); i >= 0 {
			f.Path, f.Format = strings.TrimSpace(item[:i]), strings.TrimSpace(item[i+1:])
		}
		lc.Files = append(lc.Files, f)
	}
	if v := get("NODE64_HONEYPOT_SYSLOG_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 65535 {
			return fmt.Errorf("NODE64_HONEYPOT_SYSLOG_PORT must be 0 (off) or a port number up to 65535, got %q", v)
		}
		lc.SyslogPort = n
	}
	lc.SyslogAllow = strings.FieldsFunc(get("NODE64_HONEYPOT_SYSLOG_ALLOW"), func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
	if err := honeypot.ValidateLogConfig(lc); err != nil {
		return fmt.Errorf("NODE64_HONEYPOT_LOGS / NODE64_HONEYPOT_SYSLOG_*: %w", err)
	}
	if p := lc.SyslogPort; p > 0 {
		if slices.ContainsFunc(hc.Sensor.Services, func(s honeypot.Service) bool { return s.Port == p }) {
			return fmt.Errorf("NODE64_HONEYPOT_SYSLOG_PORT %d is also a honeypot port", p)
		}
		if p == hc.InfoPort {
			return fmt.Errorf("NODE64_HONEYPOT_SYSLOG_PORT %d is also NODE64_HONEYPOT_INFO_PORT", p)
		}
	}
	return nil
}

// parseHPServices liest "ssh:22,ssh:2222,http:80,https:443:wp-login,tcp:3389" (Dienst:Port[:Koeder]).
func parseHPServices(v string) ([]honeypot.Service, error) {
	var out []honeypot.Service
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parts := strings.Split(item, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("NODE64_HONEYPOT_SERVICES: %q is not service:port", item)
		}
		svc := strings.ToLower(strings.TrimSpace(parts[0]))
		switch svc {
		case honeypot.SvcSSH, honeypot.SvcTelnet, honeypot.SvcHTTP, honeypot.SvcHTTPS, honeypot.SvcTCP:
		default:
			if !honeypot.ProtoKnown(svc) {
				return nil, fmt.Errorf("NODE64_HONEYPOT_SERVICES: unknown service %q (ssh, telnet, http, https, tcp, ftp, smtp, pop3, imap, mqtt)", parts[0])
			}
		}
		port, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("NODE64_HONEYPOT_SERVICES: %q has no valid port", item)
		}
		s := honeypot.Service{Service: svc, Port: port}
		if len(parts) == 3 {
			s.Page = strings.ToLower(strings.TrimSpace(parts[2]))
			if (svc != honeypot.SvcHTTP && svc != honeypot.SvcHTTPS) || !slices.Contains(honeypot.Pages, s.Page) {
				return nil, fmt.Errorf("NODE64_HONEYPOT_SERVICES: %q: page only for http/https, one of %s", item, strings.Join(honeypot.Pages, ", "))
			}
		}
		if slices.ContainsFunc(out, func(o honeypot.Service) bool { return o.Port == port }) {
			return nil, fmt.Errorf("NODE64_HONEYPOT_SERVICES: port %d is used twice", port)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, errors.New("NODE64_HONEYPOT_SERVICES contains no service")
	}
	return out, nil
}

// parseHPRetention liest "7d", "36h", "90m" (leer = 7 Tage); erlaubt 1 Stunde bis 365 Tage.
func parseHPRetention(v string) (time.Duration, error) {
	if v == "" {
		return honeypot.DefaultRetention, nil
	}
	var d time.Duration
	if n, ok := strings.CutSuffix(strings.ToLower(v), "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil {
			return 0, fmt.Errorf("NODE64_HONEYPOT_RETENTION %q is not a duration like 7d or 48h", v)
		}
		d = time.Duration(days) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(v); err != nil {
			return 0, fmt.Errorf("NODE64_HONEYPOT_RETENTION %q is not a duration like 7d or 48h", v)
		}
	}
	if d < time.Hour || d > 365*24*time.Hour {
		return 0, fmt.Errorf("NODE64_HONEYPOT_RETENTION %q must be between 1h and 365d", v)
	}
	return d, nil
}

// honeypotHealthcheck ist "node64 healthcheck" im Modus ohne Oberflaeche: /health des Info-Ports, ohne Info-Port
// genuegt, dass der Befehl laeuft (der Container lebt nur mit dem Hauptprozess).
func honeypotHealthcheck(cfg *config.Config) int {
	hc, err := honeypotModeFromEnv(os.Getenv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	if hc.InfoPort == 0 {
		fmt.Println("healthy (info port off)")
		return 0
	}
	hosts := []string{"127.0.0.1", "::1"}
	if cfg.BindAddr != "" && cfg.BindAddr != "0.0.0.0" && cfg.BindAddr != "::" {
		hosts = []string{cfg.BindAddr}
	}
	client := &http.Client{Timeout: 4 * time.Second}
	var resp *http.Response
	for _, h := range hosts {
		req, _ := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort(h, strconv.Itoa(hc.InfoPort))+"/health", nil)
		if hc.InfoToken != "" {
			req.Header.Set("Authorization", "Bearer "+hc.InfoToken)
		}
		if resp, err = client.Do(req); err == nil {
			break
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", resp.StatusCode)
		return 1
	}
	fmt.Println("healthy")
	return 0
}

// ---- Info-Server: Info-Seite, /metrics, /health

// hpSensor ist der Teil des Sensors, den der Info-Server braucht (in Tests ersetzbar).
type hpSensor = honeypot.SensorState

// hpLogs ist der Teil des Log-Sensors, den der Info-Server braucht (*honeypot.LogSensor; nil = keiner).
type hpLogs interface {
	Status() honeypot.LogStatus
}

type hpInfo struct {
	hc      *hpModeConfig
	sensor  hpSensor
	logs    hpLogs
	store   *honeypot.Store
	db      *store.Store
	rep     *honeypot.Reporter
	version string
	started time.Time
	token   [32]byte // SHA-256 des Tokens (Vergleich in konstanter Zeit, auch bei anderer Laenge)

	mu      sync.Mutex
	at      time.Time
	day     *honeypot.Stats
	week    *honeypot.Stats
	statErr error
}

func newHPInfo(hc *hpModeConfig, sensor hpSensor, hpStore *honeypot.Store, db *store.Store, rep *honeypot.Reporter, version string) *hpInfo {
	h := &hpInfo{hc: hc, sensor: sensor, store: hpStore, db: db, rep: rep, version: version, started: time.Now()}
	if hc.InfoToken != "" {
		h.token = sha256.Sum256([]byte(hc.InfoToken))
	}
	return h
}

var hpCGNAT = netip.MustParsePrefix("100.64.0.0/10")

// hpLocalAddr: privat (RFC 1918, ULA fc00::/7), CGNAT, Loopback, Link-Local. Nur RemoteAddr zaehlt, keine
// Weiterleitungs-Kopfzeilen.
func hpLocalAddr(remote string) bool {
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	a := ap.Addr().Unmap()
	return a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || hpCGNAT.Contains(a)
}

// allowed: aus lokalen Netzen immer, sonst nur mit gueltigem Token (?token= oder Authorization: Bearer).
func (h *hpInfo) allowed(r *http.Request) bool {
	if hpLocalAddr(r.RemoteAddr) {
		return true
	}
	if h.hc.InfoToken == "" {
		return false
	}
	got := r.URL.Query().Get("token")
	if a := r.Header.Get("Authorization"); got == "" && len(a) > 7 && strings.EqualFold(a[:7], "bearer ") {
		got = strings.TrimSpace(a[7:])
	}
	if got == "" {
		return false
	}
	sum := sha256.Sum256([]byte(got))
	return subtle.ConstantTimeCompare(sum[:], h.token[:]) == 1
}

func (h *hpInfo) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Security-Policy", hpInfoCSP)
	hd.Set("X-Content-Type-Options", "nosniff")
	hd.Set("Referrer-Policy", "no-referrer")
	hd.Set("X-Frame-Options", "DENY")
	hd.Set("Cache-Control", "no-store")
	hd.Set("Cross-Origin-Resource-Policy", "same-origin")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		hd.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.allowed(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/":
		h.page(w, r)
	case "/metrics":
		h.metrics(w, r)
	case "/health":
		h.health(w, r)
	default:
		http.NotFound(w, r)
	}
}

// health: 200, wenn die Datenbank antwortet und (bei eingestellten Diensten) mindestens einer offen ist.
func (h *hpInfo) health(w http.ResponseWriter, r *http.Request) {
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := h.db.Reader().PingContext(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "unhealthy: database")
		return
	}
	if len(h.hc.Sensor.Services) > 0 && !slices.ContainsFunc(h.sensor.Status(), func(s honeypot.ServiceStatus) bool { return s.Listen }) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintln(w, "unhealthy: no honeypot service open")
		return
	}
	fmt.Fprintln(w, "ok")
}

// stats liefert die Auswertung fuer 24 h und 7 Tage (zwischengespeichert, siehe hpStatsCache).
func (h *hpInfo) stats(ctx context.Context) (day, week *honeypot.Stats, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.at.IsZero() && time.Since(h.at) < hpStatsCache {
		return h.day, h.week, h.statErr
	}
	now := time.Now()
	day, err = h.store.Stats(ctx, now.Add(-24*time.Hour), 10)
	if err == nil {
		week, err = h.store.Stats(ctx, now.Add(-7*24*time.Hour), 10)
	}
	if err != nil && ctx.Err() != nil {
		return nil, nil, err // abgebrochene Anfrage nicht zwischenspeichern
	}
	h.at, h.day, h.week, h.statErr = time.Now(), day, week, err
	return day, week, err
}

func (h *hpInfo) metrics(w http.ResponseWriter, r *http.Request) {
	mw := metrics.New()
	h.writeMetrics(r.Context(), mw)
	w.Header().Set("Content-Type", metrics.ContentType)
	_, _ = mw.WriteTo(w)
}

// writeMetrics schreibt die Kennzahlen des Honeypots (honeypot.WriteMetrics, wie /api/metrics des Moduls) und die
// des Modus selbst.
func (h *hpInfo) writeMetrics(ctx context.Context, w *metrics.Writer) {
	w.Gauge("node64_honeypot_up", "Honeypot64 laeuft.", 1)
	w.Gauge("node64_honeypot_info", "Honeypot64 ohne Oberflaeche (Version, Profil).", 1, "version", h.version, "profile", h.profileLabel())
	w.Gauge("node64_honeypot_uptime_seconds", "Sekunden seit dem Start des Modus ohne Oberflaeche.", time.Since(h.started).Seconds())
	honeypot.WriteMetrics(w, h.sensor, h.store, h.rep, ctx)
	if h.logs != nil {
		st := h.logs.Status()
		honeypot.WriteLogMetrics(w, &st)
	}
}

func (h *hpInfo) profileLabel() string { return hpProfileLabel(h.hc) }

func hpProfileLabel(hc *hpModeConfig) string {
	if hc.Custom {
		return "custom"
	}
	return hc.Profile
}

// ---- Info-Seite (nur lesend, ohne Formular und ohne JS; zweisprachig fest im Template)

// hpInfoCSS steht woertlich im Template; ihr Hash erlaubt sie in der CSP (sonst keine Inhalte).
const hpInfoCSS = `:root{color-scheme:light dark;--bg:#f6f7f9;--fg:#1d2330;--mut:#5d6675;--card:#fff;--line:#dfe3ea;--ok:#1a7f37;--bad:#c62828;--acc:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#12151b;--fg:#e4e8ef;--mut:#99a3b3;--card:#1b2029;--line:#2c3340;--ok:#4cc26b;--bad:#f0645a;--acc:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:16px}h1{font-size:1.4rem;margin:0 0 4px}h2{font-size:1rem;margin:0 0 8px}
.mut{color:var(--mut);font-size:.9rem}.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(min(100%,300px),1fr));margin-top:12px}
.kpis{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-top:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px;min-width:0}
.kpi b{display:block;font-size:1.5rem;font-variant-numeric:tabular-nums}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}td,th{padding:4px 6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}td.k{word-break:break-all;font-family:ui-monospace,Consolas,monospace}
.ok{color:var(--ok)}.bad{color:var(--bad)}footer{margin-top:16px}`

var (
	hpInfoCSP = func() string {
		sum := sha256.Sum256([]byte(hpInfoCSS))
		return "default-src 'none'; style-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	}()
	hpInfoTmpl = template.Must(template.New("info").Funcs(template.FuncMap{"short": hpShort, "when": hpWhen, "perm": hpPermErr}).Parse(`<!doctype html>
<html lang="{{.Lang}}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><meta http-equiv="refresh" content="60">
<title>Honeypot64</title><style>` + hpInfoCSS + `</style></head><body><main>
<h1>Honeypot64</h1>
<div class="mut">Node64 {{.Version}} · {{.T.Profile}}: {{.Profile}} · {{.T.Uptime}}: {{.Uptime}}</div>
<div class="kpis">
<div class="card kpi"><span class="mut">{{.T.Hits24}}</span><b>{{.Day.Events}}</b></div>
<div class="card kpi"><span class="mut">{{.T.Hits7}}</span><b>{{.Week.Events}}</b></div>
<div class="card kpi"><span class="mut">{{.T.Src24}}</span><b>{{.Day.Sources}}</b></div>
<div class="card kpi"><span class="mut">{{.T.Src7}}</span><b>{{.Week.Sources}}</b></div>
<div class="card kpi"><span class="mut">{{.T.Logins7}}</span><b>{{.Week.Logins}}</b></div>
</div>
{{if .Err}}<p class="bad">{{.T.StatsErr}}</p>{{end}}
<div class="grid">
<section class="card"><h2>{{.T.Services}}</h2><div class="tw"><table><tr><th>{{.T.Service}}</th><th>Port</th><th>{{.T.State}}</th><th>{{.T.Conns}}</th></tr>
{{range .Services}}<tr><td>{{.Service}}</td><td class="n">{{.Port}}</td><td>{{if .Listen}}<span class="ok">{{$.T.Open}}</span>{{else}}<span class="bad">{{$.T.Closed}}{{if .Error}}: {{short .Error}}{{end}}</span>{{end}}</td><td class="n">{{.Conns}}</td></tr>
{{else}}<tr><td colspan="4" class="mut">{{$.T.None}}</td></tr>{{end}}</table></div>
<p class="mut">{{.T.Scan}}: {{if .Scan}}{{.T.On}}{{else}}{{.T.Off}}{{end}}</p></section>
<section class="card"><h2>{{.T.Report}}</h2><div class="tw"><table>
<tr><td>{{.T.State}}</td><td>{{if .Rep.Active}}<span class="ok">{{.T.On}}</span>{{else if .Key}}{{.T.Off}} (NODE64_HONEYPOT_REPORT=0){{else}}{{.T.Off}} ({{.T.NoKey}}){{end}}</td></tr>
{{if .Rep.Active}}<tr><td>{{.T.LastReport}}</td><td>{{if .Rep.LastSuccess.IsZero}}{{.T.Never}}{{else}}{{when .Rep.LastSuccess}}{{end}}</td></tr>
<tr><td>{{.T.NextTry}}</td><td>{{if .Rep.NextAttempt.IsZero}}–{{else}}{{when .Rep.NextAttempt}}{{end}}</td></tr>
<tr><td>{{.T.RepSources}}</td><td class="n">{{.Rep.SourcesToday}} / {{.Rep.SourcesTotal}}</td></tr>
<tr><td>{{.T.RepErrors}}</td><td class="n">{{.Rep.Errors}}</td></tr>
{{if .Rep.LastRejected}}<tr><td>{{.T.Rejected}}</td><td>{{.Rep.LastRejected}}: {{short .Rep.RejectedText}}</td></tr>{{end}}
{{if .Rep.LastError}}<tr><td>{{.T.LastErr}}</td><td class="bad">{{when .Rep.LastErrorAt}}: {{short .Rep.LastError}}</td></tr>{{end}}
<tr><td>{{.T.SensorID}}</td><td class="k">{{.Rep.SensorID}}</td></tr>{{end}}
</table></div></section>
<section class="card"><h2>{{.T.Logs}}</h2><div class="tw"><table><tr><th>{{.T.File}}</th><th>{{.T.State}}</th><th>{{.T.Lines}}</th></tr>
{{range .Logs.Files}}<tr><td class="k">{{short .Path}}{{if .Format}} ({{.Format}}){{end}}</td><td>{{if .OK}}<span class="ok">{{$.T.FileOK}}</span>{{else}}<span class="bad">{{$.T.FileErr}}{{if .Error}}: {{short .Error}}{{end}}</span>{{if perm .Error}}<br><span class="mut">{{$.T.PermHint}}</span>{{end}}{{end}}</td><td class="n">{{.Lines}}</td></tr>
{{else}}<tr><td colspan="3" class="mut">{{$.T.Off}} (NODE64_HONEYPOT_LOGS)</td></tr>{{end}}
<tr><td>Syslog</td><td colspan="2">{{with .Logs.Syslog}}{{if .Error}}<span class="bad">{{$.T.FileErr}} ({{.Port}}): {{short .Error}}</span>{{else}}<span class="ok">{{$.T.On}}</span> · Port {{.Port}}{{if .UDP}} UDP{{end}}{{if .TCP}} TCP{{end}} · {{$.T.Messages}}: {{.Messages}} · {{$.T.Denied}}: {{.Denied}}{{end}}{{else}}{{$.T.Off}} (NODE64_HONEYPOT_SYSLOG_PORT){{end}}</td></tr>
</table></div><p class="mut">{{.T.LogNote}}</p></section>
{{template "list" (.L .T.TopIPs .Week.TopSources)}}
{{template "list" (.L .T.Kinds .Week.ByKind)}}
{{template "list" (.L .T.Origins .Week.BySource)}}
{{template "list" (.L .T.Ports .Week.ByPort)}}
{{template "list" (.L .T.Creds .Week.TopCreds)}}
{{template "list" (.L .T.Paths .Week.TopPaths)}}
{{template "list" (.L .T.UAs .Week.TopUAs)}}
</div>
<footer class="mut">{{.T.Foot}}</footer>
</main></body></html>
{{define "list"}}<section class="card"><h2>{{.Title}}</h2><div class="tw"><table>
{{range .Rows}}<tr><td class="k">{{short .Key}}</td><td class="n">{{.Count}}</td></tr>
{{else}}<tr><td class="mut">–</td></tr>{{end}}</table></div></section>{{end}}`))
)

type hpTexts struct {
	Profile, Uptime, Hits24, Hits7, Src24, Src7, Logins7, StatsErr, Services, Service, State, Conns, Open, Closed, None,
	Scan, On, Off, Report, NoKey, LastReport, Never, NextTry, RepSources, RepErrors, Rejected, LastErr, SensorID, TopIPs, Kinds, Ports, Creds, Paths, UAs, Foot string
	// Log-Sensor und Syslog (H5)
	Logs, File, Lines, FileOK, FileErr, PermHint, Messages, Denied, LogNote, Origins string
}

var hpTextsByLang = map[string]hpTexts{
	"de": {Profile: "Profil", Uptime: "Laufzeit", Hits24: "Treffer 24 h", Hits7: "Treffer 7 Tage", Src24: "Quell-IPs 24 h", Src7: "Quell-IPs 7 Tage",
		Logins7: "Login-Versuche 7 Tage", StatsErr: "Statistik zurzeit nicht lesbar.", Services: "Dienste", Service: "Dienst", State: "Zustand",
		Conns: "Verbindungen", Open: "offen", Closed: "nicht offen", None: "keine", Scan: "Port-Scan-Erkennung", On: "an", Off: "aus",
		Report: "Meldung an ipv64", NoKey: "kein NODE64_IPV64_KEY", LastReport: "Letzte Meldung", Never: "noch keine", NextTry: "Nächster Versuch",
		RepSources: "Gemeldete Quell-IPs heute / seit Start", RepErrors: "Fehler seit Start", Rejected: "Zuletzt von ipv64 abgelehnte Quellen", LastErr: "Letzter Fehler", SensorID: "Sensor-Kennung", TopIPs: "Top-IPs (7 Tage)",
		Kinds: "Arten (7 Tage)", Ports: "Ports (7 Tage)", Creds: "Zugangsdaten (7 Tage)", Paths: "Pfade (7 Tage)", UAs: "User-Agents (7 Tage)",
		Foot: "Nur lesend. Aktualisiert sich jede Minute. Prometheus: /metrics",
		Logs: "Log-Sensor und Syslog", File: "Datei", Lines: "Zeilen", FileOK: "wird gelesen", FileErr: "Fehler",
		PermHint: "Keine Leserechte: Container mit --group-add 4 (Gruppe adm) starten.", Messages: "Nachrichten", Denied: "abgewiesen",
		LogNote: "Aus echten Logs werden nur IP, Art, Dienst, Port, Anzahl und Regel gemeldet.", Origins: "Quellen (7 Tage)"},
	"en": {Profile: "Profile", Uptime: "Uptime", Hits24: "Hits 24 h", Hits7: "Hits 7 days", Src24: "Source IPs 24 h", Src7: "Source IPs 7 days",
		Logins7: "Login attempts 7 days", StatsErr: "Statistics currently not readable.", Services: "Services", Service: "Service", State: "State",
		Conns: "Connections", Open: "open", Closed: "not open", None: "none", Scan: "Port scan detection", On: "on", Off: "off",
		Report: "Reporting to ipv64", NoKey: "no NODE64_IPV64_KEY", LastReport: "Last report", Never: "none yet", NextTry: "Next attempt",
		RepSources: "Reported source IPs today / since start", RepErrors: "Errors since start", Rejected: "Sources last rejected by ipv64", LastErr: "Last error", SensorID: "Sensor ID", TopIPs: "Top IPs (7 days)",
		Kinds: "Kinds (7 days)", Ports: "Ports (7 days)", Creds: "Credentials (7 days)", Paths: "Paths (7 days)", UAs: "User agents (7 days)",
		Foot: "Read only. Refreshes every minute. Prometheus: /metrics",
		Logs: "Log sensor and syslog", File: "File", Lines: "Lines", FileOK: "reading", FileErr: "error",
		PermHint: "No read permission: start the container with --group-add 4 (group adm).", Messages: "messages", Denied: "denied",
		LogNote: "From real logs only IP, kind, service, port, count and rule are reported.", Origins: "Sources (7 days)"},
}

type hpList struct {
	Title string
	Rows  []honeypot.Count
}

type hpPage struct {
	Lang, Version, Profile, Uptime string
	T                              hpTexts
	Day, Week                      *honeypot.Stats
	Err, Scan, Key                 bool
	Services                       []honeypot.ServiceStatus
	Rep                            honeypot.ReportStatus
	Logs                           honeypot.LogStatus
}

// L baut eine Rangliste fuer das Untertemplate "list".
func (hpPage) L(title string, rows []honeypot.Count) hpList { return hpList{Title: title, Rows: rows} }

func (h *hpInfo) page(w http.ResponseWriter, r *http.Request) {
	lang := hpLang(r.Header.Get("Accept-Language"))
	day, week, err := h.stats(r.Context())
	if err != nil {
		day, week = &honeypot.Stats{}, &honeypot.Stats{}
	}
	p := hpPage{Lang: lang, Version: h.version, Profile: h.profileLabel(), Uptime: hpUptime(time.Since(h.started)), T: hpTextsByLang[lang],
		Day: day, Week: week, Err: err != nil, Scan: h.hc.Sensor.Scan, Key: h.hc.IPv64Key != "", Services: h.sensor.Status()}
	if h.rep != nil {
		p.Rep = h.rep.Status(r.Context())
	}
	if h.logs != nil {
		p.Logs = h.logs.Status()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method == http.MethodHead {
		return
	}
	_ = hpInfoTmpl.Execute(w, p)
}

// hpLang: die erste passende Sprache aus Accept-Language (de oder en), sonst en.
func hpLang(accept string) string {
	for _, part := range strings.Split(accept, ",") {
		tag, _, _ := strings.Cut(strings.TrimSpace(part), ";")
		tag = strings.ToLower(strings.TrimSpace(tag))
		if tag == "de" || strings.HasPrefix(tag, "de-") {
			return "de"
		}
		if tag == "en" || strings.HasPrefix(tag, "en-") {
			return "en"
		}
	}
	return "en"
}

// hpUptime: "3 d 4 h 5 min".
func hpUptime(d time.Duration) string {
	d = d.Truncate(time.Minute)
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	mins := int((d - time.Duration(hours)*time.Hour) / time.Minute)
	if days > 0 {
		return fmt.Sprintf("%d d %d h %d min", days, hours, mins)
	}
	if hours > 0 {
		return fmt.Sprintf("%d h %d min", hours, mins)
	}
	return fmt.Sprintf("%d min", mins)
}

// hpWhen: Zeitpunkt in der Zeitzone des Containers (TZ), mit Zone.
func hpWhen(t time.Time) string { return t.Local().Format("2006-01-02 15:04:05 MST") }

// hpPermErr: Fehler beim Lesen einer Log-Datei sind fehlende Rechte (Hinweis auf --group-add 4).
func hpPermErr(err string) bool { return strings.Contains(strings.ToLower(err), "permission denied") }

// hpShort kuerzt Angreifer-Texte fuer die Anzeige (Steuerzeichen raus, hoechstens 120 Zeichen).
func hpShort(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return '·'
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 120 {
		s = string([]rune(s)[:120]) + "…"
	}
	return s
}
