// ipv64-hub: Serverdienst von Healthchecks 2.0 (Rollen checker und gateway).
//
//	hub -config /etc/ipv64-hub/config.yaml
//	hub -version
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen fuer Ruhezeiten auch ohne zoneinfo auf dem Server

	"github.com/ipv64net/node64/internal/hub/checker"
	"github.com/ipv64net/node64/internal/hub/config"
	"github.com/ipv64net/node64/internal/hub/gateway"
	"github.com/ipv64net/node64/internal/hub/httpapi"
	hubnotify "github.com/ipv64net/node64/internal/hub/notify"
	"github.com/ipv64net/node64/internal/hub/ops"
	"github.com/ipv64net/node64/internal/hub/store"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
)

// Version wird beim Build gesetzt.
var Version = "dev"

var opsTest *bool

func main() {
	cfgPath := flag.String("config", "/etc/ipv64-hub/config.yaml", "Konfigurationsdatei")
	showVersion := flag.Bool("version", false, "Version ausgeben")
	opsTest = flag.Bool("ops-test", false, "Testnachricht an die Betriebsalarm-Kanaele schicken und beenden")
	flag.Parse()
	if *showVersion {
		fmt.Println("ipv64-hub", Version)
		return
	}
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	log.Info("ipv64-hub starting", "version", Version, "node", cfg.NodeName, "location", cfg.Location, "roles", cfg.Roles)

	st, err := store.Open(cfg.MySQL.DSN, cfg.Location, cfg.NodeName, log)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go st.UsageLoop(ctx) // Tageskontingent der Online-Checks

	// Benachrichtigungen: Kanal-Geheimnisse mit dem gemeinsamen Schluessel, Versand ueber Bruecke + direkte Sender
	var box *secrets.Box
	if key, err := os.ReadFile(cfg.SecretKeyFile); err == nil {
		// Textdatei mit 64 Hex-Zeichen (kopierbar) oder 32 Rohbytes
		if t := strings.TrimSpace(string(key)); len(t) == 64 {
			if raw, err := hex.DecodeString(t); err == nil {
				key = raw
			}
		}
		if box, err = secrets.New(key); err != nil {
			return fmt.Errorf("secret key: %w", err)
		}
	} else {
		log.Warn("secret key file missing, channel secrets cannot be decrypted", "file", cfg.SecretKeyFile)
	}
	var bridge *hubnotify.Bridge
	var portalSecret []byte
	if cfg.Bridge.URL != "" {
		sec, err := os.ReadFile(cfg.Bridge.SecretFile)
		if err != nil {
			log.Warn("bridge secret missing, ipv64_mail/sms/app disabled", "file", cfg.Bridge.SecretFile)
		} else {
			bridge = hubnotify.NewBridge(cfg.Bridge.URL, []byte(strings.TrimSpace(string(sec))), "ipv64-hub/"+Version)
			portalSecret = []byte(strings.TrimSpace(string(sec)))
		}
	}
	bundle, err := i18n.Load()
	if err != nil {
		return err
	}
	st.SetBox(box)
	nfStore := hubnotify.New(st.DB(), box, log)
	senders := hubnotify.Senders(Version, bridge, nfStore)
	dispatcher := notify.NewMultiDispatcher(nfStore, senders, bundle, nfStore.SettingsFor, log)
	// der hub verschickt alle Kanaele: ipv64-Mail/SMS/App und Portal-Kanaele selbst, Node-Kanaele per Sendeauftrag
	dispatcher.SetSendServerChannels(true)
	// Links fuehren auf die Seiten des Portals
	dispatcher.SetLinks(func(token string) string { return "/check.php?token=" + token }, func(q string) string {
		if q == "" {
			return "/"
		}
		return "/index.php?" + q
	})
	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	var chk *checker.Checker
	if cfg.HasRole("checker") {
		chk = checker.New(st, log, cfg.Location, Version, strings.Join(cfg.Roles, ","), cfg.Limits.CheckerWorkers)
		chk.SetLimits(cfg.Limits.TargetRunsPerMinute, cfg.Limits.RunsPerSecond)
		chk.SetNotifier(dispatcher, nfStore)
		if err := chk.Start(ctx); err != nil {
			return fmt.Errorf("checker: %w", err)
		}
		defer chk.Stop()
	}

	var gw *gateway.Gateway
	if cfg.HasRole("gateway") {
		gw = gateway.New(st, nfStore, senders, log, Version, cfg.Location, cfg.Limits.MaxConnections)
		// Eigener Kontext: beim Stopp-Signal sollen die Nodes erst "bye" bekommen (gw.Stop), nicht sofort EOF
		gw.SetPortalSecret(portalSecret)
		gw.SetTrusted(cfg.Limits.TrustedIPs)
		realIP, _ := cfg.RealIPPrefixes() // in config.Load geprueft
		gw.SetRealIPFrom(realIP)
		if err := gw.Start(context.Background()); err != nil {
			return fmt.Errorf("gateway: %w", err)
		}
		defer gw.Stop()
	}

	locName := map[string]string{"fsn": "Falkenstein (Deutschland)", "nbg": "Nürnberg (Deutschland)"}[cfg.Location]
	if locName == "" {
		locName = cfg.Location
	}
	// Betriebsalarme (andere hubs, eigene Datenbank) an den Betreiber
	watcher := ops.New(cfg.Ops, cfg.NodeName, locName, st.DB(), senders, log)
	if *opsTest {
		watcher.Test(ctx)
		return nil
	}
	go watcher.Run(ctx)
	status := func() map[string]any {
		out := map[string]any{"node": cfg.NodeName, "location": cfg.Location, "roles": cfg.Roles, "version": Version, "db": "ok"}
		if ok, e := watcher.DBStatus(); !ok {
			out["status"], out["db"] = "degraded", e
		}
		if chk != nil {
			out["checks"] = chk.Count()
			out["throttled"] = chk.Skipped()
		}
		if gw != nil {
			out["connections"] = gw.Connections()
		}
		return out
	}
	srv := httpapi.New(cfg.Listen, log, st.Metrics, status)
	srv.RegisterInfo(httpapi.Info{Name: cfg.NodeName, Location: locName, Version: Version})
	if gw != nil {
		gw.Register(srv.Mux())
		gw.RegisterPortal(srv.Mux())
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("http listening", "addr", cfg.Listen)
	if cfg.MetricsListen != "" { // Prometheus fuer den Betreiber im internen Netz
		allow, _ := cfg.MetricsPrefixes() // in config.Load geprueft
		ms, err := srv.ServeMetrics(cfg.MetricsListen, allow)
		if err != nil {
			return fmt.Errorf("metrics_listen: %w", err)
		}
		defer ms.Shutdown(5 * time.Second)
		log.Info("metrics listening", "addr", ms.Addr(), "allow", cfg.MetricsAllow)
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil {
			return err
		}
	}
	srv.Shutdown(10 * time.Second)
	return nil
}
