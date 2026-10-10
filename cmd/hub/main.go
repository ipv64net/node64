// ipv64-hub: Serverdienst von Healthchecks 2.0 (Rollen checker und gateway).
//
//	hub -config /etc/ipv64-hub/config.yaml
//	hub -version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ipv64net/agent/internal/hub/checker"
	"github.com/ipv64net/agent/internal/hub/config"
	"github.com/ipv64net/agent/internal/hub/httpapi"
	hubnotify "github.com/ipv64net/agent/internal/hub/notify"
	"github.com/ipv64net/agent/internal/hub/store"
	"github.com/ipv64net/agent/internal/i18n"
	"github.com/ipv64net/agent/internal/notify"
	"github.com/ipv64net/agent/internal/secrets"
)

// Version wird beim Build gesetzt.
var Version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/ipv64-hub/config.yaml", "Konfigurationsdatei")
	showVersion := flag.Bool("version", false, "Version ausgeben")
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

	// Benachrichtigungen: Kanal-Geheimnisse mit dem gemeinsamen Schluessel, Versand ueber Bruecke + direkte Sender
	var box *secrets.Box
	if key, err := os.ReadFile(cfg.SecretKeyFile); err == nil {
		if box, err = secrets.New(key); err != nil {
			return fmt.Errorf("secret key: %w", err)
		}
	} else {
		log.Warn("secret key file missing, channel secrets cannot be decrypted", "file", cfg.SecretKeyFile)
	}
	var bridge *hubnotify.Bridge
	if cfg.Bridge.URL != "" {
		sec, err := os.ReadFile(cfg.Bridge.SecretFile)
		if err != nil {
			log.Warn("bridge secret missing, ipv64_mail/sms/app disabled", "file", cfg.Bridge.SecretFile)
		} else {
			bridge = hubnotify.NewBridge(cfg.Bridge.URL, []byte(strings.TrimSpace(string(sec))), "ipv64-hub/"+Version)
		}
	}
	bundle, err := i18n.Load()
	if err != nil {
		return err
	}
	nfStore := hubnotify.New(st.DB(), box, log)
	dispatcher := notify.NewMultiDispatcher(nfStore, hubnotify.Senders(Version, bridge, nfStore), bundle, nfStore.SettingsFor, log)
	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	var chk *checker.Checker
	if cfg.HasRole("checker") {
		chk = checker.New(st, log, cfg.Location, Version, strings.Join(cfg.Roles, ","), cfg.Limits.CheckerWorkers)
		chk.SetNotifier(dispatcher, nfStore)
		if err := chk.Start(ctx); err != nil {
			return fmt.Errorf("checker: %w", err)
		}
		defer chk.Stop()
	}

	status := func() map[string]any {
		out := map[string]any{"node": cfg.NodeName, "location": cfg.Location, "roles": cfg.Roles, "version": Version}
		if chk != nil {
			out["checks"] = chk.Count()
		}
		return out
	}
	srv := httpapi.New(cfg.Listen, log, st.Metrics, status)
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("http listening", "addr", cfg.Listen)

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
