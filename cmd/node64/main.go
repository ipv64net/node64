// Node64: ein Binary mit Weboberflaeche, SQLite und Modulen.
//
// Befehle:
//
//	node              startet den Node
//	node healthcheck  prueft die lokale UI (fuer Docker HEALTHCHECK), Exit 0 = gesund
//	node version      zeigt die Version
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen im Binary, das Laufzeit-Image hat keine

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/update"
	"github.com/ipv64net/node64/internal/web"
)

// Version wird beim Build gesetzt: -ldflags "-X main.Version=1.2.3"
var Version = "dev"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println("node64", Version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "node:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logger := logging.New(cfg.LogLevel, cfg.LogFormat, os.Stdout)
	defer logger.Close()
	log := logger.Slog().With("module", "core")
	logger.OnChange(func() { log.Info("log level changed", "level", logging.LevelName(logger.Level())) })
	log.Info("node64 starting", "version", Version, "data", cfg.DataDir)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir %s: %w", cfg.DataDir, err)
	}
	box, err := secrets.Load(cfg.SecretKeyPath())
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := applyRestore(cfg, log); err != nil {
		return err
	}

	st, err := store.Open(ctx, cfg.DBPath(), cfg.BackupDir(), logger.Slog())
	if err != nil {
		return err
	}
	defer st.Close()
	core, err := store.CoreMigrations()
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "core", core); err != nil {
		return err
	}
	if err := firstAdminFromEnv(ctx, cfg, st, log); err != nil {
		return err
	}

	bundle, err := i18n.Load()
	if err != nil {
		return err
	}

	// Benachrichtigungen gehoeren zum Kern und laufen immer
	nfMigrations, err := notify.Migrations()
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "notify", nfMigrations); err != nil {
		return err
	}
	nfStore := notify.NewStore(st, box)
	dispatcher := notify.NewDispatcher(nfStore, notify.Senders(Version), bundle, func(key, def string) string { return st.SettingOr(ctx, key, def) }, logger.Slog())
	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	modules := module.NewRegistry(st, logger.Slog())
	hcModule := healthchecks.New(st, logger.Slog(), dispatcher, nfStore, Version)
	modules.Register(hcModule)
	registerModules(modules)
	modules.StartEnabled(ctx)
	defer modules.StopAll()

	// Verknuepfung mit ipv64.net (Sync-Client); standalone bleibt alles wie gehabt
	syncClient := nodesync.New(nodesync.Deps{Core: st, HC: hcModule, NF: nfStore, Box: box, Version: Version, Log: logger.Slog(), Senders: notify.Senders(Version)})
	dispatcher.SetSendServerChannels(st.SettingOr(ctx, nodesync.SetLocalNotif, "0") == "1")
	if err := syncClient.Start(ctx); err != nil {
		log.Warn("sync start failed", "err", err)
	}
	defer syncClient.Stop(context.Background())
	go updateLoop(ctx, st, log)

	srv, err := web.New(web.Deps{
		Cfg: cfg, Store: st, Log: logger, I18n: bundle, Modules: modules, Notify: nfStore, Dispatcher: dispatcher,
		Sync: syncClient, Linker: syncClient, HC: hcModule, Version: Version, StartedAt: time.Now(), Restart: stop,
	})
	if err != nil {
		return err
	}
	err = srv.Run(ctx)
	log.Info("node64 stopped")
	return err
}

// registerModules meldet die Platzhalter an, die erst spaeter kommen.
func registerModules(r *module.Registry) {
	r.Register(module.Placeholder{I: module.Info{Name: "dyndns", TitleKey: "nav.dyndns", Icon: "bi-globe", Image: "dyndns64.webp", Path: "/dyndns", Order: 20}})
	r.Register(module.Placeholder{I: module.Info{Name: "proxy", TitleKey: "nav.proxy", Icon: "bi-diagram-3", Image: "cdn64.webp", Path: "/proxy", Order: 30}})
}

// updateLoop prueft taeglich auf neue Versionen, aber nur wenn der Nutzer es
// in den Einstellungen eingeschaltet hat.
func updateLoop(ctx context.Context, st *store.Store, log *slog.Logger) {
	check := func() {
		if st.SettingOr(ctx, "updates.check", "0") != "1" {
			return
		}
		info, err := update.New(Version).Check(ctx)
		if err != nil {
			log.Debug("update check failed", "err", err)
			return
		}
		b, _ := json.Marshal(info)
		_ = st.SetSetting(ctx, "updates.latest", string(b))
		if info.Newer {
			log.Info("new node version available", "version", info.Version, "url", info.URL)
		}
	}
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
		check()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			check()
		}
	}
}

// applyRestore setzt eine hochgeladene Datenbank (node64.db.restore) ein und
// sichert die bisherige vorher unter backups/.
func applyRestore(cfg *config.Config, log *slog.Logger) error {
	restore := filepath.Join(cfg.DataDir, web.RestoreFileName)
	if _, err := os.Stat(restore); err != nil {
		return nil
	}
	if err := os.MkdirAll(cfg.BackupDir(), 0o750); err != nil {
		return err
	}
	if _, err := os.Stat(cfg.DBPath()); err == nil {
		dest := filepath.Join(cfg.BackupDir(), "node64-"+time.Now().UTC().Format("20060102-150405")+"-pre-restore.db")
		if err := os.Rename(cfg.DBPath(), dest); err != nil {
			return fmt.Errorf("move old database: %w", err)
		}
		log.Info("old database kept", "file", dest)
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		_ = os.Remove(cfg.DBPath() + suffix)
	}
	if err := os.Rename(restore, cfg.DBPath()); err != nil {
		return fmt.Errorf("apply restore: %w", err)
	}
	log.Warn("database restored from upload")
	return nil
}

// firstAdminFromEnv legt den Administrator aus NODE64_ADMIN_USER/PASSWORD an,
// aber nur, solange noch kein Benutzer existiert.
func firstAdminFromEnv(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) error {
	if cfg.AdminUser == "" {
		return nil
	}
	n, err := st.UserCount(ctx)
	if err != nil || n > 0 {
		return err
	}
	hash, err := web.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	if _, err := st.CreateUser(ctx, cfg.AdminUser, hash, "", "UTC"); err != nil {
		return fmt.Errorf("create admin from environment: %w", err)
	}
	host, _ := os.Hostname()
	_ = st.SetSetting(ctx, web.SettingNodeName, host)
	_ = st.Audit(ctx, store.AuditEntry{Actor: cfg.AdminUser, Action: "setup", Details: "admin created from environment"})
	log.Info("admin user created from environment", "user", cfg.AdminUser)
	return nil
}

// healthcheck ruft /api/health der eigenen Oberflaeche auf (Docker HEALTHCHECK).
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Bind-Adresse verwenden, wenn gesetzt; sonst beide Loopbacks probieren
	// (Container ohne IPv4 oder ohne IPv6 sollen beide gesund gemeldet werden).
	hosts := []string{"127.0.0.1", "::1"}
	if cfg.BindAddr != "" && cfg.BindAddr != "0.0.0.0" && cfg.BindAddr != "::" {
		hosts = []string{cfg.BindAddr}
	}
	scheme, port := "http", cfg.HTTPPort
	client := &http.Client{Timeout: 4 * time.Second}
	if cfg.HTTPPort == 0 {
		scheme, port = "https", cfg.HTTPSPort
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // eigenes selbstsigniertes Zertifikat
	}
	var resp *http.Response

	for _, h := range hosts {
		resp, err = client.Get(fmt.Sprintf("%s://%s/api/health", scheme, net.JoinHostPort(h, strconv.Itoa(port))))
		if err == nil {
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
