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
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ipv64net/node64/internal/netstat"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen im Binary, das Laufzeit-Image hat keine

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
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
	if err := applyReset(cfg, log); err != nil {
		return err
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
	ipv64Key := ipv64api.NewKey(st, box, ipv64api.NewClient(os.Getenv("NODE64_IPV64_API"), "node64/"+Version), logger.Slog()) // leer = ipv64.net (Env nur fuer Tests)
	dynModule := dyndns.New(st, logger.Slog(), box, dispatcher, Version)
	dynModule.SetKey(ipv64Key)
	modules.Register(dynModule)
	registerModules(modules)
	modules.StartEnabled(ctx)
	defer modules.StopAll()

	// Verknuepfung mit ipv64.net (Sync-Client); standalone bleibt alles wie gehabt
	syncClient := nodesync.New(nodesync.Deps{Core: st, HC: hcModule, NF: nfStore, Box: box, Version: Version, Log: logger.Slog(), Senders: notify.Senders(Version), Modules: modules,
		UnlinkAPI: func(ctx context.Context, nodeID string, keep bool) error { // hubs nicht erreichbar: ueber die API v2 trennen
			key := ipv64Key.Get(ctx)
			if key == "" {
				return errors.New("no ipv64 api key")
			}
			return ipv64Key.Client().HC2UnlinkNode(ctx, key, nodeID, keep)
		}})
	// lokale Gruppe: Nodes desselben ipv64-Accounts gleichen direkt untereinander ab
	if st.SettingOr(ctx, web.SettingNodeID, "") == "" { // Kennung der Node (sonst erst beim Setup-Assistenten oder Verknuepfen)
		b := make([]byte, 24)
		_, _ = rand.Read(b)
		if err := st.SetSetting(ctx, web.SettingNodeID, base64.RawURLEncoding.EncodeToString(b)); err != nil {
			return err
		}
	}
	peerMigrations, err := peer.Migrations()
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "peer", peerMigrations); err != nil {
		return err
	}
	peerMgr, err := peer.New(ctx, peer.Deps{Core: st, Box: box, Log: logger.Slog().With("module", "peer"), Version: Version,
		NodeID:   func() string { return st.SettingOr(context.Background(), web.SettingNodeID, "") },
		NodeName: func() string { return st.SettingOr(context.Background(), web.SettingNodeName, "Node64") },
		AccountID: func() int64 { // ipv64-Account aus dem Healthchecks-Sync, sonst vom API-Key
			if s := syncClient.State(); s.Linked {
				if id, err := strconv.ParseInt(s.AccountID, 10, 64); err == nil && id > 0 {
					return id
				}
			}
			return int64(ipv64Key.Info(context.Background()).ID)
		},
		Checks: func() peer.Checks { // Abgleich der Checks nur bei laufendem Healthchecks-Modul
			if !modules.IsRunning(healthchecks.Name) {
				return nil
			}
			return hcModule
		},
		Linked: syncClient.Linked,
		Forward: func(ctx context.Context, entity, id, op string) { // Aenderung einer nicht verknuepften Node an den hub
			if f := hcModule.Store().OnChange; f != nil {
				f(context.WithoutCancel(ctx), entity, id, op)
			}
		}})
	if err != nil {
		return err
	}
	hcModule.Store().OnAnyChange = peerMgr.LogChange
	go peerMgr.Run(ctx)
	dispatcher.SetSendServerChannels(st.SettingOr(ctx, nodesync.SetLocalNotif, "0") == "1")
	dispatcher.SetServerSends(syncClient.ServerSends)
	// Meldungen der Module (z. B. DynDNS) ueber ipv64-Mail/-SMS direkt per API, ohne hub; ohne Verknuepfung die Kanaele des Accounts
	dispatcher.SetAPISender(ipv64Key.SendNotification, ipv64Key.APIReady)
	dispatcher.SetRemoteChannels(func(ctx context.Context) []*notify.Channel {
		if syncClient.Linked() {
			return nil // verknuepft: die Server-Kanaele kommen als Platzhalter ueber den Sync
		}
		return ipv64Key.RemoteChannels(ctx)
	})
	hcModule.SetLinked(syncClient.Linked)
	hcModule.SetQuota(syncClient.Quota)
	hcModule.SetAPI(ipv64Key) // Online-Checks direkt ueber die API v2, solange kein Sync besteht
	hcModule.SetPushForward(syncClient.ForwardPush)
	hcModule.SetRunRemote(syncClient.RunRemote)
	go netstat.Loop(ctx, st) // Datenverkehr des Containers fuer das Dashboard
	if err := syncClient.Start(ctx); err != nil {
		log.Warn("sync start failed", "err", err)
	}
	if toHub := hcModule.Store().OnChange; toHub != nil { // Checks nur nicht verknuepfter Nodes der Gruppe bleiben lokal
		hcModule.Store().OnChange = func(ctx context.Context, entity, id, op string) {
			if entity == "check" && op != "delete" && !peerMgr.HubKnowsCheck(ctx, id) {
				return
			}
			toHub(ctx, entity, id, op)
		}
	}
	defer syncClient.Stop(context.Background())
	go updateLoop(ctx, st, log)

	srv, err := web.New(web.Deps{
		Cfg: cfg, Store: st, Log: logger, I18n: bundle, Modules: modules, Notify: nfStore, Dispatcher: dispatcher,
		Sync: syncClient, Linker: syncClient, HC: hcModule, IPv64: ipv64Key, Peer: peerMgr, Version: Version, StartedAt: time.Now(), Restart: stop,
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
	r.Register(module.Placeholder{I: module.Info{Name: "proxy", TitleKey: "nav.proxy", Icon: "bi-diagram-3", Image: "cdn64.webp", Path: "/proxy", Order: 30}})
	r.Register(module.Placeholder{I: module.Info{Name: "dns64", TitleKey: "nav.dns64", Icon: "bi-shield-check", Image: "dns64.webp", Path: "/dns64", Order: 40}})
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

// applyReset leert nach einem Zuruecksetzen (Merker node64.reset) das Datenverzeichnis; nur ein
// eigenes Zertifikat (NODE64_TLS_CERT/KEY), das dort liegt, bleibt erhalten.
func applyReset(cfg *config.Config, log *slog.Logger) error {
	if _, err := os.Stat(filepath.Join(cfg.DataDir, web.ResetFileName)); err != nil {
		return nil
	}
	var keep []string
	for _, f := range []string{cfg.TLSCertFile, cfg.TLSKeyFile} {
		if f != "" {
			if abs, err := filepath.Abs(f); err == nil {
				keep = append(keep, abs)
			}
		}
	}
	entries, err := os.ReadDir(cfg.DataDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		p := filepath.Join(cfg.DataDir, e.Name())
		abs, _ := filepath.Abs(p)
		held := false
		for _, k := range keep {
			held = held || k == abs || strings.HasPrefix(k, abs+string(filepath.Separator))
		}
		if held || e.Name() == web.ResetFileName {
			continue
		}
		if err := os.RemoveAll(p); err != nil {
			return fmt.Errorf("reset %s: %w", p, err)
		}
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, web.ResetFileName)); err != nil {
		return err
	}
	log.Warn("factory reset: data directory cleared")
	return nil
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
