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
	"io"
	"io/fs"
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

	"github.com/ipv64net/node64/internal/caps"
	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/certs/certcluster"
	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/ports"
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
		case "reset-password":
			os.Exit(resetPassword(os.Args[2:]))
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
	if raised, err := caps.Raise(); err != nil { // Ports unter 1024 (DNS64) und ICMP ohne Root, siehe Dockerfile
		log.Warn("capabilities could not be raised", "err", err)
	} else if raised {
		log.Debug("capabilities raised")
	}
	log.Info("node64 starting", "version", Version, "data", cfg.DataDir)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data dir %s: %w", cfg.DataDir, err)
	}
	if err := applyReset(cfg, log); err != nil {
		return err
	}
	ensureTempDir(cfg, log)
	// vor secret.key: ein Archiv bringt seinen Schluessel mit
	if err := applyRestore(cfg, log); err != nil {
		return err
	}
	box, err := secrets.Load(cfg.SecretKeyPath())
	if err != nil {
		return fmt.Errorf("secret key: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	// Kern: Port-Verwaltung, Zertifikate und der gemeinsame Eingang 80/443 (offen nur, solange ein Abnehmer ihn
	// braucht). Vor den Modulen angelegt und nach ihnen geschlossen (defer).
	portReg := ports.New()
	portReg.Provide("web", func(context.Context) []ports.Claim {
		var out []ports.Claim
		if cfg.HTTPPort > 0 {
			out = append(out, ports.Claim{Purpose: "HTTP", Proto: ports.TCP, Port: cfg.HTTPPort, Bind: cfg.BindAddr, Active: true})
		}
		if cfg.HTTPSPort > 0 {
			out = append(out, ports.Claim{Purpose: "HTTPS", Proto: ports.TCP, Port: cfg.HTTPSPort, Bind: cfg.BindAddr, Active: true})
		}
		return out
	})
	certMigrations, err := certs.Migrations()
	if err != nil {
		return err
	}
	if err := st.Migrate(ctx, "certs", certMigrations); err != nil {
		return err
	}
	certMgr, err := certs.New(ctx, certs.Deps{Store: st, Box: box, DNS: certs.IPv64(ipv64Key), Notify: dispatcher.Dispatch, Log: logger.Slog(), Version: Version})
	if err != nil {
		return err
	}
	edgeSrv, err := edge.New(edge.LoadConfig(func(k, def string) string { return st.SettingOr(ctx, k, def) }), certMgr,
		func(ctx context.Context, want []ports.Claim) error { return portReg.Check(ctx, edge.Owner, want) }, logger.Slog())
	if err != nil {
		return err
	}
	defer edgeSrv.Close(context.Background())
	certMgr.SetHTTP(edgeSrv) // HTTP-01 ueber Port 80 des Eingangs
	defer certMgr.Close()
	portReg.Provide(edge.Owner, edgeSrv.Claims)
	dynModule := dyndns.New(st, logger.Slog(), box, dispatcher, Version)
	dynModule.SetKey(ipv64Key)
	modules.Register(dynModule)
	dnsModule := dns64.New(st, logger.Slog(), cfg.DataDir, Version)
	dnsModule.SetEdge(edgeSrv)  // DoH teilt sich den HTTPS-Port mit CDN64
	dnsModule.SetCerts(certMgr) // Zertifikate aus der zentralen Verwaltung (einmaliger Umzug beim Start)
	if cfg.TLSCertFile != "" {  // DNS64 kann fuer DoH/DoT/DoQ das Zertifikat der Weboberflaeche nutzen
		dnsModule.SetWebCert(cfg.TLSCertFile, cfg.TLSKeyFile)
	} else {
		dnsModule.SetWebCert(filepath.Join(cfg.TLSDir(), "cert.pem"), filepath.Join(cfg.TLSDir(), "key.pem"))
	}
	dnsModule.SetNotifier(dispatcher.Dispatch) // Upstream gestoert, Blockliste nicht ladbar
	modules.Register(dnsModule)
	// Reverse-Proxy ueber den gemeinsamen Eingang
	cdnModule := cdn64.New(st, logger.Slog(), edgeSrv, certMgr, Version)
	cdnModule.SetSecrets(box)   // Tunnel-Token (CDN64 online)
	cdnModule.SetPorts(portReg) // Streams pruefen ihre Ports
	cdnModule.SetDataDir(cfg.DataDir)
	cdnModule.SetDNSRecords(cdn64.IPv64Records(ipv64Key))                          // DNS-Eintrag bei ipv64 beim Anlegen eines Hosts
	cdnModule.SetOnlineAPI(cdn64.IPv64Online(ipv64Key))                            // CDN64 online per Klick (Tunnel, Namen bei ipv64)
	cdnModule.SetNotifier(dispatcher.Dispatch)                                     // CDN64 online: Tunnel weg/wieder da, Sperre
	dnsModule.SetSplit(cdnModule.OnlineName)                                       // im Heimnetz: CDN64-online-Namen direkt zur Node
	cdnModule.SetCheckCreator(func(r *http.Request, body []byte) (string, error) { // "Healthcheck fuer dieses Ziel"
		if !modules.IsRunning(healthchecks.Name) {
			return "", errors.New("healthchecks module is switched off")
		}
		return hcModule.CreateFromJSON(r, body)
	})
	cdnModule.SetCheckFinder(func(ctx context.Context) []cdn64.CheckRef { // Liste: "von Healthchecks ueberwacht"
		if !modules.IsRunning(healthchecks.Name) {
			return nil
		}
		list, err := hcModule.Store().Checks(ctx)
		if err != nil {
			return nil
		}
		out := make([]cdn64.CheckRef, 0, len(list))
		for _, c := range list {
			out = append(out, cdn64.CheckRef{Token: c.Token, Name: c.Name, Type: string(c.Type), Target: c.Target, Params: c.Params, State: string(c.Runtime.State),
				Paused: c.Paused, Local: c.Owner != "online" && c.Owner != "other" && c.Execution != "online", LastCheck: c.Runtime.LastCheck})
		}
		return out
	})
	portReg.Provide(cdn64.Name, cdnModule.Claims)
	modules.Register(cdnModule)
	portReg.Provide(dns64.Name, func(ctx context.Context) []ports.Claim { // nur eingeschaltet; aktiv, solange es laeuft
		if on, _ := st.ModuleEnabled(ctx, dns64.Name); !on {
			return nil
		}
		return dnsModule.Ports(ctx, modules.IsRunning(dns64.Name))
	})
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
			if id := syncClient.AccountID(); id > 0 {
				return id
			}
			return int64(ipv64Key.Info(context.Background()).ID)
		},
		Checks: func() peer.Checks { // Abgleich der Checks nur bei laufendem Healthchecks-Modul
			if !modules.IsRunning(healthchecks.Name) {
				return nil
			}
			return hcModule
		},
		Linked: syncClient.Linked, HubNotifies: syncClient.ServerSends, SettingsToHub: syncClient.NotifySettingsChanged,
		Forward: func(ctx context.Context, entity, id, op string) { // Aenderung einer nicht verknuepften Node an den hub
			if f := hcModule.Store().OnChange; f != nil {
				f(context.WithoutCancel(ctx), entity, id, op)
			}
		},
		Hub: syncClient, // nicht verknuepfte Mitglieder als Stellvertreter-Nodes beim hub
		HTTPSPort: func() int { // Cluster nur HTTPS: HTTPS-Port, sonst der Web-Port (spricht auch TLS, dualport.go)
			if cfg.HTTPSPort > 0 {
				return cfg.HTTPSPort
			}
			return cfg.HTTPPort
		}})
	if err != nil {
		return err
	}
	hcModule.Store().OnAnyChange = peerMgr.LogChange
	hcModule.SetGroupRole(peerMgr.NotifyRole)
	hcModule.SetGroupDecides(peerMgr.GroupDecides)
	hcModule.SetGroupNotifier(peerMgr.NotifierOf)
	hcModule.SetGroupPeers(func(ctx context.Context) []healthchecks.Peer { // Nodes der lokalen Gruppe zur Auswahl
		list, _ := peerMgr.Members(ctx)
		out := make([]healthchecks.Peer, 0, len(list))
		for _, x := range list {
			out = append(out, healthchecks.Peer{ID: x.NodeID, Name: x.Name, Location: "LAN", Online: x.Online()})
		}
		return out
	})
	certcluster.Register(peerMgr, certMgr, func() string { return st.SettingOr(context.Background(), web.SettingNodeID, "") }) // Zertifikate ueber den Cluster
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
	hcModule.SetAccount(func() (string, int) { st := syncClient.State(); return st.Plan, st.OnlineLimit })
	hcModule.SetAPI(ipv64Key) // Online-Checks direkt ueber die API v2, solange kein Sync besteht
	hcModule.SetPushForward(syncClient.ForwardPush)
	hcModule.SetRunRemote(syncClient.RunRemote)
	hcModule.SetHubEvents(syncClient.HubEvents)
	hcModule.SetOnlineTest(syncClient.OnlineTest)
	netDone := make(chan struct{})
	// Datenverkehr des Containers fuer das Dashboard; vor dem Schliessen der Datenbank (defer weiter oben) die
	// letzte Summe schreiben lassen
	go func() { netstat.Loop(ctx, st); close(netDone) }()
	defer func() {
		select {
		case <-netDone:
		case <-time.After(3 * time.Second):
		}
	}()
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
		Ports: portReg, Edge: edgeSrv, Certs: certMgr, Box: box,
	})
	if err != nil {
		return err
	}
	err = srv.Run(ctx)
	log.Info("node64 stopped")
	return err
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
			// z. B. ein eigener Mount unter /data: den Ordner nicht loeschen, nur leeren. Kein Abbruch, sonst
			// startet die Node mit dem Merker immer wieder neu.
			if inner, rerr := os.ReadDir(p); rerr == nil {
				for _, x := range inner {
					if err := os.RemoveAll(filepath.Join(p, x.Name())); err != nil {
						log.Error("factory reset: could not delete", "path", filepath.Join(p, x.Name()), "err", err)
					}
				}
			} else {
				log.Error("factory reset: could not delete", "path", p, "err", err)
			}
		}
	}
	if err := os.Remove(filepath.Join(cfg.DataDir, web.ResetFileName)); err != nil {
		return err
	}
	log.Warn("factory reset: data directory cleared")
	return nil
}

// ensureTempDir: Das Image hat kein /tmp (FROM scratch). Ohne nutzbares Temp-Verzeichnis scheitern grosse
// Uploads (multipart) und SQLite-Zwischendateien; dann <DATA_DIR>/tmp nehmen (beim Start geleert).
func ensureTempDir(cfg *config.Config, log *slog.Logger) {
	if f, err := os.CreateTemp("", "probe-*"); err == nil {
		f.Close()
		os.Remove(f.Name())
		return
	}
	dir := filepath.Join(cfg.DataDir, "tmp")
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Warn("temp dir", "err", err)
		return
	}
	os.Setenv("TMPDIR", dir)
	os.Setenv("SQLITE_TMPDIR", dir)
}

// applyRestore setzt eine Wiederherstellung ein: ein Archiv (restore.new) oder eine hochgeladene Datenbank
// (node64.db.restore). Was ersetzt wird, bleibt vorher unter backups/ erhalten.
func applyRestore(cfg *config.Config, log *slog.Logger) error {
	if err := applyRestoreArchive(cfg, log); err != nil {
		return err
	}
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

// applyRestoreArchive setzt den Inhalt von restore.new ein (Datenbank, secret.key, Dateien der Module); ersetzte
// Dateien wandern nach backups/pre-restore-<Zeit>/.
func applyRestoreArchive(cfg *config.Config, log *slog.Logger) error {
	src := filepath.Join(cfg.DataDir, web.RestoreDirName)
	if st, err := os.Stat(src); err != nil || !st.IsDir() {
		return nil
	}
	keep := filepath.Join(cfg.BackupDir(), "pre-restore-"+time.Now().UTC().Format("20060102-150405"))
	n := 0
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		dst := filepath.Join(cfg.DataDir, rel)
		if _, err := os.Stat(dst); err == nil {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(keep, rel)), 0o750); err != nil {
				return err
			}
			if err := moveFile(dst, filepath.Join(keep, rel)); err != nil {
				return fmt.Errorf("keep %s: %w", rel, err)
			}
		}
		if strings.HasSuffix(dst, ".db") {
			for _, suffix := range []string{"-wal", "-shm"} {
				_ = os.Remove(dst + suffix)
			}
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o750); err != nil {
			return err
		}
		n++
		return moveFile(p, dst)
	})
	if err != nil {
		return fmt.Errorf("apply restore archive: %w", err)
	}
	if err := os.RemoveAll(src); err != nil {
		return err
	}
	log.Warn("backup archive restored", "files", n, "previous", keep)
	return nil
}

// moveFile verschiebt eine Datei; ueber Mount-Grenzen (eigener Mount unter /data) per Kopie.
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	in.Close()
	return os.Remove(src)
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
