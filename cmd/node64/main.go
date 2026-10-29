// Node64: ein Binary mit Weboberflaeche, SQLite und Modulen.
//
// Befehle:
//
//	node              startet den Node
//	node healthcheck  prueft die lokale UI (fuer Docker HEALTHCHECK), Exit 0 = gesund
//	                  (NODE64_MODE=honeypot: /health des Info-Ports, honeypot_mode.go)
//	node version      zeigt die Version
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	_ "time/tzdata" // Zeitzonen im Binary, das Laufzeit-Image hat keine

	"github.com/ipv64net/node64/internal/caps"
	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/certs/certcluster"
	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/dns64/dns64cluster"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/dyndns/ddcluster"
	"github.com/ipv64net/node64/internal/edge"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/healthchecks/hccluster"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/ipv64api"
	"github.com/ipv64net/node64/internal/logging"
	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/nodecfg"
	"github.com/ipv64net/node64/internal/nodecfg/nodecluster"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/notify/nfcluster"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/secrets"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/sonar64"
	"github.com/ipv64net/node64/internal/store"
	nodesync "github.com/ipv64net/node64/internal/sync"
	"github.com/ipv64net/node64/internal/usercluster"
	"github.com/ipv64net/node64/internal/web"
)

// Version wird beim Build gesetzt: -ldflags "-X main.Version=1.2.3"
var Version = "dev"

// sonar64Enabled: Sonar64 ist vorerst pausiert (Code bleibt, Modul nicht registriert). Fuer eigene Builds auf true setzen.
const sonar64Enabled = false

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
	err := run()
	if restartAfterStop.Load() { // Selbst-Update: sauber beendet, jetzt in-place neu (der Starter waehlt die Version)
		if rerr := selfupdate.Reexec(); rerr != nil {
			fmt.Fprintln(os.Stderr, "node: restart after update:", rerr)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "node:", err)
		os.Exit(1)
	}
}

// restartAfterStop: run endete fuer einen Neustart (Selbst-Update).
var restartAfterStop atomic.Bool

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	selfupdate.Launch(cfg.DataDir, Version)                              // neuere geprueft abgelegte Version starten (exec), sonst weiter
	if mode := strings.TrimSpace(os.Getenv("NODE64_MODE")); mode != "" { // z. B. honeypot: ohne Oberflaeche (honeypot_mode.go)
		return runMode(cfg, mode)
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
	hcModule.SetSecrets(box) // Proxmox VE: Token-Secrets verschluesselt
	modules.Register(hcModule)
	ipv64Key := ipv64api.NewKey(st, box, ipv64api.NewClient(os.Getenv("NODE64_IPV64_API"), "node64/"+Version), logger.Slog()) // leer = ipv64.net (Env nur fuer Tests)
	ipv64Key.Client().SetNodeID(func() string { return st.SettingOr(context.Background(), web.SettingNodeID, "") })           // X-Node64-Node

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
	// Knopf "lokal in DNS64 eintragen" in der Host-Liste
	cdnModule.SetLocalDNS(func() cdn64.LocalDNS {
		if !modules.IsRunning(dns64.Name) {
			return nil
		}
		return dnsLocal{dnsModule}
	})
	cdnModule.SetStatusPages(statusPages{hc: hcModule, on: func() bool { return modules.IsRunning(healthchecks.Name) }}) // Hostart "Statusseite"
	portReg.Provide(cdn64.Name, cdnModule.Claims)
	portReg.ProvideOutbound(cdn64.Name, cdnModule.OutboundClaims) // Tunnel CDN64 online (ausgehend, nur Anzeige)
	modules.Register(cdnModule)
	portReg.Provide(dns64.Name, func(ctx context.Context) []ports.Claim { // nur eingeschaltet; aktiv, solange es laeuft
		if on, _ := st.ModuleEnabled(ctx, dns64.Name); !on {
			return nil
		}
		return dnsModule.Ports(ctx, modules.IsRunning(dns64.Name))
	})
	hpModule := honeypot.New(st, logger.Slog(), cfg.DataDir, Version) // Honeypot64 als Modul (standardmaessig aus)
	hpModule.SetPorts(portReg)                                        // Fallen-Dienste pruefen ihre Ports
	hpModule.SetNotifier(dispatcher.Dispatch)                         // neue Angreifer (gebuendelt, hoechstens stuendlich)
	hpModule.SetKey(ipv64Key)                                         // Meldung an ipv64 (Opt-in) mit dem zentralen API-Key
	hpModule.SetCerts(certMgr)                                        // gueltige Zertifikate fuer Koeder-Namen (optional)
	portReg.Provide(honeypot.Name, hpModule.Claims)
	modules.Register(hpModule)
	if sonar64Enabled { // Sonar64 pausiert (Dennis, 2026-10-28): ohne Registrierung unsichtbar und nicht einschaltbar
		s64Module := sonar64.New(st, logger.Slog(), box, cfg.DataDir, Version) // Sonar64 als Modul (standardmaessig aus, Teilnahme per Opt-in)
		s64Module.SetKey(ipv64Key)                                             // Teilnahme legt mit dem zentralen API-Key ein Sonar-Token an
		s64Module.SetPorts(portReg)                                            // UDP 6464 nur bei "auch gemessen"
		portReg.Provide(sonar64.Name, s64Module.Claims)
		modules.Register(s64Module)
	}
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
		},
		DirectNotify: ipv64Key.APIReady, // Meldungen der nur hier gemessenen Checks ueber die API v2 statt ueber den hub
	})
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
		Notify: dispatcher.Dispatch, // Node des Clusters nicht erreichbar / wieder da
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
	dns64cluster.Register(peerMgr, dnsModule)                                                                                  // DNS64 ueber den Cluster
	hccluster.Register(peerMgr, hcModule)                                                                                      // Proxmox VE, Docker und Statusseiten ueber den Cluster
	nfcluster.Register(peerMgr, nfStore)                                                                                       // Benachrichtigungskanaele ueber den Cluster
	nodecluster.Register(peerMgr, nodecfg.New(nodecfg.Deps{Store: st, Box: box, Key: ipv64Key, Account: peerMgr.Account, ClusterAccount: peerMgr.ClusterAccount, Log: logger.Slog().With("module", "peer")}),
		func() string { return st.SettingOr(context.Background(), web.SettingNodeID, "") }) // API-Key und allgemeine Einstellungen ueber den Cluster
	userCluster := usercluster.New(st, box, logger.Slog().With("module", "peer"))
	usercluster.Register(peerMgr, userCluster)                                                                                 // Benutzer und SSO-Einrichtung ueber den Cluster
	ddcluster.Register(peerMgr, dynModule, func() string { return st.SettingOr(context.Background(), web.SettingNodeID, "") }) // DynDNS ueber den Cluster
	go peerMgr.Run(ctx)
	dispatcher.SetSendServerChannels(st.SettingOr(ctx, nodesync.SetLocalNotif, "0") == "1")
	dispatcher.SetServerSends(syncClient.ServerSends)
	dispatcher.SetHubDirect(syncClient.HubDirect) // nur hier gemessene Checks: ipv64-Kanaele und eigene Kanaele selbst
	// Meldungen der Module (z. B. DynDNS) ueber ipv64-Mail/-SMS direkt per API, ohne hub; ohne Verknuepfung die Kanaele des Accounts
	dispatcher.SetAPISender(ipv64Key.SendNotification, ipv64Key.APIReady)
	dispatcher.SetLinked(syncClient.Linked) // ohne Verknuepfung auch Healthchecks ueber die API
	dispatcher.SetRemoteChannels(func(ctx context.Context) []*notify.Channel {
		if syncClient.Linked() {
			return nil // verknuepft: die Server-Kanaele kommen als Platzhalter ueber den Sync
		}
		return ipv64Key.RemoteChannels(ctx)
	})
	hcModule.SetLinked(syncClient.Linked)
	viaCluster := func() bool { // nicht verknuepft: eine verknuepfte Node des Clusters reicht weiter
		if syncClient.Linked() {
			return false
		}
		id, _, self := peerMgr.Forwarder(context.Background())
		return id != "" && !self
	}
	hcModule.SetViaCluster(viaCluster)
	// Grenzen des Accounts: verknuepft aus dem Sync, ueber den Cluster aus der API v2 (GET /hc2/account mit dem
	// API-Key); ohne lesbare Grenzen meldet account() keinen Tarif und Online-Checks werden nicht angelegt
	hcModule.SetQuota(func() (int, int, int) {
		if !syncClient.Linked() && viaCluster() {
			if l, ok := ipv64Key.HCLimits(context.Background()); ok {
				return l.ChecksToday, l.ChecksPerDay, l.Locations
			}
		}
		return syncClient.Quota()
	})
	hcModule.SetAccount(func() (string, int) {
		if !syncClient.Linked() && viaCluster() {
			if l, ok := ipv64Key.HCLimits(context.Background()); ok {
				return l.Plan, l.OnlinePoints
			}
			return "", 0
		}
		st := syncClient.State()
		return st.Plan, st.OnlineLimit
	})
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
	// Selbst-Update: stuendlich pruefen (Einstellung), Rueckfall bzw. Erfolg melden
	upd := selfupdate.New(cfg.DataDir, Version)
	upd.Backup = st.Backup
	upd.Restart = func() { restartAfterStop.Store(true); stop() }
	getSetting := func(k, d string) string { return st.SettingOr(ctx, k, d) }
	nodeLoc := func() *time.Location {
		if loc, err := time.LoadLocation(st.SettingOr(ctx, "node.timezone", "")); err == nil && st.SettingOr(ctx, "node.timezone", "") != "" {
			return loc
		}
		return time.Local
	}
	go upd.Loop(ctx, getSetting, func(k, v string) error { return st.SetSetting(ctx, k, v) }, nodeLoc, logger.Slog().With("module", "update"))
	go selfupdate.Watch(ctx, cfg.DataDir, Version, func(e selfupdate.Event) {
		kind, data := notify.KindUpdateFailed, map[string]string{"text": "notify.text.update_failed", "version": e.Version, "back": e.Other}
		if e.OK {
			kind, data = notify.KindUpdateOK, map[string]string{"text": "notify.text.update_ok", "version": e.Version, "from": e.Other}
		}
		now := time.Now().UTC()
		log.Info("self-update", "ok", e.OK, "version", e.Version, "other", e.Other)
		dispatcher.Dispatch(notify.Alert{EventID: "update-" + string(kind) + "-" + strconv.FormatInt(now.UnixNano(), 36), Kind: kind, Time: now,
			Check: notify.CheckInfo{Name: e.Version, NotifyDown: true, NotifyUp: true, Local: true}, Data: data})
	})
	go planLoop(ctx, ipv64Key, syncClient)
	// Node-Uebersicht auf ipv64.net: anmelden; dort entfernt = Key und Verknuepfung lokal vergessen
	go ipv64api.NewPresence(ipv64api.PresenceConfig{Client: ipv64Key.Client(), Key: ipv64Key.Get, Log: logger.Slog().With("module", "ipv64"),
		Info:    func(ctx context.Context) ipv64api.Hello { return nodeHello(ctx, st, modules, syncClient.Linked) },
		Removed: func(ctx context.Context) bool { return !ipv64Key.Removed(ctx).IsZero() },
		OnRemoved: func(ctx context.Context) {
			if err := ipv64Key.MarkRemoved(ctx); err != nil {
				log.Error("node removed: api key not cleared", "err", err)
			}
			if err := syncClient.Forget(ctx); err != nil {
				log.Error("node removed: healthchecks link not cleared", "err", err)
			}
		}}).Run(ctx)

	srv, err := web.New(web.Deps{
		Cfg: cfg, Store: st, Log: logger, I18n: bundle, Modules: modules, Notify: nfStore, Dispatcher: dispatcher,
		Sync: syncClient, Linker: syncClient, HC: hcModule, IPv64: ipv64Key, Peer: peerMgr, Version: Version, StartedAt: time.Now(), Restart: stop,
		Ports: portReg, Edge: edgeSrv, Certs: certMgr, Box: box, Updater: upd,
		Users: userCluster,
	})
	if err != nil {
		return err
	}
	srv.SetLoginWatcher(hpModule) // Fehlversuche an der Anmeldung (Honeypot64, Regel node64/login@1; nur wenn das Modul laeuft)
	err = srv.Run(ctx)
	log.Info("node64 stopped")
	return err
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
	defer pruneRestoreBackups(cfg, keepRestoreBackups)
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

// keepRestoreBackups: so viele Staende vor einer Wiederherstellung bleiben unter backups/ (je Art: Datenbank bzw.
// Archiv), aeltere werden geloescht – wie die Backups vor Migrationen (store.BackupBeforeMigration).
const keepRestoreBackups = 5

// pruneRestoreBackups loescht aeltere Staende vor einer Wiederherstellung (node64-<Zeit>-pre-restore.db und
// pre-restore-<Zeit>/); die Namen sortieren nach der Zeit.
func pruneRestoreBackups(cfg *config.Config, keep int) {
	entries, err := os.ReadDir(cfg.BackupDir())
	if err != nil {
		return
	}
	var files, dirs []string
	for _, e := range entries {
		switch {
		case !e.IsDir() && strings.HasPrefix(e.Name(), "node64-") && strings.HasSuffix(e.Name(), "-pre-restore.db"):
			files = append(files, e.Name())
		case e.IsDir() && strings.HasPrefix(e.Name(), "pre-restore-"):
			dirs = append(dirs, e.Name())
		}
	}
	for _, list := range [][]string{files, dirs} {
		sort.Strings(list)
		for len(list) > keep {
			_ = os.RemoveAll(filepath.Join(cfg.BackupDir(), list[0]))
			list = list[1:]
		}
	}
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
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if top, _, _ := strings.Cut(filepath.ToSlash(rel), "/"); top == "bin" { // Programme des Selbst-Updates nie aus einem Archiv (der Starter fuehrt sie aus)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
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
	if isHoneypotMode() { // ohne Oberflaeche: /health des Info-Ports
		return honeypotHealthcheck(cfg)
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

// statusPages gibt PROXY64 die Statusseiten der Healthchecks (Hostart "status"); Healthchecks aus -> nil.
type statusPages struct {
	hc *healthchecks.Module
	on func() bool
}

func (s statusPages) StatusSite(id int64) http.Handler {
	if !s.on() {
		return nil
	}
	return s.hc.StatusSite(id)
}

func (s statusPages) StatusPageList(ctx context.Context) []cdn64.StatusPageInfo {
	if !s.on() {
		return nil
	}
	refs := s.hc.StatusPageRefs(ctx)
	out := make([]cdn64.StatusPageInfo, 0, len(refs))
	for _, p := range refs {
		out = append(out, cdn64.StatusPageInfo{ID: p.ID, Slug: p.Slug, Title: p.Title, Enabled: p.Enabled})
	}
	return out
}

// planLoop schaut regelmaessig nach der Account-Klasse: nach einem Upgrade gelten Klasse und Limits nach wenigen
// Minuten (Seitenleiste, Tarife, Healthchecks-Limits vom hub), nicht erst nach einem Tag.
func planLoop(ctx context.Context, key *ipv64api.Key, sc *nodesync.Live) {
	t := time.NewTicker(ipv64api.PlanEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		if key.RefreshPlan(cctx) {
			sc.RefreshAccount(cctx)
		}
		cancel()
	}
}

// dnsLocal: eigene DNS64-Eintraege fuer PROXY64 (lokaler Zugriff auf die Namen eines Hosts).
type dnsLocal struct{ m *dns64.Module }

func (d dnsLocal) Records(ctx context.Context) ([]cdn64.LocalRecord, error) {
	list, err := d.m.Records(ctx)
	out := make([]cdn64.LocalRecord, 0, len(list))
	for _, r := range list {
		out = append(out, cdn64.LocalRecord{Name: r.Name, Type: r.Type, Value: r.Value, Enabled: r.Enabled})
	}
	return out, err
}

func (d dnsLocal) Add(ctx context.Context, r cdn64.LocalRecord, comment string) error {
	// NoPTR: die Rueckwaertssuche der Proxy-Adresse liefert weiter den Namen des Geraets, nicht einen der Hosts
	_, err := d.m.AddRecord(ctx, dns64.Record{Name: r.Name, Type: r.Type, Value: r.Value, Comment: comment, NoPTR: true})
	return err
}
