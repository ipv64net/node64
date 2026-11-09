// Command monitor64-agent ist der Monitor64-Agent: eine eigenstaendige Datei, die per SSH (Port 6465) genau vier
// Anfragen der Node beantwortet (info, collect, update, keys). Plan docs/PLAN-NODE64-MONITOR64.md, Abschnitt
// "Monitor64-Agent". Er baut nur m64agent, m64proto und m64linux ein, damit die Datei klein bleibt.
//
//	monitor64-agent install --key "<pubkey>" [--port 6465]   Datei, Schluessel und systemd-Dienst anlegen
//	monitor64-agent uninstall                                 alles wieder entfernen
//	monitor64-agent run [--port 6465] [--keys ...]            im Vordergrund laufen (systemd ruft das auf)
//	monitor64-agent fingerprint                               Fingerabdruck des Hostschluessels
//	monitor64-agent version                                   Version
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
)

// Version wird beim Build gesetzt: -ldflags "-X main.Version=0.1.0"
var Version = "dev"

// ReleaseKeys sind die oeffentlichen Release-Schluessel fuer update (base64 ed25519, durch Komma getrennt), gesetzt
// beim Release-Build: -ldflags "-X main.ReleaseKeys=..." . Leer = update abgelehnt.
var ReleaseKeys = ""

// memLimit ist die weiche Speichergrenze, wenn GOMEMLIMIT nicht gesetzt ist (Ziel unter 15 MB).
const memLimit = 24 << 20

const usage = `usage: monitor64-agent <command>
  install --key "<public key>" [--port 6465]   install file, key and service, print the host key fingerprint
  uninstall                                     remove service, file and settings
  run [--port 6465] [--listen addr] [--dir path] run in the foreground
  fingerprint                                   print the host key fingerprint
  version                                       print the version`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	args := os.Args[2:]
	switch os.Args[1] {
	case "version", "-version", "--version":
		fmt.Println(m64agent.Name, Version, runtime.GOOS+"/"+runtime.GOARCH)
	case "run":
		os.Exit(run(args))
	case "install":
		os.Exit(install(args))
	case "uninstall":
		os.Exit(uninstall(args))
	case "fingerprint":
		os.Exit(fingerprint(args))
	case "help", "-h", "--help":
		fmt.Println(usage)
	default:
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
}

// runFlags sind die Einstellungen fuer run.
type runFlags struct {
	port     int
	listen   string
	dir      string
	keys     string
	hostKey  string
	localDir string
	maxConns int
	debug    bool
}

func parseRunFlags(args []string, errOut io.Writer) (runFlags, error) {
	var f runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.IntVar(&f.port, "port", m64proto.DefaultPort, "TCP port")
	fs.StringVar(&f.listen, "listen", "", "listen address (default: all)")
	fs.StringVar(&f.dir, "dir", defaultDir, "settings directory")
	fs.StringVar(&f.keys, "keys", "", "allowed keys (default: <dir>/keys)")
	fs.StringVar(&f.hostKey, "hostkey", "", "host key (default: <dir>/hostkey)")
	fs.StringVar(&f.localDir, "local", "", "local check scripts (default: <dir>/local.d)")
	fs.IntVar(&f.maxConns, "max-conns", m64agent.DefaultMaxConns, "maximum concurrent connections")
	fs.BoolVar(&f.debug, "debug", false, "debug log")
	if err := fs.Parse(args); err != nil {
		return f, err
	}
	if fs.NArg() > 0 {
		return f, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if f.port <= 0 || f.port > 65535 {
		return f, fmt.Errorf("invalid port %d", f.port)
	}
	if f.keys == "" {
		f.keys = filepath.Join(f.dir, "keys")
	}
	if f.hostKey == "" {
		f.hostKey = filepath.Join(f.dir, "hostkey")
	}
	if f.localDir == "" {
		f.localDir = filepath.Join(f.dir, "local.d")
	}
	return f, nil
}

// restartFn ersetzt den Prozess durch die Programmdatei (Tests setzen einen Ersatz).
var restartFn = restartSelf

// platformRun startet runAgent (Windows: als Dienst, siehe run_windows.go); baseContext endet, wenn der Agent
// aufhoeren soll (zusaetzlich zu Strg+C/SIGTERM; Windows: Stopp durch den Dienst-Manager).
var (
	platformRun = runAgent
	baseContext = context.Background
)

func run(args []string) int { return platformRun(selfPath(), args) }

func runAgent(exe string, args []string) int {
	// Rueckfall nach einem Update: kam die neue Version beim letzten Start nicht hoch, laeuft wieder die alte. Das
	// steht vor allem anderen (Flags, Release-Schluessel, Hostschluessel, Port): scheitert die neue Version schon
	// daran, ist ihr Start trotzdem gezaehlt und der naechste Start faellt zurueck.
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	pending := false
	if exe != "" {
		var rolledBack bool
		var err error
		pending, rolledBack, err = m64agent.UpdateStart(exe, Version)
		if err != nil {
			log.Warn("monitor64-agent: update check", "err", err)
		}
		if rolledBack {
			log.Warn("monitor64-agent: new version did not start properly - previous version restored", "failed", Version)
			if err := restartFn(exe); err != nil {
				log.Error("monitor64-agent: restart", "err", err)
				return 1
			}
		}
	}
	f, err := parseRunFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	if f.debug {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	relKeys, err := m64agent.ParseReleaseKeys(ReleaseKeys)
	if err != nil {
		log.Error("monitor64-agent: built-in release keys invalid", "err", err)
		return 1
	}
	hk, err := m64agent.LoadOrCreateHostKey(f.hostKey)
	if err != nil {
		log.Error("monitor64-agent: host key", "err", err)
		return 1
	}
	updated := make(chan string, 1)
	srv, err := m64agent.New(m64agent.Config{
		HostKey:     hk,
		KeysFile:    f.keys,
		LocalDir:    f.localDir,
		Collector:   newCollector(),
		Version:     Version,
		ReleaseKeys: relKeys,
		ExePath:     exe,
		Probe:       probe,
		OnUpdated: func(v string) {
			select {
			case updated <- v:
			default:
			}
		},
		MaxConns: f.maxConns,
		Logger:   log,
	})
	if err != nil {
		log.Error("monitor64-agent: start", "err", err)
		return 1
	}
	addr := net.JoinHostPort(f.listen, strconv.Itoa(f.port))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error("monitor64-agent: listen", "addr", addr, "err", err)
		return 1
	}
	log.Info("monitor64-agent: running", "version", Version, "addr", ln.Addr().String(),
		"fingerprint", m64agent.Fingerprint(hk.PublicKey()), "update", len(relKeys) > 0)
	var confirm *time.Timer
	if pending {
		confirm = time.AfterFunc(m64agent.HealthyAfter, func() {
			m64agent.ConfirmUpdate(exe, Version)
			log.Info("monitor64-agent: update confirmed", "version", Version)
		})
	}

	ctx, stop := signal.NotifyContext(baseContext(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	code := 0
	restart := ""
	select {
	case <-ctx.Done():
		log.Info("monitor64-agent: stopping")
		// Sauber beendet (nicht abgestuerzt): eine neue Version gilt damit als gestartet.
		if confirm != nil && confirm.Stop() {
			m64agent.ConfirmUpdate(exe, Version)
		}
	case v := <-updated:
		// Bestaetigung dieser (noch unbestaetigten) Version anhalten: der Merker gehoert jetzt der neuen Version
		// (ConfirmUpdate prueft zusaetzlich die Zielversion, falls der Timer schon laeuft).
		if confirm != nil {
			confirm.Stop()
		}
		// Antwort ist geschrieben; kurz warten, dann die neue Datei im selben Prozess starten (geht auch ohne
		// systemd; mit systemd bleibt Restart=always als Netz).
		log.Info("monitor64-agent: restarting after update", "version", v)
		time.Sleep(500 * time.Millisecond)
		restart = v
	case err := <-served:
		if !errors.Is(err, m64agent.ErrServerClosed) {
			log.Error("monitor64-agent: serve", "err", err)
			code = 1
		}
	}
	done := make(chan struct{})
	go func() { _ = srv.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	if restart != "" && exe != "" {
		_ = ln.Close()
		err := restartFn(exe)
		// Exec fehlgeschlagen: alte Datei zurueck und diese starten; geht auch das nicht, beenden (systemd startet neu).
		log.Error("monitor64-agent: starting the new version failed - restoring the previous one", "err", err)
		if rerr := m64agent.RollbackUpdate(exe, restart); rerr != nil {
			log.Error("monitor64-agent: rollback", "err", rerr)
			return 1
		}
		if err := restartFn(exe); err != nil {
			log.Error("monitor64-agent: restart", "err", err)
			return 1
		}
	}
	return code
}

// selfPath liefert die eigene Programmdatei ohne Symlinks ("" wenn unbekannt).
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return ""
	}
	return exe
}

// probe startet die neue Datei probeweise ("version") und prueft, dass sie die erwartete Version meldet.
func probe(exe, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, exe, "version").Output()
	if err != nil {
		return err
	}
	if f := bytes.Fields(out); len(f) < 2 || strings.TrimPrefix(string(f[1]), "v") != strings.TrimPrefix(version, "v") {
		return fmt.Errorf("reports %q instead of version %s", bytes.TrimSpace(out), version)
	}
	return nil
}

func fingerprint(args []string) int {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	dir := fs.String("dir", defaultDir, "settings directory")
	hostKey := fs.String("hostkey", "", "host key (default: <dir>/hostkey)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p := *hostKey
	if p == "" {
		p = filepath.Join(*dir, "hostkey")
	}
	fp, err := m64agent.ReadHostKeyFingerprint(p)
	if err != nil {
		fmt.Fprintln(os.Stderr, "monitor64-agent:", err)
		return 1
	}
	fmt.Println(fp)
	return 0
}
