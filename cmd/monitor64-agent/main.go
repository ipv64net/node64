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
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
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

func run(args []string) int {
	f, err := parseRunFlags(args, os.Stderr)
	if err != nil {
		return 2
	}
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	lvl := slog.LevelInfo
	if f.debug {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	code := 0
	select {
	case <-ctx.Done():
		log.Info("monitor64-agent: stopping")
	case v := <-updated:
		// Antwort ist geschrieben; kurz warten, dann beenden - systemd startet die neue Datei (Restart=always).
		log.Info("monitor64-agent: exiting for restart after update", "version", v)
		time.Sleep(500 * time.Millisecond)
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
	return code
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
