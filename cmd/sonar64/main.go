// Command sonar64 ist der eigenstaendige Sonar64-Knoten ohne Dashboard (Pi Zero, MikroTik-Container, beliebiger
// Linux-Rechner) und zugleich der Anker (Vertrag docs/SONAR64-VERTRAG.md, Abschnitt 8; Anleitung docs/SONAR64.md).
// Er baut nur den Kern internal/sonar ein, damit die Datei klein bleibt.
//
//	sonar64              Knoten starten (Einstellung ueber SONAR64_*-Umgebungsvariablen)
//	sonar64 healthcheck  prueft den Mini-Status (fuer Docker HEALTHCHECK), Exit 0 = gesund
//	sonar64 version      zeigt die Version
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	_ "time/tzdata" // Ruhezeit in lokaler Zeit auch im leeren Image (TZ=Europe/Berlin)

	"github.com/ipv64net/node64/internal/sonar"
)

// Version wird beim Build gesetzt: -ldflags "-X main.Version=1.2.3"
var Version = "dev"

// memLimit ist die weiche Speichergrenze, wenn GOMEMLIMIT nicht gesetzt ist (Pi Zero, MikroTik).
const memLimit = 40 << 20

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("sonar64", Version)
			return
		case "healthcheck":
			os.Exit(healthcheck(os.Getenv))
		default:
			fmt.Fprintln(os.Stderr, "usage: sonar64 [version|healthcheck]  (settings via SONAR64_* environment, see docs/SONAR64.md)")
			os.Exit(2)
		}
	}
	os.Exit(run())
}

func run() int {
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(memLimit)
	}
	opt, err := loadEnv(os.Getenv)
	log := newLogger(opt.LogLevel)
	slog.SetDefault(log)
	if err != nil {
		log.Error("sonar64: invalid settings", "err", err)
		return 2
	}
	for _, w := range opt.Warnings {
		log.Warn("sonar64: " + w)
	}
	if raised, err := raiseNetRaw(); err != nil {
		log.Debug("sonar64: capabilities not raised", "err", err)
	} else if raised {
		log.Debug("sonar64: cap_net_raw active")
	}
	if os.Geteuid() == 0 {
		log.Warn("sonar64: running as root - a dedicated user with cap_net_raw is enough")
	}
	if err := prepareDataDir(opt.Config.DataDir); err != nil {
		log.Error("sonar64: data directory not usable", "dir", opt.Config.DataDir, "err", err)
		return 1
	}

	cfg := opt.Config
	cfg.Version = Version
	cfg.Log = log
	r, err := sonar.New(cfg)
	if err != nil {
		log.Error("sonar64: start failed", "err", err)
		return 1
	}
	log.Info("sonar64 starting", "version", Version, "mode", cfg.Mode, "measured", cfg.Measured,
		"budget", cfg.Budget, "data", cfg.DataDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var running atomic.Bool
	running.Store(true)
	if opt.StatusAddr != "" {
		srv := newStatusServer(opt.StatusAddr, r, running.Load)
		go func() {
			log.Info("sonar64: mini status", "addr", opt.StatusAddr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("sonar64: mini status failed", "err", err)
			}
		}()
		defer func() {
			sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(sctx)
		}()
	}

	err = r.Run(ctx)
	running.Store(false)
	if ctx.Err() != nil {
		log.Info("sonar64 stopped")
		return 0
	}
	if err == nil {
		err = errors.New("runner ended")
	}
	log.Error("sonar64: runner failed", "err", err)
	return 1
}

// newLogger schreibt Textzeilen auf stderr (journald, docker logs).
func newLogger(level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

// prepareDataDir legt den Datenordner an (0700) und prueft, ob er beschreibbar ist.
func prepareDataDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}
