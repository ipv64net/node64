// cdn64-edge: Dienst auf den CDN64-Servern (srv07/srv08.cdn64.de). Planung: docs/CDN64-ONLINE.md.
//
//	cdn64-edge -config /etc/cdn64-edge/config.yaml
//	cdn64-edge -version
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

	"github.com/ipv64net/node64/internal/cdnedge"
)

// Version wird beim Build gesetzt.
var Version = "dev"

func main() {
	cfgPath := flag.String("config", "/etc/cdn64-edge/config.yaml", "Konfigurationsdatei")
	showVersion := flag.Bool("version", false, "Version ausgeben")
	flag.Parse()
	if *showVersion {
		fmt.Println("cdn64-edge", Version)
		return
	}
	if err := run(*cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run(cfgPath string) error {
	cfg, err := cdnedge.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return cdnedge.New(cfg, log, Version).Run(ctx)
}
