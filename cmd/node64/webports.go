package main

import (
	"context"
	"log/slog"

	"github.com/ipv64net/node64/internal/config"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/web"
)

// applyWebPorts: in der Oberflaeche eingestellte Ports (Einstellungen > Allgemein > Erreichbarkeit) gelten vor
// NODE64_HTTP_PORT/NODE64_HTTPS_PORT. Sind sie ungueltig oder laesst sich einer nicht oeffnen, bleibt es bei der
// Umgebung (sonst waere die Oberflaeche nach einem Neustart weg). Die wirksamen Ports landen fuer
// "node64 healthcheck" in <data>/web-ports.
func applyWebPorts(ctx context.Context, cfg *config.Config, st *store.Store, log *slog.Logger) {
	h, hs, set := web.WebPorts(ctx, st, cfg.EnvHTTPPort, cfg.EnvHTTPSPort)
	if set && (h != cfg.HTTPPort || hs != cfg.HTTPSPort) {
		err := config.CheckWebPorts(h, hs)
		for _, p := range []int{h, hs} {
			if err == nil && p > 0 {
				err = ports.Probe(ports.TCP, cfg.BindAddr, p)
			}
		}
		if err != nil {
			log.Error("web ports from settings not usable, using NODE64_HTTP_PORT/NODE64_HTTPS_PORT", "http", h, "https", hs, "err", err)
		} else {
			cfg.HTTPPort, cfg.HTTPSPort = h, hs
			log.Info("web ports from settings", "http", h, "https", hs)
		}
	}
	if err := cfg.WritePortsFile(); err != nil {
		log.Warn("web ports file not written", "err", err)
	}
}
