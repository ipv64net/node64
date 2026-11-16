//go:build linux

package main

import (
	"context"
	"path/filepath"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64linux"
	"github.com/ipv64net/node64/internal/m64proto"
)

// linuxCollector liest die Werte ueber m64linux (eigener Puffer fuer SMART/Updates).
type linuxCollector struct{ cache *m64linux.Cache }

func newCollector() m64agent.Collector { return &linuxCollector{cache: m64linux.NewCache()} }

func (c *linuxCollector) Collect(ctx context.Context, sections []string) *m64proto.Report {
	// dnf-Logs in den eigenen Ordner: /var/log ist unter ProtectSystem=strict schreibgeschuetzt (#169) - wirkt auch
	// bei bestehenden Installationen, deren Unit der Agent selbst nicht aendern darf
	return m64linux.Collect(ctx, m64linux.Options{Sections: sections, Cache: c.cache, PkgLogDir: filepath.Join(stateDir, "dnf")})
}

func (c *linuxCollector) Caps() []string {
	return m64linux.Caps(m64linux.Options{Cache: c.cache})
}
