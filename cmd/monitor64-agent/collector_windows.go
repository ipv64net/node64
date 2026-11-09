//go:build windows

package main

import (
	"context"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/m64win"
)

// windowsCollector liest die Werte ueber m64win (eigener Puffer fuer SMART/Storage Spaces/Updates).
type windowsCollector struct{ cache *m64win.Cache }

func newCollector() m64agent.Collector { return &windowsCollector{cache: m64win.NewCache()} }

func (c *windowsCollector) Collect(ctx context.Context, sections []string) *m64proto.Report {
	return m64win.Collect(ctx, m64win.Options{Sections: sections, Cache: c.cache})
}

func (c *windowsCollector) Caps() []string {
	return m64win.Caps(m64win.Options{Cache: c.cache})
}
