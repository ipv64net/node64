//go:build freebsd

package main

import (
	"context"

	"github.com/ipv64net/node64/internal/m64agent"
	"github.com/ipv64net/node64/internal/m64bsd"
	"github.com/ipv64net/node64/internal/m64proto"
)

// bsdCollector liest die Werte ueber m64bsd (eigener Puffer fuer SMART/Updates/Neustart).
type bsdCollector struct{ cache *m64bsd.Cache }

func newCollector() m64agent.Collector { return &bsdCollector{cache: m64bsd.NewCache()} }

func (c *bsdCollector) Collect(ctx context.Context, sections []string) *m64proto.Report {
	return m64bsd.Collect(ctx, m64bsd.Options{Sections: sections, Cache: c.cache})
}

func (c *bsdCollector) Caps() []string {
	return m64bsd.Caps(m64bsd.Options{Cache: c.cache})
}
