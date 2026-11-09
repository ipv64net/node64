//go:build !linux && !windows && !freebsd

package main

import "github.com/ipv64net/node64/internal/m64agent"

// newCollector: ausserhalb von Linux und Windows noch keine Werte (FreeBSD folgt).
func newCollector() m64agent.Collector { return nil }
