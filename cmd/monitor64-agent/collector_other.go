//go:build !linux

package main

import "github.com/ipv64net/node64/internal/m64agent"

// newCollector: ausserhalb von Linux noch keine Werte (Windows folgt in Phase 2).
func newCollector() m64agent.Collector { return nil }
