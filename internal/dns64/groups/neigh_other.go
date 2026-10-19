//go:build !linux

package groups

import "net/netip"

// Neighbors gibt es nur unter Linux (Container); sonst bleibt die Zuordnung bei IP und Netz.
func Neighbors() (map[netip.Addr]string, error) { return nil, nil }
