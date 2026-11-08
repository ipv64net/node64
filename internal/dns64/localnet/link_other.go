//go:build !linux

package localnet

// linkKinds: ausserhalb von Linux unbekannt (bisherige Erkennung).
func linkKinds() map[string]string { return nil }
