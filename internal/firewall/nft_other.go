//go:build !linux

package firewall

import "errors"

// nftables gibt es nur unter Linux (Entwicklung unter Windows/macOS: Fehler beim Start).
func newNFT() (Backend, error) {
	return nil, errors.New("firewall helper (nftables) only works on Linux")
}
