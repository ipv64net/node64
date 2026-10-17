// Package cdnedge ist der Dienst auf den CDN64-Servern (srv07/srv08.cdn64.de): Eingang fuer Besucher, Ende der
// Tunnels der Nodes, Konfiguration von ipv64. Planung: docs/CDN64-ONLINE.md.
package cdnedge

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config steht in /etc/cdn64-edge/config.yaml (root:cdn64-edge 640). Geheimnisse nur dort, nie im Repo.
type Config struct {
	Name         string        `yaml:"name"`          // z. B. srv07
	Location     string        `yaml:"location"`      // nbg | fsn
	PublicHost   string        `yaml:"public_host"`   // srv07.cdn64.de (Zertifikat fuer den Tunnel)
	ListenHTTP   string        `yaml:"listen_http"`   // Standard :80
	TunnelListen string        `yaml:"tunnel_listen"` // UDP (QUIC) und TCP (Ausweichweg), z. B. :7844; leer = aus
	TLSCert      string        `yaml:"tls_cert"`      // fester Schluessel (Tests); leer = Let's Encrypt fuer public_host
	TLSKey       string        `yaml:"tls_key"`
	DataDir      string        `yaml:"data_dir"`     // Standard /var/lib/cdn64-edge
	LogLevel     string        `yaml:"log_level"`    // debug | info | warn
	Tunnels      []TunnelEntry `yaml:"tunnels"`      // T1: feste Testkonfiguration; ab T3 von ipv64
	DebugListen  string        `yaml:"debug_listen"` // T1: nur lokal, je Verbindung ein Stream "http80" in DebugTunnel
	DebugTunnel  string        `yaml:"debug_tunnel"`
}

// TunnelEntry: erlaubter Tunnel (Token nur als SHA-256 in Hex).
type TunnelEntry struct {
	ID          string `yaml:"id"`
	TokenSHA256 string `yaml:"token_sha256"`
}

// LoadConfig liest die Datei und setzt Standardwerte.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.ListenHTTP == "" {
		c.ListenHTTP = ":80"
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/cdn64-edge"
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return nil, errors.New("config: name fehlt")
	}
	if c.TunnelListen != "" && c.TLSCert == "" && c.PublicHost == "" {
		return nil, errors.New("config: public_host fehlt (Zertifikat fuer den Tunnel)")
	}
	if strings.HasPrefix(c.DebugListen, ":") || strings.HasPrefix(c.DebugListen, "0.0.0.0") || strings.HasPrefix(c.DebugListen, "[::]") {
		return nil, errors.New("config: debug_listen nur auf 127.0.0.1")
	}
	return c, nil
}
