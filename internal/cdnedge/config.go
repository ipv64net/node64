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
	Name       string `yaml:"name"`        // z. B. srv07
	Location   string `yaml:"location"`    // nbg | fsn
	PublicHost string `yaml:"public_host"` // srv07.cdn64.de
	ListenHTTP string `yaml:"listen_http"` // Standard :80
	DataDir    string `yaml:"data_dir"`    // Standard /var/lib/cdn64-edge
	LogLevel   string `yaml:"log_level"`   // debug | info | warn
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
	return c, nil
}
