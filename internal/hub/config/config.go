// Package config liest /etc/ipv64-hub/config.yaml.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ipv64net/node64/internal/hub/ops"
	"gopkg.in/yaml.v3"
)

// Config ist die Konfiguration einer hub-Instanz. Geheimnisse stehen nur hier.
type Config struct {
	NodeName   string   `yaml:"node_name"`
	Location   string   `yaml:"location"`    // nbg, fsn, ...
	PublicHost string   `yaml:"public_host"` // hc-srv01.ipv64.net
	Listen     string   `yaml:"listen"`      // 127.0.0.1:9000
	Roles      []string `yaml:"roles"`       // checker, gateway
	MySQL      struct {
		DSN string `yaml:"dsn"`
	} `yaml:"mysql"`
	Redis struct {
		Addr     string `yaml:"addr"`
		Password string `yaml:"password"`
	} `yaml:"redis"`
	SecretKeyFile string `yaml:"secret_key_file"`
	Bridge        struct {
		URL        string `yaml:"url"`         // https://ipv64.net/hc2_send.php
		SecretFile string `yaml:"secret_file"` // /etc/ipv64-hub/bridge.secret
	} `yaml:"bridge"`
	Limits struct {
		MaxConnections int      `yaml:"max_connections"`
		CheckerWorkers int      `yaml:"checker_workers"`
		TrustedIPs     []string `yaml:"trusted_ips"` // ohne IP-Ratenlimit (z. B. Lasttest-Quelle); leer im Normalbetrieb
	} `yaml:"limits"`
	LogLevel string     `yaml:"log_level"` // debug, info, warn, error
	Ops      ops.Config `yaml:"ops"`       // Betriebsalarme an den Betreiber (andere hubs, Datenbank)
}

// Load liest und prueft die Datei.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.NodeName == "" {
		c.NodeName, _ = os.Hostname()
	}
	if c.Location == "" {
		return nil, errors.New("config: location fehlt")
	}
	if c.MySQL.DSN == "" {
		return nil, errors.New("config: mysql.dsn fehlt")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:9000"
	}
	if len(c.Roles) == 0 {
		c.Roles = []string{"checker", "gateway"}
	}
	if c.Limits.CheckerWorkers <= 0 {
		c.Limits.CheckerWorkers = 200
	}
	if c.Limits.MaxConnections <= 0 {
		c.Limits.MaxConnections = 20000
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	return &c, nil
}

// HasRole sagt, ob die Rolle aktiv ist.
func (c *Config) HasRole(r string) bool {
	for _, x := range c.Roles {
		if strings.EqualFold(x, r) {
			return true
		}
	}
	return false
}
