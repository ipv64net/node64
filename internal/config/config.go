// Package config liest die Konfiguration des Nodes aus Umgebungsvariablen.
//
// Alle Variablen beginnen mit NODE64_. Werte, die der Nutzer spaeter im UI
// aendert (Name, Standort, Sprache, Log-Level), liegen in der Datenbank;
// die Umgebung liefert nur das, was vor dem Start feststehen muss.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	// DataDir ist das einzige beschreibbare Verzeichnis (Volume /data).
	DataDir string
	// HTTPPort fuer die lokale Oberflaeche, 0 = aus.
	HTTPPort int
	// HTTPSPort fuer die lokale Oberflaeche mit TLS, 0 = aus.
	HTTPSPort int
	// EnvHTTPPort / EnvHTTPSPort: Ports aus der Umgebung; HTTPPort/HTTPSPort koennen davon abweichen, wenn sie in
	// der Oberflaeche eingestellt sind (Einstellungen > Allgemein > Erreichbarkeit).
	EnvHTTPPort, EnvHTTPSPort int
	// Bind-Adresse, leer = alle Interfaces.
	BindAddr string
	// LogLevel beim Start: debug, info, warn, error.
	LogLevel string
	// LogFormat: text oder json.
	LogFormat string
	// AdminUser / AdminPassword werden nur beim allerersten Start verwendet,
	// solange noch kein Benutzer existiert. Danach werden sie ignoriert.
	AdminUser     string
	AdminPassword string
	// TLSCertFile / TLSKeyFile: eigenes Zertifikat. Leer = selbstsigniertes
	// Zertifikat unter DataDir/tls, das beim ersten Start erzeugt wird.
	TLSCertFile string
	TLSKeyFile  string
	// TrustProxyHeaders: X-Forwarded-For auswerten (nur hinter eigenem Reverse Proxy).
	TrustProxyHeaders bool
}

func (c *Config) DBPath() string        { return filepath.Join(c.DataDir, "node64.db") }
func (c *Config) BackupDir() string     { return filepath.Join(c.DataDir, "backups") }
func (c *Config) TLSDir() string        { return filepath.Join(c.DataDir, "tls") }
func (c *Config) SecretKeyPath() string { return filepath.Join(c.DataDir, "secret.key") }

// PortsFile: wirksame Ports der Oberflaeche fuer "node64 healthcheck" (schreibt der laufende Node beim Start).
func (c *Config) PortsFile() string { return filepath.Join(c.DataDir, "web-ports") }

// Load liest die Umgebung und prueft die Werte.
func Load() (*Config, error) {
	c := &Config{
		DataDir:           env("NODE64_DATA_DIR", "/data"),
		BindAddr:          env("NODE64_BIND_ADDR", ""),
		LogLevel:          strings.ToLower(env("NODE64_LOG_LEVEL", "info")),
		LogFormat:         strings.ToLower(env("NODE64_LOG_FORMAT", "text")),
		AdminUser:         env("NODE64_ADMIN_USER", ""),
		AdminPassword:     env("NODE64_ADMIN_PASSWORD", ""),
		TLSCertFile:       env("NODE64_TLS_CERT", ""),
		TLSKeyFile:        env("NODE64_TLS_KEY", ""),
		TrustProxyHeaders: envBool("NODE64_TRUST_PROXY", false),
	}
	var err error
	if c.HTTPPort, err = envInt("NODE64_HTTP_PORT", 8080); err != nil {
		return nil, err
	}
	if c.HTTPSPort, err = envInt("NODE64_HTTPS_PORT", 0); err != nil {
		return nil, err
	}
	if c.HTTPPort == 0 && c.HTTPSPort == 0 {
		return nil, errors.New("NODE64_HTTP_PORT and NODE64_HTTPS_PORT are both 0, the UI would be unreachable")
	}
	if c.HTTPPort == c.HTTPSPort { // gleicher Port: der Web-Port spricht HTTPS ohnehin mit
		c.HTTPSPort = 0
	}
	c.EnvHTTPPort, c.EnvHTTPSPort = c.HTTPPort, c.HTTPSPort
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("NODE64_LOG_LEVEL %q is not one of debug, info, warn, error", c.LogLevel)
	}
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return nil, fmt.Errorf("NODE64_LOG_FORMAT %q is not text or json", c.LogFormat)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return nil, errors.New("NODE64_TLS_CERT and NODE64_TLS_KEY must be set together")
	}
	if (c.AdminUser == "") != (c.AdminPassword == "") {
		return nil, errors.New("NODE64_ADMIN_USER and NODE64_ADMIN_PASSWORD must be set together")
	}
	if c.AdminPassword != "" && len(c.AdminPassword) < 8 {
		return nil, errors.New("NODE64_ADMIN_PASSWORD must have at least 8 characters")
	}
	return c, nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 65535 {
		return 0, fmt.Errorf("%s must be a port number between 0 and 65535, got %q", key, v)
	}
	return n, nil
}

func envBool(key string, def bool) bool {
	switch strings.ToLower(env(key, "")) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return def
}

// Fehler von CheckWebPorts.
var (
	ErrPortRange = errors.New("ports must be between 0 and 65535")
	ErrPortsOff  = errors.New("web port and https port are both 0, the UI would be unreachable")
	ErrPortsSame = errors.New("web port and https port must differ")
)

// CheckWebPorts prueft die Ports der Oberflaeche (0 = aus, aber nicht beide).
func CheckWebPorts(httpPort, httpsPort int) error {
	switch {
	case httpPort < 0 || httpPort > 65535 || httpsPort < 0 || httpsPort > 65535:
		return ErrPortRange
	case httpPort == 0 && httpsPort == 0:
		return ErrPortsOff
	case httpPort == httpsPort:
		return ErrPortsSame
	}
	return nil
}

// WritePortsFile legt die wirksamen Ports fuer "node64 healthcheck" ab.
func (c *Config) WritePortsFile() error {
	return os.WriteFile(c.PortsFile(), []byte(fmt.Sprintf("%d %d\n", c.HTTPPort, c.HTTPSPort)), 0o640)
}

// ReadPortsFile liest die vom laufenden Node abgelegten Ports; false ohne bzw. mit ungueltiger Datei.
func (c *Config) ReadPortsFile() (httpPort, httpsPort int, ok bool) {
	b, err := os.ReadFile(c.PortsFile())
	if err != nil {
		return 0, 0, false
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(f[0])
	s, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil || CheckWebPorts(h, s) != nil {
		return 0, 0, false
	}
	return h, s, true
}
