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
	if c.HTTPPort == c.HTTPSPort {
		return nil, errors.New("NODE64_HTTP_PORT and NODE64_HTTPS_PORT must differ")
	}
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
