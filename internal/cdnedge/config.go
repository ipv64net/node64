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
	ListenHTTPS  string        `yaml:"listen_https"` // Besucher Port 443 (Modus 1, nach SNI); leer = aus
	Hosts        []HostEntry   `yaml:"hosts"`        // T2: feste Zuordnung Name -> Tunnel; ab T3 von ipv64
	PeerListen   string        `yaml:"peer_listen"`  // Nachbar-Port (TLS), z. B. :7845; leer = aus
	PeerSecret   string        `yaml:"peer_secret"`  // gemeinsames Geheimnis der Server
	Peers        []PeerEntry   `yaml:"peers"`        // Nachbarserver fuer den Ausweichweg
	Shield       ShieldConfig  `yaml:"shield"`       // grober Schutz vor der Weitergabe
	APIURL       string        `yaml:"api_url"`      // ipv64 API v2, z. B. https://ipv64.net/api/v2; leer = nur feste Konfiguration
	APISecret    string        `yaml:"api_secret"`   // Server-Geheimnis (bei ipv64 als SHA-256 in cdn64o_edges)
	// Modus 2 (TLS endet hier): Zertifikate je Name per DNS-01 ueber ipv64, verschluesselt bei ipv64 abgelegt
	HTTP3       bool   `yaml:"http3"`          // HTTP/3 auf UDP listen_https (Port in der Firewall freigeben)
	CertKey     string `yaml:"cert_key"`       // gemeinsamer Schluessel der Server fuer die Ablage (64 Hex = 32 Byte)
	ACMEPrimary bool   `yaml:"acme_primary"`   // dieser Server bestellt (der andere erst, wenn eins 10 Minuten fehlt)
	ACMEDir     string `yaml:"acme_directory"` // leer = Let's Encrypt; z. B. Staging zum Ausprobieren
	ACMEEmail   string `yaml:"acme_email"`
	// Ausweg ZeroSSL (acmeca.go): Standard an, wenn EAB oder acme_email gesetzt; "off" = aus
	ACMEFallback        string `yaml:"acme_fallback"`
	ACMEFallbackDir     string `yaml:"acme_fallback_directory"` // Standard ZeroSSL
	ACMEFallbackEABKID  string `yaml:"acme_fallback_eab_kid"`
	ACMEFallbackEABHMAC string `yaml:"acme_fallback_eab_hmac"`
	ACMELEWeekLimit     int    `yaml:"acme_le_week_limit"` // neue Zertifikate je Domain und Woche bei Let's Encrypt, Standard 40 (Grenze 50); -1 = nur Ausweg
	// Modus 3: Cache aller Namen zusammen auf der Platte (MB, Standard 4096)
	CacheTotalMB int    `yaml:"cache_total_mb"`
	PortRange    string `yaml:"port_range"` // Portmapper (Modus 3): Standard "50000-62000", "off" = aus
}

// HostEntry: ein Name (auch *.domain) und der Tunnel, der ihn bedient.
type HostEntry struct {
	Name   string `yaml:"name"`
	Tunnel string `yaml:"tunnel"`
	Mode   int    `yaml:"mode"` // 0/1 = durchreichen, 2 = terminieren
}

// PeerEntry: Nachbarserver (host:port des Nachbar-Ports; Zertifikat auf den Namen).
type PeerEntry struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
}

// ShieldConfig: Grenzen je IP (IPv6 je /64) und ipv64-Blocklisten auf dem Server (0 = Standard, -1 = aus).
type ShieldConfig struct {
	ConnsPerIP    int      `yaml:"conns_per_ip"`   // gleichzeitig, Standard 256
	ReqRate       int      `yaml:"req_rate"`       // Modus 2: Anfragen je Sekunde, kurzzeitig das Zehnfache, Standard 50
	ConnRate      int      `yaml:"conn_rate"`      // neue je Sekunde, kurzzeitig das Zehnfache, Standard 50
	MaxConns      int      `yaml:"max_conns"`      // insgesamt, Standard 50000
	Blocklists    []string `yaml:"blocklists"`     // z. B. [spamhaus_drop]; leer = keine
	BlocklistBase string   `yaml:"blocklist_base"` // Standard https://ipv64.net/blocklists/
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
	if c.APIURL != "" && len(c.APISecret) < 32 {
		return nil, errors.New("config: api_secret fehlt oder zu kurz (mindestens 32 Zeichen)")
	}
	if c.PeerListen != "" && len(c.PeerSecret) < 32 {
		return nil, errors.New("config: peer_secret fehlt oder zu kurz (mindestens 32 Zeichen)")
	}
	if strings.HasPrefix(c.DebugListen, ":") || strings.HasPrefix(c.DebugListen, "0.0.0.0") || strings.HasPrefix(c.DebugListen, "[::]") {
		return nil, errors.New("config: debug_listen nur auf 127.0.0.1")
	}
	return c, nil
}
