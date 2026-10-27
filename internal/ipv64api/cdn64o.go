package ipv64api

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// CDN64 online (API v2 /cdn64o): Tunnel der Node anmelden, Namen ein- und ausschalten, Kontingent und Status.

// CDN64Edge ist ein Server (srv07, srv08).
type CDN64Edge struct {
	Name string   `json:"name"`
	Host string   `json:"host"`
	Port int      `json:"port"` // Tunnel-Port
	IPs  []string `json:"ips"`  // IPv6 zuerst
}

// CDN64Tunnel ist ein Tunnel des Accounts (Token nur beim Anlegen bzw. neu Ausstellen).
type CDN64Tunnel struct {
	ID       string      `json:"id"`
	Name     string      `json:"name"`
	NodeID   string      `json:"node_id"`
	Status   string      `json:"status"` // active, blocked
	LastSeen *time.Time  `json:"last_seen"`
	LastEdge *string     `json:"last_edge"`
	Token    string      `json:"token,omitempty"`
	Edges    []CDN64Edge `json:"edges,omitempty"`
	Sessions int         `json:"sessions,omitempty"` // parallele Verbindungen je Server (Klasse; Business/Company mehrere)
}

// CDN64Host ist ein eingeschalteter Name.
type CDN64Host struct {
	ID            int64       `json:"id"`
	FQDN          string      `json:"fqdn"`
	Mode          int         `json:"mode"`
	Wildcard      bool        `json:"wildcard"`
	Status        string      `json:"status"` // pending, active, blocked
	BlockedReason *string     `json:"blocked_reason"`
	Error         *string     `json:"error"`
	Tunnels       []string    `json:"tunnels"`
	Edges         []CDN64Edge `json:"edges"`
	TrafficMonth  struct {
		BytesIn  int64 `json:"bytes_in"`
		BytesOut int64 `json:"bytes_out"`
		Conns    int64 `json:"conns"`
		Requests int64 `json:"requests"` // Modus 2
		Rejected int64 `json:"rejected"` // Modus 2: Anfrage-Limit der Server
	} `json:"traffic_month"`
	Paused     bool           `json:"paused"` // Server nehmen nichts an, DNS bleibt auf den Servern
	PausedAt   *time.Time     `json:"paused_at"`
	CreatedVia string         `json:"created_via"` // node, web
	Target     *CDN64Target   `json:"target"`      // nur Modus 3
	ACL        *CDN64ACL      `json:"acl"`
	Mappings   []CDN64Mapping `json:"mappings"` // Portmapper (nur Modus 3)
	WAF        bool           `json:"waf"`      // Muster-WAF in Modus 2/3 (Schalter des Namens)
	JA4        string         `json:"ja4"`      // Angriffs-Werkzeuge (JA4): off, count, block ("" = Portal ohne Schutz-Statistik)
	// Schutz der Server in den letzten 30 Tagen
	Protection CDN64ProtectionCounts `json:"protection"`
}

// CDN64ProtectionCounts: was srv07/srv08 abgewehrt bzw. gezaehlt haben (je Name, Tag oder Konto).
type CDN64ProtectionCounts struct {
	BlockedList  int64 `json:"blocked_list"`  // Blocklisten
	BlockedACL   int64 `json:"blocked_acl"`   // Zugriffsliste
	BlockedFlood int64 `json:"blocked_flood"` // Ueberlast (Verbindungen je IP, Verbindungsrate)
	BlockedLimit int64 `json:"blocked_limit"` // Anfrage-Limit (Modus 2/3)
	BlockedWAF   int64 `json:"blocked_waf"`   // WAF-Muster
	BlockedJA4   int64 `json:"blocked_ja4"`   // Angriffs-Werkzeug (JA4), gesperrt
	JA4Hits      int64 `json:"ja4_hits"`      // Treffer der JA4-Liste (gesperrt oder nur gezaehlt)
	BlockedIPs   int64 `json:"blocked_ips"`   // verschiedene gesperrte IP-Adressen (IPv6 je /64)
	Conns        int64 `json:"conns"`         // Verbindungen ueber CDN64 (eigene Adresse verborgen)
	ConnsV4      int64 `json:"conns_v4"`      // davon von IPv4-Besuchern
}

// Blocked: alles Abgewehrte zusammen.
func (p CDN64ProtectionCounts) Blocked() int64 {
	return p.BlockedList + p.BlockedACL + p.BlockedFlood + p.BlockedLimit + p.BlockedWAF + p.BlockedJA4
}

// Overload: Ueberlast abgefangen (Verbindungs-Grenzen und Anfrage-Limit).
func (p CDN64ProtectionCounts) Overload() int64 { return p.BlockedFlood + p.BlockedLimit }

// CDN64ProtectionDay: Zahlen eines Tages (YYYY-MM-DD).
type CDN64ProtectionDay struct {
	Day string `json:"day"`
	CDN64ProtectionCounts
}

// CDN64ProtectionHost: Zahlen eines Namens im Zeitraum.
type CDN64ProtectionHost struct {
	ID   int64  `json:"id"`
	FQDN string `json:"fqdn"`
	Mode int    `json:"mode"`
	CDN64ProtectionCounts
}

// CDN64JA4Hit: Angriffs-Werkzeug (JA4) und seine Treffer.
type CDN64JA4Hit struct {
	JA4  string `json:"ja4"`
	Hits int64  `json:"hits"`
}

// CDN64Protection ist GET /cdn64o/protection (nur Namen des Kontos).
type CDN64Protection struct {
	Days      int                   `json:"days"`
	JA4Global string                `json:"ja4_global"` // count = Startphase (nur zaehlen), block
	Totals    CDN64ProtectionCounts `json:"totals"`
	Daily     []CDN64ProtectionDay  `json:"daily"`
	Hosts     []CDN64ProtectionHost `json:"hosts"`
	JA4Top    []CDN64JA4Hit         `json:"ja4_top"` // haeufigste Treffer (hoechstens 10)
}

// CDN64ACL: Erlauben-/Sperrliste eines Namens auf den Servern (default off, allow, deny).
type CDN64ACL struct {
	Default string   `json:"default"`
	List    []string `json:"list"`
}

// CDN64Mapping: Port der Server, der roh an einen Port des Ziels geht (Modus 3).
type CDN64Mapping struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	ListenPort int    `json:"listen_port"`
	Transport  string `json:"transport"` // tcp, udp
	TargetPort int    `json:"target_port"`
}

// CDN64Quota: Kontingent des Accounts (altes und neues CDN zusammen).
type CDN64Quota struct {
	Domains struct {
		Used   int `json:"used"`
		OldCDN int `json:"old_cdn"`
		Limit  int `json:"limit"`
	} `json:"domains"`
	TrafficMB struct {
		Used   float64 `json:"used"`
		OldCDN float64 `json:"old_cdn"`
		Limit  int     `json:"limit"`
	} `json:"traffic_mb"`
	BandwidthMbit int `json:"bandwidth_mbit"` // 0 = frei
}

// CDN64Overview ist GET /cdn64o.
type CDN64Overview struct {
	Quota   CDN64Quota    `json:"quota"`
	Edges   []CDN64Edge   `json:"edges"`
	Tunnels []CDN64Tunnel `json:"tunnels"`
	Hosts   []CDN64Host   `json:"hosts"`
}

// CDN64 liefert Kontingent, Server, Tunnels und Namen des Accounts.
func (c *Client) CDN64(ctx context.Context, key string) (*CDN64Overview, error) {
	var out CDN64Overview
	if err := c.get(ctx, key, "/cdn64o", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64CreateTunnel meldet einen Tunnel an; die Antwort enthaelt den Token (nur hier) und die Server.
func (c *Client) CDN64CreateTunnel(ctx context.Context, key, name, nodeID string) (*CDN64Tunnel, error) {
	var out CDN64Tunnel
	if err := c.do(ctx, http.MethodPost, key, "/cdn64o/tunnels", map[string]string{"name": name, "node_id": nodeID}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64DeleteTunnel entfernt einen Tunnel (Namen nur auf diesem Tunnel werden mit ausgeschaltet).
func (c *Client) CDN64DeleteTunnel(ctx context.Context, key, id string) error {
	return c.do(ctx, http.MethodDelete, key, "/cdn64o/tunnels/"+url.PathEscape(id), nil, nil)
}

// CDN64Target: Ziel in Modus 3 (direkt, ohne Tunnel).
type CDN64Target struct {
	Source    string `json:"source"` // records | fixed
	Target    string `json:"target,omitempty"`
	Port      int    `json:"port"`
	Scheme    string `json:"scheme"` // http | https
	VerifyTLS bool   `json:"verify_tls"`
	Frontend  int    `json:"frontend,omitempty"` // 0 nur Portmapper, 1 nur HTTP, 2 HTTPS mit Umleitung, 3 nur HTTPS
	// nur in Antworten
	Addrs        []string `json:"addrs,omitempty"` // source records: aktuelle Adressen des Namens
	PreferIPv6   bool     `json:"prefer_ipv6,omitempty"`
	CacheMB      int      `json:"cache_mb,omitempty"` // 0 = kein Cache auf den Servern
	CacheMinutes int      `json:"cache_minutes,omitempty"`
}

// CDN64AddHost schaltet einen Namen ein (DNS zeigt danach auf die Server); target nur fuer Modus 3.
func (c *Client) CDN64AddHost(ctx context.Context, key, fqdn, tunnelID string, mode int, target *CDN64Target) (*CDN64Host, error) {
	var out CDN64Host
	in := map[string]any{"fqdn": fqdn, "tunnel_id": tunnelID, "mode": mode, "via": "node"}
	if target != nil {
		in["source"], in["target"], in["port"], in["scheme"], in["verify_tls"] = target.Source, target.Target, target.Port, target.Scheme, target.VerifyTLS
		if target.Frontend > 0 {
			in["frontend"] = target.Frontend
		}
	}
	if err := c.do(ctx, http.MethodPost, key, "/cdn64o/hosts", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64SetMode wechselt den Modus eines Namens (DNS bleibt).
func (c *Client) CDN64SetMode(ctx context.Context, key string, id int64, mode int) (*CDN64Host, error) {
	var out CDN64Host
	if err := c.do(ctx, http.MethodPatch, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10), map[string]int{"mode": mode}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64SetPaused pausiert einen Namen bzw. setzt ihn fort: die Server nehmen nichts mehr an und trennen offene
// Verbindungen, DNS, Einstellungen und Statistik bleiben.
func (c *Client) CDN64SetPaused(ctx context.Context, key string, id int64, paused bool) (*CDN64Host, error) {
	var out CDN64Host
	if err := c.do(ctx, http.MethodPatch, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10), map[string]bool{"paused": paused}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64Protection liefert die Schutz-Statistik des Kontos (days 1 = heute, 7, 30).
func (c *Client) CDN64Protection(ctx context.Context, key string, days int) (*CDN64Protection, error) {
	var out CDN64Protection
	if err := c.get(ctx, key, "/cdn64o/protection?days="+strconv.Itoa(days), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64SetProtection setzt WAF (nil = unveraendert) und JA4 (off, count, block; "" = unveraendert) eines Namens.
func (c *Client) CDN64SetProtection(ctx context.Context, key string, id int64, waf *bool, ja4 string) (*CDN64Host, error) {
	in := map[string]any{}
	if waf != nil {
		in["waf"] = *waf
	}
	if ja4 != "" {
		in["ja4"] = ja4
	}
	var out CDN64Host
	if err := c.do(ctx, http.MethodPatch, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10), in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CDN64AddMapping legt einen Portmapper an (Modus 1/2: targetPort = Port des Streams in der Node); Antwort: alle
// Mappings des Namens.
func (c *Client) CDN64AddMapping(ctx context.Context, key string, id int64, name, transport string, targetPort int) ([]CDN64Mapping, error) {
	var out []CDN64Mapping
	in := map[string]any{"name": name, "transport": transport, "target_port": targetPort}
	if err := c.do(ctx, http.MethodPost, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10)+"/mappings", in, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CDN64DeleteMapping entfernt einen Portmapper.
func (c *Client) CDN64DeleteMapping(ctx context.Context, key string, id, mapping int64) error {
	return c.do(ctx, http.MethodDelete, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10)+"/mappings/"+strconv.FormatInt(mapping, 10), nil, nil)
}

// CDN64DeleteHost schaltet einen Namen aus (DNS zurueck).
func (c *Client) CDN64DeleteHost(ctx context.Context, key string, id int64) error {
	return c.do(ctx, http.MethodDelete, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10), nil, nil)
}
