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
	} `json:"traffic_month"`
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

// CDN64AddHost schaltet einen Namen ein (DNS zeigt danach auf die Server).
func (c *Client) CDN64AddHost(ctx context.Context, key, fqdn, tunnelID string, mode int) (*CDN64Host, error) {
	var out CDN64Host
	in := map[string]any{"fqdn": fqdn, "tunnel_id": tunnelID, "mode": mode, "via": "node"}
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

// CDN64DeleteHost schaltet einen Namen aus (DNS zurueck).
func (c *Client) CDN64DeleteHost(ctx context.Context, key string, id int64) error {
	return c.do(ctx, http.MethodDelete, key, "/cdn64o/hosts/"+strconv.FormatInt(id, 10), nil, nil)
}
