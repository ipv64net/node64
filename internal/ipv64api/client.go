// Package ipv64api ist die Anbindung an die ipv64 API v2 mit dem zentralen API-Key des Containers.
// Der Key wird einmal in den Einstellungen eingetragen (verschluesselt gespeichert); alle Module
// bedienen sich daran (z. B. DynDNS: Domains, Records, Tokens, Update-Limit).
package ipv64api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// DefaultBase ist die Adresse der API v2.
const DefaultBase = "https://ipv64.net/api/v2"

// KeyRe ist das Format eines API-Keys (wie api_v2.php: 16 bis 64 Buchstaben und Ziffern).
var KeyRe = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

// ErrUnauthorized: API-Key ungueltig, abgelaufen oder widerrufen.
var ErrUnauthorized = errors.New("API key rejected by ipv64")

// Client spricht die API v2 an.
type Client struct {
	base string
	http *http.Client
	ua   string
}

// NewClient erzeugt einen Client (base leer = DefaultBase).
func NewClient(base, userAgent string) *Client {
	if base == "" {
		base = DefaultBase
	}
	return &Client{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 15 * time.Second}, ua: userAgent}
}

// Usage ist ein Verbrauch mit Grenze (Limit nil = unbegrenzt).
type Usage struct {
	Used  int  `json:"used"`
	Limit *int `json:"limit"`
}

// Me ist das Konto hinter dem Key (GET /me).
type Me struct {
	ID       int     `json:"id"`
	Email    string  `json:"email"`
	Username *string `json:"username"`
	Plan     struct {
		Name string `json:"name"`
	} `json:"plan"`
	Usage struct {
		DynDNSUpdates Usage `json:"dyndns_updates_24h"`
	} `json:"usage"`
	Auth struct {
		Type    string `json:"type"` // api_key, account_key
		KeyID   *int   `json:"key_id"`
		KeyName string `json:"key_name"`
	} `json:"auth"`
}

// APIKey ist ein API-Key des Accounts (GET /api-keys, ohne den Key selbst).
type APIKey struct {
	ID        int        `json:"id"`
	Name      string     `json:"name"`
	ExpiresAt *time.Time `json:"expires_at"` // nil = laeuft nicht ab
	Expired   bool       `json:"expired"`
}

// Account ist der Name, unter dem der Key angemeldet ist.
func (me *Me) Account() string {
	if me.Username != nil && *me.Username != "" {
		return *me.Username
	}
	return me.Email
}

// Domain ist eine Domain im Account (GET /domains).
type Domain struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Kind        string  `json:"kind"` // dyndns, own
	Zone        string  `json:"zone"`
	Ignore      string  `json:"ignore"`
	IPv6Prefix  *string `json:"ipv6_prefix"`
	Active      bool    `json:"active"`
	UpdateToken string  `json:"update_token"`
}

// Record ist ein DNS-Record einer Domain (GET /domains/{domain}/records).
type Record struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Prefix  string `json:"prefix"`
	FQDN    string `json:"fqdn"`
	Type    string `json:"type"`
	Content string `json:"content"`
	State   string `json:"state"`
	Token   string `json:"token"`
}

func (c *Client) get(ctx context.Context, key, path string, out any) error {
	return c.do(ctx, http.MethodGet, key, path, nil, out)
}

// do schickt eine Anfrage (in nil = ohne Body) und liest data aus der Antwort (2xx).
func (c *Client) do(ctx context.Context, method, key, path string, in any, out any) error {
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return errors.New("ipv64: timeout")
		}
		return fmt.Errorf("ipv64 not reachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return ErrUnauthorized
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var p struct {
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &p) == nil && p.Detail != "" {
			return fmt.Errorf("ipv64: %s (%d)", p.Detail, resp.StatusCode)
		}
		return fmt.Errorf("ipv64: HTTP %d", resp.StatusCode)
	}
	if out == nil {
		return nil // ohne Antwortdaten (z. B. 204 No Content)
	}
	env := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return errors.New("ipv64: unexpected answer")
	}
	return json.Unmarshal(env.Data, out)
}

// LinkNode loest einen Verknuepfungs-Code der Healthchecks im Account des Keys ein (POST /hc2/nodes/link);
// die Node holt sich danach ihren eigenen Node-Token beim hub.
func (c *Client) LinkNode(ctx context.Context, key, code, location, remoteMgmt string) error {
	return c.do(ctx, http.MethodPost, key, "/hc2/nodes/link", map[string]string{"code": code, "location": location, "remote_mgmt": remoteMgmt}, nil)
}

// Me liefert das Konto hinter dem Key.
func (c *Client) Me(ctx context.Context, key string) (*Me, error) {
	var me Me
	if err := c.get(ctx, key, "/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

// APIKeys liefert die API-Keys des Accounts (Name, Ablauf; ohne Token).
func (c *Client) APIKeys(ctx context.Context, key string) ([]APIKey, error) {
	var out []APIKey
	return out, c.get(ctx, key, "/api-keys", &out)
}

// Domains liefert alle Domains des Accounts.
func (c *Client) Domains(ctx context.Context, key string) ([]Domain, error) {
	var out []Domain
	return out, c.get(ctx, key, "/domains", &out)
}

// Records liefert die Records einer Domain.
func (c *Client) Records(ctx context.Context, key, domain string) ([]Record, error) {
	var out []Record
	return out, c.get(ctx, key, "/domains/"+url.PathEscape(domain)+"/records", &out)
}
