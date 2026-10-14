package dyndns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Anbindung an die ipv64 API v2 (nur mit API-Key): Konto, Domains, Records und deren Tokens.
// Die eigentlichen Updates laufen spaeter ueber update.php mit Record- bzw. Domain-Token, nie mit dem API-Key.

const defaultAPIBase = "https://ipv64.net/api/v2"

var apiKeyRe = regexp.MustCompile(`^[A-Za-z0-9]{16,64}$`)

// ErrUnauthorized: API-Key ungueltig, abgelaufen oder widerrufen.
var ErrUnauthorized = errors.New("API key rejected by ipv64")

type apiClient struct {
	base string
	http *http.Client
	ua   string
}

func newAPIClient(base, ua string) *apiClient {
	return &apiClient{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 15 * time.Second}, ua: ua}
}

// usage ist ein Verbrauch mit Grenze (Limit nil = unbegrenzt).
type usage struct {
	Used  int  `json:"used"`
	Limit *int `json:"limit"`
}

type apiMe struct {
	ID       int     `json:"id"`
	Email    string  `json:"email"`
	Username *string `json:"username"`
	Plan     struct {
		Name string `json:"name"`
	} `json:"plan"`
	Usage struct {
		DynDNSUpdates usage `json:"dyndns_updates_24h"`
	} `json:"usage"`
}

// Account ist der Name, unter dem der Key angemeldet ist.
func (me *apiMe) Account() string {
	if me.Username != nil && *me.Username != "" {
		return *me.Username
	}
	return me.Email
}

type apiDomain struct {
	ID          int     `json:"id"`
	Name        string  `json:"name"`
	Kind        string  `json:"kind"` // dyndns, own
	Zone        string  `json:"zone"`
	Ignore      string  `json:"ignore"`
	IPv6Prefix  *string `json:"ipv6_prefix"`
	Active      bool    `json:"active"`
	UpdateToken string  `json:"update_token"`
}

type apiRecord struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Prefix  string `json:"prefix"`
	FQDN    string `json:"fqdn"`
	Type    string `json:"type"`
	Content string `json:"content"`
	State   string `json:"state"`
	Token   string `json:"token"`
}

func (c *apiClient) get(ctx context.Context, key, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.http.Do(req)
	if err != nil {
		return shortErr(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ErrUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		var p struct {
			Detail string `json:"detail"`
			Code   string `json:"code"`
		}
		if json.Unmarshal(body, &p) == nil && p.Detail != "" {
			return fmt.Errorf("ipv64: %s (%d)", p.Detail, resp.StatusCode)
		}
		return fmt.Errorf("ipv64: HTTP %d", resp.StatusCode)
	}
	env := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 {
		return errors.New("ipv64: unexpected answer")
	}
	return json.Unmarshal(env.Data, out)
}

func (c *apiClient) me(ctx context.Context, key string) (*apiMe, error) {
	var me apiMe
	if err := c.get(ctx, key, "/me", &me); err != nil {
		return nil, err
	}
	return &me, nil
}

func (c *apiClient) domains(ctx context.Context, key string) ([]apiDomain, error) {
	var out []apiDomain
	return out, c.get(ctx, key, "/domains", &out)
}

func (c *apiClient) records(ctx context.Context, key, domain string) ([]apiRecord, error) {
	var out []apiRecord
	return out, c.get(ctx, key, "/domains/"+url.PathEscape(domain)+"/records", &out)
}
