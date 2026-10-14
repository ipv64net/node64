package ipv64api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// Healthchecks 2.0 direkt ueber die API v2: Online-Checks verwalten (ohne Healthchecks-Sync) und eine
// Node trennen, wenn die hubs nicht erreichbar sind. Checks im selben JSON-Format wie die lokale API.

// HC2Checks liefert die Checks des Accounts (query z. B. "?execution=online").
func (c *Client) HC2Checks(ctx context.Context, key, query string) ([]json.RawMessage, error) {
	var out []json.RawMessage
	err := c.get(ctx, key, "/hc2/checks"+query, &out)
	return out, err
}

// HC2Check liefert einen Check.
func (c *Client) HC2Check(ctx context.Context, key, token string) (json.RawMessage, error) {
	var out json.RawMessage
	err := c.get(ctx, key, "/hc2/checks/"+url.PathEscape(token), &out)
	return out, err
}

// HC2SaveCheck legt einen Check an (token leer) oder aendert ihn; liefert den gespeicherten Check.
func (c *Client) HC2SaveCheck(ctx context.Context, key, token string, body map[string]any) (json.RawMessage, error) {
	var out json.RawMessage
	if token == "" {
		return out, c.do(ctx, http.MethodPost, key, "/hc2/checks", body, &out)
	}
	return out, c.do(ctx, http.MethodPatch, key, "/hc2/checks/"+url.PathEscape(token), body, &out)
}

// HC2DeleteCheck loescht einen Check.
func (c *Client) HC2DeleteCheck(ctx context.Context, key, token string) error {
	return c.do(ctx, http.MethodDelete, key, "/hc2/checks/"+url.PathEscape(token), nil, nil)
}

// HC2CheckAction: pause, resume oder run.
func (c *Client) HC2CheckAction(ctx context.Context, key, token, action string) error {
	return c.do(ctx, http.MethodPost, key, "/hc2/checks/"+url.PathEscape(token)+"/"+action, map[string]any{}, nil)
}

// HC2UnlinkNode trennt eine Node (Token widerrufen); keepChecks wie beim Trennen in der Node.
func (c *Client) HC2UnlinkNode(ctx context.Context, key, nodeID string, keepChecks bool) error {
	return c.do(ctx, http.MethodDelete, key, "/hc2/nodes/"+url.PathEscape(nodeID), map[string]any{"keep_checks": keepChecks}, nil)
}
