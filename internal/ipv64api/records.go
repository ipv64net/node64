package ipv64api

import (
	"context"
	"net/http"
	"net/url"
)

// Schreibende Record-Aufrufe der API v2 (z. B. fuer ACME DNS-01). TTL ist bei ipv64 fest 60 s; nach dem Anlegen
// schreibt ipv64 den Record erst nach einigen Sekunden auf die Nameserver (pending_dns).

// AddRecord legt einen Record an (POST /domains/{domain}/records); prefix relativ zur Domain, "" = Domain selbst.
func (c *Client) AddRecord(ctx context.Context, key, domain, typ, prefix, content string) (*Record, error) {
	var out Record
	in := map[string]string{"type": typ, "prefix": prefix, "content": content}
	if err := c.do(ctx, http.MethodPost, key, "/domains/"+url.PathEscape(domain)+"/records", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRecordByContent loescht einen Record nach Typ, Praefix und Inhalt (DELETE /domains/{domain}/records?...).
func (c *Client) DeleteRecordByContent(ctx context.Context, key, domain, typ, prefix, content string) error {
	q := url.Values{"type": {typ}, "prefix": {prefix}, "content": {content}}
	return c.do(ctx, http.MethodDelete, key, "/domains/"+url.PathEscape(domain)+"/records?"+q.Encode(), nil, nil)
}
