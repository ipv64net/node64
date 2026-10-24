package ipv64api

import (
	"context"
	"net/http"
	"strconv"
	"time"
)

// Verwaltung der ipv64-Kanaele des Accounts (E-Mail, SMS, App) ueber die API v2: Node64 legt sie mit dem API-Key an,
// aendert, bestaetigt per Code, testet und loescht sie wie die eigenen Kanaele.

// ChannelInput sind die Felder beim Anlegen bzw. Aendern (nil = unveraendert lassen).
type ChannelInput struct {
	Type       string            `json:"type,omitempty"`
	Name       string            `json:"name,omitempty"`
	Lang       string            `json:"lang,omitempty"`
	Config     map[string]string `json:"config,omitempty"`
	Enabled    *bool             `json:"enabled,omitempty"`
	Default    *bool             `json:"default,omitempty"`
	NotifyDown *bool             `json:"notify_down,omitempty"`
	NotifyUp   *bool             `json:"notify_up,omitempty"`
}

func channelPath(id int64) string { return "/hc2/channels/" + strconv.FormatInt(id, 10) }

// Channel liefert einen Kanal des Accounts.
func (c *Client) Channel(ctx context.Context, key string, id int64) (*RemoteChannel, error) {
	var out RemoteChannel
	return &out, c.get(ctx, key, channelPath(id), &out)
}

// CreateChannel legt einen Kanal an (E-Mail/SMS sind danach unbestaetigt).
func (c *Client) CreateChannel(ctx context.Context, key string, in ChannelInput) (*RemoteChannel, error) {
	var out RemoteChannel
	return &out, c.do(ctx, http.MethodPost, key, "/hc2/channels", in, &out)
}

// UpdateChannel aendert einen Kanal (neue Adresse/Nummer: wieder unbestaetigt).
func (c *Client) UpdateChannel(ctx context.Context, key string, id int64, in ChannelInput) (*RemoteChannel, error) {
	var out RemoteChannel
	return &out, c.do(ctx, http.MethodPatch, key, channelPath(id), in, &out)
}

// DeleteChannel loescht einen Kanal.
func (c *Client) DeleteChannel(ctx context.Context, key string, id int64) error {
	return c.do(ctx, http.MethodDelete, key, channelPath(id), nil, nil)
}

// TestChannel schickt eine Testnachricht (nur bestaetigte Kanaele).
func (c *Client) TestChannel(ctx context.Context, key string, id int64) error {
	return c.do(ctx, http.MethodPost, key, channelPath(id)+"/test", map[string]string{}, nil)
}

// VerifySend schickt den Bestaetigungscode an Adresse bzw. Nummer des Kanals.
func (c *Client) VerifySend(ctx context.Context, key string, id int64) error {
	return c.do(ctx, http.MethodPost, key, channelPath(id)+"/verify/send", map[string]string{}, nil)
}

// VerifyCheck bestaetigt den Kanal mit dem Code.
func (c *Client) VerifyCheck(ctx context.Context, key string, id int64, code string) error {
	return c.do(ctx, http.MethodPost, key, channelPath(id)+"/verify", map[string]string{"code": code}, nil)
}

// AccountChannels liefert die ipv64-Kanaele des Accounts (E-Mail, SMS, App) frisch, auch unbestaetigte – fuer die
// Verwaltung in der Oberflaeche. Leert zugleich den Zwischenstand des Dispatchers.
func (k *Key) AccountChannels(ctx context.Context) ([]RemoteChannel, error) {
	key := k.Get(ctx)
	if key == "" {
		return nil, ErrNoKey
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := k.client.Channels(lctx, key)
	if err != nil {
		return nil, err
	}
	var out []RemoteChannel
	for _, c := range list {
		if serverTypes[c.Type] && c.NodeID == "" {
			out = append(out, c)
		}
	}
	return out, nil
}

// ResetChannels verwirft den Zwischenstand der Kanalliste (nach einer Aenderung gilt sie sofort).
func ResetChannels() {
	remote.mu.Lock()
	remote.at = time.Time{}
	remote.mu.Unlock()
}
