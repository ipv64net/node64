package ipv64api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/notify"
)

// Versand ueber die ipv64-Kanaele des Accounts (ipv64-Mail, -SMS) direkt per API v2, ohne hub:
// POST /hc2/channels/{id}/send. Der Empfaenger steht nur im verifizierten Kanal auf dem Server.
// Genutzt fuer Meldungen der Module (notify.CheckInfo.Local); Healthchecks bleiben beim hub.

// SendMsg ist eine Nachricht an einen ipv64-Kanal.
type SendMsg struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html,omitempty"`
	Kind    string `json:"kind,omitempty"`
	EventID string `json:"event_id,omitempty"`
	Source  string `json:"source,omitempty"`
}

// SendResult ist die Antwort des Servers.
type SendResult struct {
	Sent      bool `json:"sent"`
	Duplicate bool `json:"duplicate"`
	SMSLeft   *int `json:"sms_left"`
}

// RemoteChannel ist ein Kanal des Accounts (GET /hc2/channels).
type RemoteChannel struct {
	ID          int64  `json:"id"`
	Type        string `json:"type"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Default     bool   `json:"default"`
	Verified    bool   `json:"verified"`
	Lang        string `json:"lang"`
	NotifyDown  bool   `json:"notify_down"`
	NotifyUp    bool   `json:"notify_up"`
	Execution   string `json:"execution"`
	SendableAPI *bool  `json:"sendable_via_api"` // nil = Server kennt das Feld noch nicht
}

// SendChannel verschickt eine Nachricht ueber einen ipv64-Kanal des Accounts.
func (c *Client) SendChannel(ctx context.Context, key string, id int64, m SendMsg) (*SendResult, error) {
	var out SendResult
	if err := c.do(ctx, http.MethodPost, key, "/hc2/channels/"+strconv.FormatInt(id, 10)+"/send", m, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Channels liefert die Kanaele des Accounts.
func (c *Client) Channels(ctx context.Context, key string) ([]RemoteChannel, error) {
	var out []RemoteChannel
	return out, c.get(ctx, key, "/hc2/channels", &out)
}

// serverTypes sind die Kanaltypen, die ipv64 selbst zustellt.
var serverTypes = map[string]bool{"ipv64_mail": true, "ipv64_sms": true}

// ErrNoKey: kein API-Key eingetragen.
var ErrNoKey = errors.New("no ipv64 API key")

// APIReady: ein Key ist eingetragen (Versand ueber die API moeglich).
func (k *Key) APIReady() bool { return k.Get(context.Background()) != "" }

// SendNotification ist der Versandweg des Dispatchers fuer Server-Kanaele (notify.Dispatcher.SetAPISender).
func (k *Key) SendNotification(ctx context.Context, ch *notify.Channel, m notify.Message) error {
	key := k.Get(ctx)
	if key == "" {
		return fmt.Errorf("%w: %v", notify.ErrUnavailable, ErrNoKey)
	}
	if ch.RemoteID <= 0 {
		return errors.New("channel has no ipv64 id")
	}
	_, err := k.client.SendChannel(ctx, key, ch.RemoteID, SendMsg{Subject: m.Title, Text: m.Text, Kind: string(m.Kind), EventID: m.EventID, Source: "node64"})
	// 404 ohne "Channel not found": die Route gibt es auf ipv64.net noch nicht -> kein Kanalfehler
	if err != nil && strings.HasSuffix(err.Error(), "(404)") && !strings.Contains(strings.ToLower(err.Error()), "channel not found") {
		return fmt.Errorf("%w: ipv64 does not offer sending via the API yet", notify.ErrUnavailable)
	}
	return err
}

// remoteCache haelt die Kanalliste des Accounts kurz vor (nur ohne Verknuepfung benutzt).
type remoteCache struct {
	mu   sync.Mutex
	list []*notify.Channel
	at   time.Time
	key  string
}

var remote remoteCache

// RemoteChannels liefert die ipv64-Kanaele des Accounts als nur lesende Liste fuer den Dispatcher
// (ohne Sync gibt es auf der Node keine Platzhalter). Abfrage hoechstens alle 10 Minuten.
func (k *Key) RemoteChannels(ctx context.Context) []*notify.Channel {
	key := k.Get(ctx)
	if key == "" {
		return nil
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.key == key && time.Since(remote.at) < 10*time.Minute {
		return remote.list
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	list, err := k.client.Channels(lctx, key)
	cancel()
	remote.at, remote.key = time.Now(), key
	if err != nil {
		k.log.Warn("ipv64 channels not readable", "err", err)
		return remote.list // letzter Stand
	}
	var out []*notify.Channel
	for _, c := range list {
		if !serverTypes[c.Type] || !c.Verified || (c.SendableAPI != nil && !*c.SendableAPI) {
			continue
		}
		out = append(out, &notify.Channel{ID: -c.ID, Type: notify.Type(c.Type), Name: c.Name, Enabled: c.Enabled, Default: c.Default, Lang: c.Lang,
			NotifyDown: c.NotifyDown, NotifyUp: c.NotifyUp, Execution: "server", RemoteID: c.ID})
	}
	remote.list = out
	return out
}
