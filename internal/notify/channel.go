// Package notify liefert Benachrichtigungskanaele, den Versand und das
// Zustellprotokoll. Der Dispatcher nimmt Ereignisse vom Scheduler an und
// verteilt sie nach Kanalzuordnung, Ruhezeiten, Ratenbegrenzung und
// Sammelmeldungen.
package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/secrets"
)

type Type string

const (
	TypeSMTP     Type = "smtp"
	TypeWebhook  Type = "webhook"
	TypeTelegram Type = "telegram"
	TypeDiscord  Type = "discord"
	TypeNtfy     Type = "ntfy"
	TypeGotify   Type = "gotify"
	TypeIGotify  Type = "igotify" // frueher eigener Menuepunkt (iPhone ueber iGotify) – jetzt normaler Gotify; bleibt fuer alte Kanaele/API gueltig
	TypePushover Type = "pushover"
	TypeSlack    Type = "slack"   // Incoming Webhook
	TypeTeams    Type = "teams"   // Workflows-Webhook (die alten Office-365-Connectoren gibt es seit Mai 2026 nicht mehr)
	TypeMatrix   Type = "matrix"  // Client-Server-API: Homeserver, Zugriffstoken eines Bot-Kontos, Raum
	TypeSecNtfy  Type = "secntfy" // SecNtfy: Ende-zu-Ende verschluesselt (RSA mit dem Schluessel des Geraets)
	// Home Assistant: Webhook-Ausloeser einer Automation (nur von der Node gesendet, HA steht im LAN)
	TypeHomeAssistant Type = "homeassistant"
	// Server-Typen: Versand ueber ipv64.net (im Node erst nach Verknuepfung)
	TypeIPv64Mail Type = "ipv64_mail"
	TypeIPv64SMS  Type = "ipv64_sms"
	TypeApp       Type = "app"
)

// Types in Anzeigereihenfolge.
var Types = []Type{TypeBrowser, TypeSMTP, TypeTelegram, TypeDiscord, TypeSlack, TypeTeams, TypeMatrix, TypeNtfy, TypeGotify, TypePushover, TypeSecNtfy, TypeHomeAssistant, TypeWebhook}

// Planned sind Kanaele, die ipv64.net nach der Verknuepfung bereitstellt:
// Mail ohne eigenen SMTP-Server und SMS ueber das ipv64-Gateway. Sie werden
// vom Server gesendet (execution "ipv64") und sind standalone nicht verfuegbar.
var Planned = []Type{TypeIPv64Mail, TypeIPv64SMS}

// Channel ist ein Benachrichtigungskanal.
type Channel struct {
	ID              int64
	UserID          int64 // Account auf dem Server; im Node 0
	Type            Type
	Name            string
	Config          map[string]string // Klartext im Speicher, verschluesselt in der DB
	Enabled         bool
	Default         bool
	Lang            string
	NotifyDown      bool
	NotifyUp        bool
	SecretOnlyLocal bool
	Execution       string
	Revision        int64
	CreatedAt       time.Time
	UpdatedAt       time.Time
	LastUsedAt      time.Time
	LastError       string
	RemoteID        int64  // ID auf dem Server (Sync); 0 = nicht abgeglichen
	NodeID          string // hub: Besitzer-Node eines Node-Kanals (Execution "node")
	UID             string // Kennung im Cluster (gleich auf allen Nodes, cluster.go); hub: leer
	cfgErr          bool   // Konfiguration nicht lesbar (Geheimnisse fehlen)
}

// Field beschreibt ein Konfigurationsfeld eines Kanaltyps (fuer Formular und Validierung).
type Field struct {
	Key      string
	Secret   bool
	Required bool
	Default  string
	Kind     string // text, url, number, select, bool, textarea, password
	Options  []string
}

// Fields je Typ. Die Schluessel sind zugleich die i18n-Schluessel "nf.field.<key>".
var Fields = map[Type][]Field{
	TypeSMTP: {
		{Key: "host", Required: true}, {Key: "port", Kind: "number", Default: "587"},
		{Key: "security", Kind: "select", Options: []string{"starttls", "tls", "none"}, Default: "starttls"},
		{Key: "user"}, {Key: "password", Secret: true, Kind: "password"},
		{Key: "from", Required: true}, {Key: "to", Required: true},
	},
	TypeTelegram: {
		{Key: "bot_token", Secret: true, Required: true, Kind: "password"}, {Key: "chat_id", Required: true},
		{Key: "silent", Kind: "bool"},
	},
	TypeDiscord: {
		{Key: "webhook_url", Secret: true, Required: true, Kind: "password"}, {Key: "username"},
	},
	TypeNtfy: {
		{Key: "server", Kind: "url", Default: "https://ntfy.sh", Required: true}, {Key: "topic", Required: true},
		{Key: "token", Secret: true, Kind: "password"}, {Key: "user"}, {Key: "password", Secret: true, Kind: "password"},
		{Key: "priority_down", Kind: "select", Options: []string{"1", "2", "3", "4", "5"}, Default: "4"},
		{Key: "priority_up", Kind: "select", Options: []string{"1", "2", "3", "4", "5"}, Default: "3"},
	},
	TypeGotify: {
		{Key: "server", Kind: "url", Required: true}, {Key: "app_token", Secret: true, Required: true, Kind: "password"},
		{Key: "priority", Kind: "number", Default: "5"},
	},
	TypeIGotify: {
		{Key: "server", Kind: "url", Required: true}, {Key: "app_token", Secret: true, Required: true, Kind: "password"},
		{Key: "priority", Kind: "number", Default: "5"},
	},
	TypePushover: {
		{Key: "user_key", Secret: true, Required: true, Kind: "password"}, {Key: "app_token", Secret: true, Required: true, Kind: "password"},
		{Key: "device"},
		{Key: "priority_down", Kind: "select", Options: []string{"-2", "-1", "0", "1", "2"}, Default: "1"},
		{Key: "priority_up", Kind: "select", Options: []string{"-2", "-1", "0", "1", "2"}, Default: "0"},
	},
	TypeSlack: {{Key: "webhook_url", Secret: true, Required: true, Kind: "password"}},
	TypeTeams: {{Key: "webhook_url", Secret: true, Required: true, Kind: "password"}},
	TypeMatrix: {
		{Key: "server", Kind: "url", Default: "https://matrix.org", Required: true},
		{Key: "token", Secret: true, Required: true, Kind: "password"},
		{Key: "room", Required: true},
	},
	TypeSecNtfy: {
		{Key: "device_key", Secret: true, Required: true, Kind: "password"},
		{Key: "server", Kind: "url", Default: "https://api.secntfy.app", Required: true},
		{Key: "critical", Kind: "bool"},
	},
	TypeBrowser:   {},
	TypeIPv64Mail: {{Key: "email", Required: true}},
	TypeIPv64SMS:  {{Key: "number", Required: true}},
	TypeApp:       {{Key: "device_token", Secret: true, Required: true, Kind: "password"}},
	TypeWebhook: {
		{Key: "url", Kind: "url", Required: true},
		{Key: "method", Kind: "select", Options: []string{"POST", "PUT", "GET"}, Default: "POST"},
		{Key: "headers", Kind: "textarea", Secret: true},
		{Key: "body", Kind: "textarea"},
		{Key: "insecure_tls", Kind: "bool"},
	},
	TypeHomeAssistant: {
		{Key: "url", Kind: "url", Required: true}, // Basis-URL, z. B. http://homeassistant.local:8123
		{Key: "webhook_id", Secret: true, Required: true, Kind: "password"},
		{Key: "verify_tls", Kind: "bool", Default: "true"},
	},
}

// haWebhookID: erlaubte Zeichen der Webhook-ID von Home Assistant.
var haWebhookID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// IsSecret sagt, ob ein Feld verschluesselt gespeichert wird.
func IsSecret(t Type, key string) bool {
	for _, f := range Fields[t] {
		if f.Key == key {
			return f.Secret
		}
	}
	return false
}

// Validate prueft Typ und Pflichtfelder.
func (c *Channel) Validate() error { return c.validate(false) }

// ValidateKeepSecrets prueft wie Validate, laesst aber leere Pflicht-Geheimnisse zu: Kanaele des
// Portals, deren Zugangsdaten bei ipv64 liegen (leer = unveraendert lassen).
func (c *Channel) ValidateKeepSecrets() error { return c.validate(true) }

func (c *Channel) validate(keepSecrets bool) error {
	fields, ok := Fields[c.Type]
	if !ok {
		return fmt.Errorf("unknown channel type %q", c.Type)
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" || len(c.Name) > 100 {
		return errors.New("name is required (max 100 characters)")
	}
	if c.Config == nil {
		c.Config = map[string]string{}
	}
	for _, f := range fields {
		v := strings.TrimSpace(c.Config[f.Key])
		if v == "" && f.Default != "" {
			v = f.Default
		}
		if f.Required && v == "" && !(keepSecrets && f.Secret) {
			return fmt.Errorf("%s is required", f.Key)
		}
		if c.Type == TypeIPv64SMS && f.Key == "number" {
			n, err := SMSNumber(v)
			if err != nil {
				return fmt.Errorf("%s: %w", f.Key, err)
			}
			c.Config[f.Key] = n
		}
		switch f.Kind {
		case "url":
			if v != "" {
				u, err := url.Parse(v)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fmt.Errorf("%s must be an http(s) URL", f.Key)
				}
			}
		case "number":
			if v != "" {
				var n int
				if _, err := fmt.Sscan(v, &n); err != nil {
					return fmt.Errorf("%s must be a number", f.Key)
				}
			}
		case "select":
			if v != "" {
				found := false
				for _, o := range f.Options {
					if o == v {
						found = true
					}
				}
				if !found {
					return fmt.Errorf("%s must be one of %s", f.Key, strings.Join(f.Options, ", "))
				}
			}
		case "bool":
			if v != "" && v != "true" && v != "false" {
				v = "true"
			}
		}
		c.Config[f.Key] = v
	}
	if c.Type == TypeSMTP {
		for _, to := range splitList(c.Config["to"]) {
			if !strings.Contains(to, "@") {
				return fmt.Errorf("to: %q is not an e-mail address", to)
			}
		}
	}
	if c.Type == TypeSlack || c.Type == TypeTeams || c.Type == TypeDiscord {
		if v := c.Config["webhook_url"]; v != "" || !keepSecrets {
			if u, err := url.Parse(v); err != nil || u.Scheme != "https" || u.Host == "" {
				return errors.New("webhook_url must be an https URL")
			}
		}
	}
	if c.Type == TypeMatrix {
		c.Config["server"] = strings.TrimRight(c.Config["server"], "/")
		if !matrixRoom.MatchString(c.Config["room"]) {
			return errors.New("room must be a room ID (!abc:example.org) or an alias (#room:example.org)")
		}
	}
	if c.Type == TypeSecNtfy {
		c.Config["server"] = strings.TrimRight(c.Config["server"], "/")
		if v := strings.TrimSpace(c.Config["device_key"]); v != "" || !keepSecrets {
			if !validSecntfyToken(v) {
				return errors.New("device_key must be a SecNtfy device token (NTFY-DEVICE-…)")
			}
			c.Config["device_key"] = v
		}
	}
	if c.Type == TypeHomeAssistant {
		// Basis-URL ohne Abfrage; der Pfad /api/webhook/<id> kommt beim Senden dazu
		if u, err := url.Parse(c.Config["url"]); err == nil && (u.RawQuery != "" || u.Fragment != "" || u.User != nil) {
			return errors.New("url must be the Home Assistant base URL, e.g. http://homeassistant.local:8123")
		}
		c.Config["url"] = strings.TrimRight(c.Config["url"], "/")
		if id := c.Config["webhook_id"]; (id != "" || !keepSecrets) && !haWebhookID.MatchString(id) {
			return errors.New("webhook_id may only contain A-Z, a-z, 0-9, _ and - (max 128 characters)")
		}
	}
	if c.Lang == "" {
		c.Lang = "de"
	}
	if c.Execution == "" {
		c.Execution = "node"
	}
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == '\n' || r == ' ' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// encodeConfig verschluesselt Geheimnisse und liefert JSON fuer die DB.
func encodeConfig(box *secrets.Box, t Type, cfg map[string]string) (string, error) {
	out := make(map[string]string, len(cfg))
	for k, v := range cfg {
		if IsSecret(t, k) && v != "" && box != nil {
			v = box.Encrypt(v)
		}
		out[k] = v
	}
	b, err := json.Marshal(out)
	return string(b), err
}

// decodeConfig entschluesselt Geheimnisse aus der DB.
func decodeConfig(box *secrets.Box, raw string) (map[string]string, error) {
	cfg := map[string]string{}
	if raw == "" {
		return cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, err
	}
	for k, v := range cfg {
		if secrets.IsEncrypted(v) {
			plain, err := box.Decrypt(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", k, err)
			}
			cfg[k] = plain
		}
	}
	return cfg, nil
}

// Masked liefert die Konfiguration mit maskierten Geheimnissen (fuer Anzeige).
func (c *Channel) Masked() map[string]string {
	out := make(map[string]string, len(c.Config))
	for k, v := range c.Config {
		if IsSecret(c.Type, k) {
			if c.Type == TypeWebhook && k == "headers" {
				out[k] = maskHeaders(v)
				continue
			}
			out[k] = secrets.Mask(v)
			continue
		}
		out[k] = v
	}
	return out
}

func maskHeaders(h string) string {
	var lines []string
	for _, line := range strings.Split(h, "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			lines = append(lines, strings.TrimSpace(k)+": "+secrets.Mask(strings.TrimSpace(v)))
		}
	}
	return strings.Join(lines, "\n")
}

// Summary ist eine Kurzbeschreibung fuer die Liste (ohne Geheimnisse).
func (c *Channel) Summary() string {
	g := func(k string) string { return c.Config[k] }
	switch c.Type {
	case TypeSMTP:
		return g("to") + " via " + g("host")
	case TypeTelegram:
		return "chat " + g("chat_id")
	case TypeDiscord:
		return "Webhook"
	case TypeNtfy:
		return strings.TrimRight(g("server"), "/") + "/" + g("topic")
	case TypeGotify, TypeIGotify:
		return g("server")
	case TypeSecNtfy:
		return "SecNtfy"
	case TypePushover:
		if g("device") != "" {
			return "Pushover (" + g("device") + ")"
		}
		return "Pushover"
	case TypeIPv64Mail:
		return g("email") + " via ipv64.net"
	case TypeIPv64SMS:
		return "+" + g("number") + " via ipv64.net"
	case TypeApp:
		return "ipv64 App"
	case TypeWebhook:
		return g("method") + " " + g("url")
	case TypeHomeAssistant:
		return g("url")
	}
	return ""
}
