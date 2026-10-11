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
	TypePushover Type = "pushover"
	// Server-Typen: Versand ueber ipv64.net (im Node erst nach Verknuepfung)
	TypeIPv64Mail Type = "ipv64_mail"
	TypeIPv64SMS  Type = "ipv64_sms"
	TypeApp       Type = "app"
)

// Types in Anzeigereihenfolge.
var Types = []Type{TypeSMTP, TypeTelegram, TypeDiscord, TypeNtfy, TypeGotify, TypePushover, TypeWebhook}

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
	RemoteID        int64 // ID auf dem Server (Sync); 0 = nicht abgeglichen
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
	TypePushover: {
		{Key: "user_key", Secret: true, Required: true, Kind: "password"}, {Key: "app_token", Secret: true, Required: true, Kind: "password"},
		{Key: "device"},
		{Key: "priority_down", Kind: "select", Options: []string{"-2", "-1", "0", "1", "2"}, Default: "1"},
		{Key: "priority_up", Kind: "select", Options: []string{"-2", "-1", "0", "1", "2"}, Default: "0"},
	},
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
}

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
func (c *Channel) Validate() error {
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
		if f.Required && v == "" {
			return fmt.Errorf("%s is required", f.Key)
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
	case TypeGotify:
		return g("server")
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
	}
	return ""
}
