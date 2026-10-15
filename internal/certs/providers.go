package certs

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/go-acme/lego/v4/providers/dns/desec"
	"github.com/go-acme/lego/v4/providers/dns/digitalocean"
	"github.com/go-acme/lego/v4/providers/dns/duckdns"
	"github.com/go-acme/lego/v4/providers/dns/gandiv5"
	"github.com/go-acme/lego/v4/providers/dns/godaddy"
	"github.com/go-acme/lego/v4/providers/dns/hetzner"
	"github.com/go-acme/lego/v4/providers/dns/inwx"
	"github.com/go-acme/lego/v4/providers/dns/ionos"
	"github.com/go-acme/lego/v4/providers/dns/netcup"
	"github.com/go-acme/lego/v4/providers/dns/ovh"
	"github.com/go-acme/lego/v4/providers/dns/porkbun"
)

// DNS-Anbieter fuer DNS-01 bei Domains, die nicht bei ipv64 liegen: eine Auswahl der Anbieter aus lego (wie bei
// Traefik und Caddy), damit das Binary klein bleibt. Die Zugangsdaten liegen verschluesselt als "DNS-Zugang".

// Field ist ein Eingabefeld eines Anbieters.
type Field struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Secret   bool   `json:"secret"`
	Optional bool   `json:"optional,omitempty"`
	Default  string `json:"default,omitempty"`
}

// ProviderInfo beschreibt einen Anbieter (fuer Oberflaeche und API).
type ProviderInfo struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Fields []Field `json:"fields"`
	Docs   string  `json:"docs"` // wo es den Schluessel gibt
}

type providerDef struct {
	ProviderInfo
	build func(v map[string]string) (challenge.Provider, error)
}

var providers = map[string]providerDef{}

func register(info ProviderInfo, build func(v map[string]string) (challenge.Provider, error)) {
	providers[info.ID] = providerDef{ProviderInfo: info, build: build}
}

func init() {
	register(ProviderInfo{ID: "cloudflare", Name: "Cloudflare", Docs: "https://dash.cloudflare.com/profile/api-tokens (Zone:DNS:Edit)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := cloudflare.NewDefaultConfig()
			c.AuthToken = v["token"]
			return cloudflare.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "hetzner", Name: "Hetzner", Docs: "https://console.hetzner.com (Security → API-Tokens)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := hetzner.NewDefaultConfig()
			c.APIToken = v["token"]
			return hetzner.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "netcup", Name: "netcup", Docs: "https://www.customercontrolpanel.de (Stammdaten → API)",
		Fields: []Field{{Key: "customer", Label: "Kundennummer"}, {Key: "key", Label: "API-Key", Secret: true}, {Key: "password", Label: "API-Passwort", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := netcup.NewDefaultConfig()
			c.Customer, c.Key, c.Password = v["customer"], v["key"], v["password"]
			c.PropagationTimeout = 15 * time.Minute // netcup veroeffentlicht langsam
			return netcup.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "inwx", Name: "INWX", Docs: "https://www.inwx.de (Konto → API-Zugang)",
		Fields: []Field{{Key: "username", Label: "Benutzer"}, {Key: "password", Label: "Passwort", Secret: true},
			{Key: "shared_secret", Label: "2FA-Schlüssel", Secret: true, Optional: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := inwx.NewDefaultConfig()
			c.Username, c.Password, c.SharedSecret = v["username"], v["password"], v["shared_secret"]
			return inwx.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "ionos", Name: "IONOS", Docs: "https://developer.hosting.ionos.de (Präfix.Secret)",
		Fields: []Field{{Key: "key", Label: "API-Key (Präfix.Secret)", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := ionos.NewDefaultConfig()
			c.APIKey = v["key"]
			return ionos.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "desec", Name: "deSEC", Docs: "https://desec.io (Token Management)",
		Fields: []Field{{Key: "token", Label: "Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := desec.NewDefaultConfig()
			c.Token = v["token"]
			return desec.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "duckdns", Name: "Duck DNS", Docs: "https://www.duckdns.org",
		Fields: []Field{{Key: "token", Label: "Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := duckdns.NewDefaultConfig()
			c.Token = v["token"]
			return duckdns.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "porkbun", Name: "Porkbun", Docs: "https://porkbun.com/account/api",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}, {Key: "secret", Label: "Secret-API-Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := porkbun.NewDefaultConfig()
			c.APIKey, c.SecretAPIKey = v["key"], v["secret"]
			return porkbun.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "godaddy", Name: "GoDaddy", Docs: "https://developer.godaddy.com/keys",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}, {Key: "secret", Label: "API-Secret", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := godaddy.NewDefaultConfig()
			c.APIKey, c.APISecret = v["key"], v["secret"]
			return godaddy.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "digitalocean", Name: "DigitalOcean", Docs: "https://cloud.digitalocean.com/account/api/tokens",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := digitalocean.NewDefaultConfig()
			c.AuthToken = v["token"]
			return digitalocean.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "gandi", Name: "Gandi", Docs: "https://account.gandi.net (Personal Access Token)",
		Fields: []Field{{Key: "token", Label: "Personal Access Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := gandiv5.NewDefaultConfig()
			c.PersonalAccessToken = v["token"]
			return gandiv5.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "ovh", Name: "OVHcloud", Docs: "https://eu.api.ovh.com/createToken/",
		Fields: []Field{{Key: "endpoint", Label: "Endpunkt", Default: "ovh-eu"}, {Key: "app_key", Label: "Application Key", Secret: true},
			{Key: "app_secret", Label: "Application Secret", Secret: true}, {Key: "consumer_key", Label: "Consumer Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := ovh.NewDefaultConfig()
			c.APIEndpoint, c.ApplicationKey, c.ApplicationSecret, c.ConsumerKey = v["endpoint"], v["app_key"], v["app_secret"], v["consumer_key"]
			if c.APIEndpoint == "" {
				c.APIEndpoint = "ovh-eu"
			}
			return ovh.NewDNSProviderConfig(c)
		})
}

// Providers: alle Anbieter, nach Name sortiert.
func Providers() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(providers))
	for _, p := range providers {
		out = append(out, p.ProviderInfo)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// checkValues prueft die Felder eines Anbieters (Pflichtfelder gesetzt, nichts Unbekanntes).
func checkValues(id string, v map[string]string) (map[string]string, error) {
	p, ok := providers[id]
	if !ok {
		return nil, invalid("provider", "unknown provider %q", id)
	}
	out := map[string]string{}
	for _, f := range p.Fields {
		val := strings.TrimSpace(v[f.Key])
		if val == "" {
			val = f.Default
		}
		if val == "" && !f.Optional {
			return nil, invalid("fields", "%s missing", f.Label)
		}
		if len(val) > 500 {
			return nil, invalid("fields", "%s too long", f.Label)
		}
		if val != "" {
			out[f.Key] = val
		}
	}
	return out, nil
}

// buildProvider erzeugt den Anbieter aus gespeicherten Werten.
func buildProvider(id string, v map[string]string) (challenge.Provider, error) {
	p, ok := providers[id]
	if !ok {
		return nil, fmt.Errorf("unknown dns provider %q", id)
	}
	prov, err := p.build(v)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p.Name, err)
	}
	if prov == nil {
		return nil, errors.New("provider not available")
	}
	return prov, nil
}
