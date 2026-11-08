package certs

import (
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/domeneshop"
	"github.com/go-acme/lego/v4/providers/dns/hostingde"
	"github.com/go-acme/lego/v4/providers/dns/luadns"
	"github.com/go-acme/lego/v4/providers/dns/netlify"
	"github.com/go-acme/lego/v4/providers/dns/njalla"
	"github.com/go-acme/lego/v4/providers/dns/simply"
	"github.com/go-acme/lego/v4/providers/dns/spaceship"
	"github.com/go-acme/lego/v4/providers/dns/variomedia"
)

// Weitere Anbieter (2026-11, ipv64net/node64#39): nur solche, die lego ohne grosses SDK anspricht (eigener HTTP-Client
// bzw. schon vorhandene Pakete), damit das Binary klein bleibt.

func init() {
	register(ProviderInfo{ID: "luadns", Name: "LuaDNS", Docs: "https://api.luadns.com/settings (API-Token)",
		Fields: []Field{{Key: "email", Label: "E-Mail"}, {Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := luadns.NewDefaultConfig()
			c.APIUsername, c.APIToken = v["email"], v["token"]
			return luadns.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "hostingde", Name: "hosting.de", Docs: "https://secure.hosting.de (Profil → API-Keys)",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}, {Key: "zone", Label: "Zone (leer = automatisch)", Optional: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := hostingde.NewDefaultConfig()
			c.APIKey, c.ZoneName = v["key"], v["zone"]
			return hostingde.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "variomedia", Name: "Variomedia", Docs: "https://www.variomedia.de (Kundenbereich → API)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := variomedia.NewDefaultConfig()
			c.APIToken = v["token"]
			return variomedia.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "netlify", Name: "Netlify", Docs: "https://app.netlify.com/user/applications (Personal access token)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := netlify.NewDefaultConfig()
			c.Token = v["token"]
			return netlify.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "njalla", Name: "Njalla", Docs: "https://njal.la/settings/api/",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := njalla.NewDefaultConfig()
			c.Token = v["token"]
			return njalla.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "spaceship", Name: "Spaceship", Docs: "https://www.spaceship.com/application/api-manager/ (Rechte: DNS records)",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}, {Key: "secret", Label: "API-Secret", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := spaceship.NewDefaultConfig()
			c.APIKey, c.APISecret = v["key"], v["secret"]
			return spaceship.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "domeneshop", Name: "Domeneshop", Docs: "https://www.domeneshop.no/admin?view=api",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}, {Key: "secret", Label: "API-Secret", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := domeneshop.NewDefaultConfig()
			c.APIToken, c.APISecret = v["token"], v["secret"]
			return domeneshop.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "simply", Name: "Simply.com", Docs: "https://www.simply.com/en/controlpanel/api/",
		Fields: []Field{{Key: "account", Label: "Kontoname (S123456)"}, {Key: "key", Label: "API-Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := simply.NewDefaultConfig()
			c.AccountName, c.APIKey = v["account"], v["key"]
			return simply.NewDNSProviderConfig(c)
		})
}
