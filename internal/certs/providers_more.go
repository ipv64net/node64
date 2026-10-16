package certs

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns/allinkl"
	"github.com/go-acme/lego/v4/providers/dns/autodns"
	"github.com/go-acme/lego/v4/providers/dns/bunny"
	"github.com/go-acme/lego/v4/providers/dns/checkdomain"
	"github.com/go-acme/lego/v4/providers/dns/cloudns"
	"github.com/go-acme/lego/v4/providers/dns/dynu"
	"github.com/go-acme/lego/v4/providers/dns/hostinger"
	"github.com/go-acme/lego/v4/providers/dns/httpreq"
	"github.com/go-acme/lego/v4/providers/dns/hurricane"
	"github.com/go-acme/lego/v4/providers/dns/infomaniak"
	"github.com/go-acme/lego/v4/providers/dns/namecheap"
	"github.com/go-acme/lego/v4/providers/dns/pdns"
	"github.com/go-acme/lego/v4/providers/dns/rfc2136"
	"github.com/go-acme/lego/v4/providers/dns/technitium"
)

// Weitere Anbieter (Z1): verbreitet im deutschsprachigen Raum, im Homelab (PowerDNS, Technitium, RFC 2136 fuer
// BIND, Knot, pfSense/OPNsense) und allgemein (HTTP-Request). Grosse Cloud-SDKs (AWS, Azure, Google) bewusst nicht.

func parseURL(field, raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%s: http(s)://host expected", field)
	}
	return u, nil
}

func init() {
	register(ProviderInfo{ID: "allinkl", Name: "ALL-INKL.COM", Docs: "https://kas.all-inkl.com (KAS-Login)",
		Fields: []Field{{Key: "login", Label: "KAS-Login"}, {Key: "password", Label: "KAS-Passwort", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := allinkl.NewDefaultConfig()
			c.Login, c.Password = v["login"], v["password"]
			return allinkl.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "autodns", Name: "AutoDNS (InterNetX)", Docs: "https://login.autodns.com (API-Benutzer)",
		Fields: []Field{{Key: "username", Label: "Benutzer"}, {Key: "password", Label: "Passwort", Secret: true}, {Key: "context", Label: "Kontext", Default: "4"}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := autodns.NewDefaultConfig()
			c.Username, c.Password = v["username"], v["password"]
			if n, err := strconv.Atoi(v["context"]); err == nil && n > 0 {
				c.Context = n
			}
			return autodns.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "bunny", Name: "Bunny DNS", Docs: "https://dash.bunny.net/account/api-key",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := bunny.NewDefaultConfig()
			c.APIKey = v["key"]
			return bunny.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "checkdomain", Name: "checkdomain", Docs: "https://www.checkdomain.de (Konto → API)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := checkdomain.NewDefaultConfig()
			c.Token = v["token"]
			c.Endpoint, _ = url.Parse("https://api.checkdomain.de") // sonst nur ueber Umgebungsvariable gesetzt
			return checkdomain.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "cloudns", Name: "ClouDNS", Docs: "https://www.cloudns.net (API → Auth-ID oder Sub-Auth-ID)",
		Fields: []Field{{Key: "auth_id", Label: "Auth-ID", Optional: true}, {Key: "sub_auth_id", Label: "Sub-Auth-ID", Optional: true},
			{Key: "password", Label: "API-Passwort", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			if v["auth_id"] == "" && v["sub_auth_id"] == "" {
				return nil, fmt.Errorf("Auth-ID or Sub-Auth-ID missing")
			}
			c := cloudns.NewDefaultConfig()
			c.AuthID, c.SubAuthID, c.AuthPassword = v["auth_id"], v["sub_auth_id"], v["password"]
			return cloudns.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "dynu", Name: "Dynu", Docs: "https://www.dynu.com/ControlPanel/APICredentials",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := dynu.NewDefaultConfig()
			c.APIKey = v["key"]
			return dynu.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "hostinger", Name: "Hostinger", Docs: "https://hpanel.hostinger.com/profile/api",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := hostinger.NewDefaultConfig()
			c.APIToken = v["token"]
			return hostinger.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "httpreq", Name: "HTTP-Request (eigener Dienst)", Docs: "POST <URL>/present und /cleanup mit {fqdn, value} (lego httpreq)",
		Fields: []Field{{Key: "endpoint", Label: "URL"}, {Key: "mode", Label: "Modus (leer oder RAW)", Optional: true},
			{Key: "username", Label: "Benutzer", Optional: true}, {Key: "password", Label: "Passwort", Secret: true, Optional: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			u, err := parseURL("URL", v["endpoint"])
			if err != nil {
				return nil, err
			}
			c := httpreq.NewDefaultConfig()
			c.Endpoint, c.Mode, c.Username, c.Password = u, strings.ToUpper(v["mode"]), v["username"], v["password"]
			return httpreq.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "hurricane", Name: "Hurricane Electric (dns.he.net)", Docs: "dns.he.net: TXT-Eintrag _acme-challenge anlegen, „Dynamic DNS“ aktivieren, Schlüssel erzeugen",
		Fields: []Field{{Key: "tokens", Label: "Domain:Schlüssel (mehrere mit Komma)", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			creds := map[string]string{}
			for _, pair := range strings.Split(v["tokens"], ",") {
				d, t, ok := strings.Cut(strings.TrimSpace(pair), ":")
				if !ok || d == "" || t == "" {
					return nil, fmt.Errorf("format domain:key expected")
				}
				creds[strings.ToLower(strings.TrimSpace(d))] = strings.TrimSpace(t)
			}
			c := hurricane.NewDefaultConfig()
			c.Credentials = creds
			return hurricane.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "infomaniak", Name: "Infomaniak", Docs: "https://manager.infomaniak.com/v3/infomaniak-api (Bereich domain)",
		Fields: []Field{{Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := infomaniak.NewDefaultConfig()
			c.AccessToken = v["token"]
			return infomaniak.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "namecheap", Name: "Namecheap", Docs: "https://ap.www.namecheap.com/settings/tools/apiaccess/ (IP freigeben)",
		Fields: []Field{{Key: "user", Label: "API-Benutzer"}, {Key: "key", Label: "API-Key", Secret: true},
			{Key: "client_ip", Label: "Freigegebene IPv4 (leer = automatisch)", Optional: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := namecheap.NewDefaultConfig()
			c.APIUser, c.APIKey, c.ClientIP = v["user"], v["key"], v["client_ip"]
			return namecheap.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "pdns", Name: "PowerDNS (eigener Server)", Docs: "pdns.conf: api=yes, api-key=…, webserver=yes",
		Fields: []Field{{Key: "url", Label: "API-URL (z. B. http://192.168.1.2:8081)"}, {Key: "key", Label: "API-Key", Secret: true},
			{Key: "server", Label: "Servername", Default: "localhost"}}},
		func(v map[string]string) (challenge.Provider, error) {
			u, err := parseURL("API-URL", v["url"])
			if err != nil {
				return nil, err
			}
			c := pdns.NewDefaultConfig()
			c.Host, c.APIKey = u, v["key"]
			c.APIVersion = 1 // PowerDNS 4.x; sonst fragt lego die Version schon beim Anlegen uebers Netz ab
			if v["server"] != "" {
				c.ServerName = v["server"]
			}
			return pdns.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "rfc2136", Name: "RFC 2136 (BIND, Knot, pfSense/OPNsense …)", Docs: "dynamische Updates mit TSIG-Schlüssel (z. B. tsig-keygen)",
		Fields: []Field{{Key: "nameserver", Label: "Nameserver (Host oder Host:Port)"}, {Key: "tsig_key", Label: "TSIG-Schlüsselname"},
			{Key: "tsig_secret", Label: "TSIG-Secret (Base64)", Secret: true}, {Key: "tsig_algorithm", Label: "TSIG-Algorithmus", Default: "hmac-sha256."}}},
		func(v map[string]string) (challenge.Provider, error) {
			c := rfc2136.NewDefaultConfig()
			c.Nameserver, c.TSIGKey, c.TSIGSecret = v["nameserver"], v["tsig_key"], v["tsig_secret"]
			if a := v["tsig_algorithm"]; a != "" {
				c.TSIGAlgorithm = strings.TrimSuffix(a, ".") + "."
			}
			c.PropagationTimeout = 5 * time.Minute
			return rfc2136.NewDNSProviderConfig(c)
		})
	register(ProviderInfo{ID: "technitium", Name: "Technitium DNS (eigener Server)", Docs: "Technitium: Administration → Sessions → Create Token",
		Fields: []Field{{Key: "url", Label: "URL (z. B. http://192.168.1.2:5380)"}, {Key: "token", Label: "API-Token", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			u, err := parseURL("URL", v["url"])
			if err != nil {
				return nil, err
			}
			c := technitium.NewDefaultConfig()
			c.BaseURL, c.APIToken = strings.TrimSuffix(u.String(), "/"), v["token"]
			return technitium.NewDNSProviderConfig(c)
		})
}
