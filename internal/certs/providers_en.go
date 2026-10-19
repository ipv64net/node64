package certs

// Englische Texte der DNS-Anbieter (Name, Hinweis, Feldbeschriftung). Registriert wird auf Deutsch; ProvidersFor
// liefert fuer jede andere Sprache die englische Fassung. Fehlt ein Eintrag, bleibt der Text wie registriert.
var providerEN = map[string]string{
	// Namen
	"HTTP-Request (eigener Dienst)":   "HTTP request (own service)",
	"PowerDNS (eigener Server)":       "PowerDNS (own server)",
	"Technitium DNS (eigener Server)": "Technitium DNS (own server)",
	// Hinweise
	"https://console.hetzner.com (Security → API-Tokens)":                                           "https://console.hetzner.com (Security → API tokens)",
	"https://www.customercontrolpanel.de (Stammdaten → API)":                                        "https://www.customercontrolpanel.de (Master data → API)",
	"https://www.inwx.de (Konto → API-Zugang)":                                                      "https://www.inwx.de (Account → API access)",
	"https://developer.hosting.ionos.de (Präfix.Secret)":                                            "https://developer.hosting.ionos.de (prefix.secret)",
	"https://kas.all-inkl.com (KAS-Login)":                                                          "https://kas.all-inkl.com (KAS login)",
	"https://login.autodns.com (API-Benutzer)":                                                      "https://login.autodns.com (API user)",
	"https://www.checkdomain.de (Konto → API)":                                                      "https://www.checkdomain.de (Account → API)",
	"https://www.cloudns.net (API → Auth-ID oder Sub-Auth-ID)":                                      "https://www.cloudns.net (API → auth ID or sub auth ID)",
	"POST <URL>/present und /cleanup mit {fqdn, value} (lego httpreq)":                              "POST <URL>/present and /cleanup with {fqdn, value} (lego httpreq)",
	"dns.he.net: TXT-Eintrag _acme-challenge anlegen, „Dynamic DNS“ aktivieren, Schlüssel erzeugen": "dns.he.net: create a TXT record _acme-challenge, enable “Dynamic DNS”, generate a key",
	"https://manager.infomaniak.com/v3/infomaniak-api (Bereich domain)":                             "https://manager.infomaniak.com/v3/infomaniak-api (scope domain)",
	"https://ap.www.namecheap.com/settings/tools/apiaccess/ (IP freigeben)":                         "https://ap.www.namecheap.com/settings/tools/apiaccess/ (whitelist the IP)",
	"dynamische Updates mit TSIG-Schlüssel (z. B. tsig-keygen)":                                     "dynamic updates with a TSIG key (e.g. tsig-keygen)",
	// Felder
	"API-Token":                              "API token",
	"Kundennummer":                           "Customer number",
	"API-Passwort":                           "API password",
	"Benutzer":                               "User",
	"Passwort":                               "Password",
	"2FA-Schlüssel":                          "2FA secret",
	"API-Key (Präfix.Secret)":                "API key (prefix.secret)",
	"API-Key":                                "API key",
	"Secret-API-Key":                         "Secret API key",
	"API-Secret":                             "API secret",
	"Endpunkt":                               "Endpoint",
	"KAS-Login":                              "KAS login",
	"KAS-Passwort":                           "KAS password",
	"Kontext":                                "Context",
	"Auth-ID":                                "Auth ID",
	"Sub-Auth-ID":                            "Sub auth ID",
	"Modus (leer oder RAW)":                  "Mode (empty or RAW)",
	"Domain:Schlüssel (mehrere mit Komma)":   "Domain:key (several separated by commas)",
	"API-Benutzer":                           "API user",
	"Freigegebene IPv4 (leer = automatisch)": "Whitelisted IPv4 (empty = automatic)",
	"API-URL (z. B. http://192.168.1.2:8081)": "API URL (e.g. http://192.168.1.2:8081)",
	"Servername":                          "Server name",
	"Nameserver (Host oder Host:Port)":    "Name server (host or host:port)",
	"TSIG-Schlüsselname":                  "TSIG key name",
	"TSIG-Secret (Base64)":                "TSIG secret (Base64)",
	"TSIG-Algorithmus":                    "TSIG algorithm",
	"URL (z. B. http://192.168.1.2:5380)": "URL (e.g. http://192.168.1.2:5380)",
}

func textEN(s string) string {
	if t, ok := providerEN[s]; ok {
		return t
	}
	return s
}

// ProvidersFor: Anbieter in der Sprache lang ("de" wie registriert, sonst Englisch).
func ProvidersFor(lang string) []ProviderInfo {
	list := Providers()
	if lang == "de" {
		return list
	}
	for i := range list {
		p := &list[i]
		p.Name, p.Docs = textEN(p.Name), textEN(p.Docs)
		fs := make([]Field, len(p.Fields))
		for j, f := range p.Fields {
			f.Label = textEN(f.Label)
			fs[j] = f
		}
		p.Fields = fs
	}
	return list
}
