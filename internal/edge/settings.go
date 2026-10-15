package edge

import "strconv"

// Schluessel der Einstellungen des Eingangs (Kern).
const (
	SetBind       = "edge.bind"
	SetHTTPPort   = "edge.http_port"
	SetHTTPSPort  = "edge.https_port"
	SetPublicPort = "edge.public_port"
	SetHTTP3      = "edge.http3"
	SetDefault    = "edge.default"
	SetDefaultURL = "edge.default_url"
	SetDefaultPg  = "edge.default_html"
)

// LoadConfig liest die Einstellungen (fehlende bzw. ungueltige Werte = Standard).
func LoadConfig(get func(key, def string) string) Config {
	d := DefaultConfig()
	num := func(key string, def int) int {
		n, err := strconv.Atoi(get(key, strconv.Itoa(def)))
		if err != nil || n < 0 || n > 65535 {
			return def
		}
		return n
	}
	c := Config{Bind: get(SetBind, d.Bind), HTTPPort: num(SetHTTPPort, d.HTTPPort), HTTPSPort: num(SetHTTPSPort, d.HTTPSPort),
		PublicPort: num(SetPublicPort, d.PublicPort), HTTP3: get(SetHTTP3, "1") == "1", Default: get(SetDefault, d.Default),
		DefaultURL: get(SetDefaultURL, ""), DefaultPage: get(SetDefaultPg, "")}
	if c.Validate() != nil {
		c.Default, c.DefaultURL, c.DefaultPage = DefaultNotFound, "", "" // nur die Standardseite ist ungueltig
		if c.Validate() != nil {
			return d
		}
	}
	return c
}

// Settings: die Einstellungen als Schluessel/Wert zum Speichern.
func (c Config) Settings() map[string]string {
	h3 := "0"
	if c.HTTP3 {
		h3 = "1"
	}
	return map[string]string{SetBind: c.Bind, SetHTTPPort: strconv.Itoa(c.HTTPPort), SetHTTPSPort: strconv.Itoa(c.HTTPSPort),
		SetPublicPort: strconv.Itoa(c.PublicPort), SetHTTP3: h3, SetDefault: c.Default, SetDefaultURL: c.DefaultURL, SetDefaultPg: c.DefaultPage}
}
