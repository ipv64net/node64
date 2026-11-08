package groups

import (
	"strings"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

// Anzeige der Kategorien einer Gruppe bzw. eines Zeitplans: Kategorien (social ...) und Dienste ("svc:<id>")
// getrennt, Dienste mit ihrem Namen.

func catKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		if !strings.HasPrefix(k, filter.ServicePrefix) {
			out = append(out, k)
		}
	}
	return out
}

func serviceNames(keys []string) []string {
	var out []string
	for _, k := range keys {
		if n := filter.ServiceName(k); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// CatKeys: gesperrte Kategorien ohne Dienste.
func (g Group) CatKeys() []string { return catKeys(g.Cats) }

// ServiceNames: Namen der gesperrten Dienste.
func (g Group) ServiceNames() []string { return serviceNames(g.Cats) }

// CatKeys: Kategorien des Zeitplans ohne Dienste.
func (s Schedule) CatKeys() []string { return catKeys(s.Cats) }

// ServiceNames: Namen der Dienste, die der Zeitplan sperrt.
func (s Schedule) ServiceNames() []string { return serviceNames(s.Cats) }

// TagList: Tags als Text fuer das Formular ("Kueche, MQTT").
func (m Member) TagList() string { return strings.Join(m.Tags, ", ") }

// TagAttr: Tags fuer den Filter der Seite (klein, mit "|" getrennt).
func (m Member) TagAttr() string { return strings.ToLower(strings.Join(m.Tags, "|")) }
