package filter

import (
	"bufio"
	"embed"
	"strings"
)

// Kategorien fuer Geraetegruppen: kleine, von Node64 gepflegte Domainlisten (Soziale Netzwerke, Spiele,
// Streaming) im Image, dazu Kategorien, die eine fertige Blockliste einschalten (Gluecksspiel, Erwachsene).

//go:embed categories/*.txt
var categoryFS embed.FS

// GroupCategories sind alle Kategorien in Anzeigereihenfolge.
var GroupCategories = []string{"social", "games", "streaming", "gambling", "adult"}

// BypassList sperrt fremde DoH-Server, VPNs und Proxys (Schutz gegen Umgehen einer Gruppe).
const BypassList = hagezi + "doh-vpn-proxy-bypass.txt"

// GroupCategoryLists: Kategorien, die eine Vorlage aus MoreLists fuer die Gruppe einschalten.
var GroupCategoryLists = map[string]string{
	"gambling": hagezi + "gambling.txt",
	"adult":    hagezi + "nsfw.txt",
}

var categorySets = func() map[string]*DomainSet {
	out := map[string]*DomainSet{}
	for _, key := range GroupCategories {
		f, err := categoryFS.Open("categories/" + key + ".txt")
		if err != nil {
			continue // Kategorie ueber eine Blockliste
		}
		var list []string
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if l := strings.TrimSpace(sc.Text()); l != "" && l[0] != '#' {
				list = append(list, l)
			}
		}
		f.Close()
		out[key] = NewDomainSet(list)
	}
	return out
}()

// GroupCategory liefert die Domains einer eingebauten Kategorie (nil = keine bzw. ueber eine Blockliste).
func GroupCategory(key string) *DomainSet { return categorySets[key] }

// DomainSet ist eine Menge von Domains, die jeweils samt Subdomains gelten.
type DomainSet struct{ m map[string]bool }

// NewDomainSet legt die Menge an; ungueltige Eintraege fallen weg (IDN als Punycode).
func NewDomainSet(domains []string) *DomainSet {
	d := &DomainSet{m: make(map[string]bool, len(domains))}
	for _, s := range domains {
		if n, ok := normalizeDomain(strings.TrimPrefix(strings.TrimSpace(s), "*.")); ok {
			d.m[n] = true
		}
	}
	return d
}

// Match liefert den Eintrag, der name (klein, ohne Punkt am Ende) enthaelt.
func (d *DomainSet) Match(name string) (string, bool) {
	if d == nil || len(d.m) == 0 {
		return "", false
	}
	for s := name; ; {
		if d.m[s] {
			return s, true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return "", false
		}
		s = s[i+1:]
	}
}

// Len ist die Zahl der Eintraege.
func (d *DomainSet) Len() int {
	if d == nil {
		return 0
	}
	return len(d.m)
}

// NormalizeDomain prueft und vereinheitlicht eine Domain (klein, Punycode, mit Punkt); false = ungueltig.
func NormalizeDomain(s string) (string, bool) {
	return normalizeDomain(strings.TrimPrefix(strings.TrimSpace(s), "*."))
}
