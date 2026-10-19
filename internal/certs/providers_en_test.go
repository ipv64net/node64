package certs

import (
	"strings"
	"testing"
)

// Englisch: kein deutscher Text bleibt in Namen, Hinweisen und Feldern; Deutsch bleibt wie registriert.
func TestProvidersEnglish(t *testing.T) {
	german := []string{"ä", "ö", "ü", "ß", "Präfix", "Konto", "Benutzer", "Passwort", "Schlüssel", "eigener", "Modus", "leer", "Bereich",
		"freigeben", "dynamische", "Kundennummer", "Endpunkt", "Kontext", "Freigegebene", "z. B.", "Stammdaten", "anlegen", "oder", "mit "}
	check := func(where, s string) {
		for _, g := range german {
			if strings.Contains(s, g) {
				t.Errorf("%s: %q still contains %q", where, s, g)
			}
		}
	}
	for _, p := range ProvidersFor("en") {
		check(p.ID+" name", p.Name)
		check(p.ID+" docs", p.Docs)
		for _, f := range p.Fields {
			check(p.ID+" field "+f.Key, f.Label)
		}
	}
	de := ProvidersFor("de")
	for _, p := range de {
		if p.ID == "netcup" && p.Fields[0].Label != "Kundennummer" {
			t.Fatalf("german changed: %+v", p.Fields[0])
		}
	}
	if Providers()[0].Fields[0].Label == "" {
		t.Fatal("registry damaged")
	}
	for _, p := range Providers() { // ProvidersFor darf die Registrierung nicht veraendern
		if p.ID == "netcup" && p.Fields[0].Label != "Kundennummer" {
			t.Fatal("ProvidersFor changed the registered labels")
		}
	}
}
