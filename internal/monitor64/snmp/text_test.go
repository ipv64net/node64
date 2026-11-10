package snmp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// Texte in den Profilen: fester Text oder ein Token, dessen Schluessel es in Deutsch und Englisch gibt (sonst sieht
// der Betrachter den Schluessel). Ein Profil mit deutschem Text ohne Token faellt hier nicht auf – dafuer nennt der
// Test, wie viele Texte uebersetzbar sind.
func TestProfileTexts(t *testing.T) {
	b, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	tokens, literals := 0, 0
	check := func(prof, field, s string) {
		t.Helper()
		if s == "" {
			return
		}
		if !strings.Contains(s, "i18n:") {
			literals++
			if strings.ContainsAny(s, "äöüßÄÖÜ") {
				t.Errorf("%s: %s %q sieht nach deutschem Text aus – als Token (i18n:monitor64.snmp.…) schreiben", prof, field, s)
			}
			return
		}
		tokens++
		key, ok := model.Key(fill(s, "x", "1"))
		if !ok {
			t.Errorf("%s: %s %q ist kein gueltiges Token", prof, field, s)
			return
		}
		for _, lang := range []string{"de", "en"} {
			if b.T(lang, key) == key {
				t.Errorf("%s: %s: Text %s fehlt (%s)", prof, field, key, lang)
			}
		}
		if strings.Contains(s, "{name}") && !strings.Contains(b.T("en", key), "{name}") {
			t.Errorf("%s: %s: Text %s hat keinen Platzhalter {name}", prof, field, key)
		}
	}
	value := func(prof string, v Value) {
		check(prof, "label", v.Label)
		for _, x := range v.Text {
			check(prof, "text", x)
		}
		if v.Fact != nil {
			check(prof, "fact.text", v.Fact.Text)
		}
	}
	for _, p := range Profiles() {
		for _, s := range p.Scalars {
			check(p.ID, "service", s.Service)
			value(p.ID, s.Value)
		}
		for _, tb := range p.Tables {
			check(p.ID, "service", tb.Service)
			for _, c := range tb.Columns {
				value(p.ID, c.Value)
			}
		}
	}
	if tokens < 80 || literals < 10 {
		t.Fatalf("nur %d uebersetzbare und %d feste Texte in den Profilen", tokens, literals)
	}
	// kaputtes Token im Profil ist ein Fehler beim Laden
	bad := `{"id":"x","name":"X","match":{"probe":".1.3"},"scalars":[{"key":"a","service":"i18n:kaputt","kind":"hw","oid":".1.3.1","label":"L"}]}`
	if _, err := ParseProfile([]byte(bad)); err == nil || !strings.Contains(err.Error(), "Token") {
		t.Errorf("kaputtes Token angenommen: %v", err)
	}
	ok := `{"id":"x","name":"X","match":{"probe":".1.3"},"tables":[{"key":"d:{name}","service":"i18n:monitor64.svc.disk?name={name}","kind":"disk","oid":".1.3.1","name_col":1,"columns":[{"col":2,"label":"i18n:monitor64.snmp.model"}]}]}`
	if _, err := ParseProfile([]byte(ok)); err != nil {
		t.Errorf("gueltiges Profil abgelehnt: %v", err)
	}
	// Platzhalter: im Token kodiert, im festen Text entschaerft
	if got := profText("i18n:monitor64.svc.disk?name={name}", "a b/c", "1"); modeltest.DE(got) != "Platte a b/c" || modeltest.EN(got) != "Disk a b/c" {
		t.Errorf("profText Token = %q", got)
	}
	if got := profText("ZFS {name}", "i18n:monitor64.state.ok", "1"); got != "ZFS i18n: monitor64.state.ok" {
		t.Errorf("profText fest = %q", got)
	}
	if got := profText("i18n:monitor64.svc.disk?name={name}", "i18n:monitor64.state.ok&x=1", "1"); modeltest.DE(got) != "Platte i18n: monitor64.state.ok&x=1" {
		t.Errorf("profText feindlich = %q / %q", got, modeltest.DE(got))
	}
}

// Ein Geraet darf ueber keinen Text (Namen von Ports, Sensoren, Platten, Pools, Beschreibungen) ein eigenes Token
// einschleusen: alle Texte jeder Aufzeichnung werden durch ein Token ersetzt, danach darf kein Dienst es enthalten.
func TestNoInjection(t *testing.T) {
	const evil = "i18n:monitor64.state.crit"
	walks, _ := filepath.Glob("testdata/*.walk")
	if len(walks) < 5 {
		t.Fatalf("Aufzeichnungen fehlen: %v", walks)
	}
	for _, w := range walks {
		m := loadWalk(t, w)
		n := 0
		for o, p := range m.vals {
			if p.Type != gosnmp.OctetString || o == oidSysDescr {
				continue // sysDescr bleibt, damit die Profile weiter passen
			}
			if b, ok := p.Value.([]byte); ok && len(b) > 0 && isText(b) {
				m.set(o, gosnmp.OctetString, []byte(evil))
				n++
			}
		}
		if n == 0 {
			t.Fatalf("%s: keine Texte ersetzt", w)
		}
		c, _, now := newTestCollector(t, m, Config{Custom: []CustomOID{{OID: oidSysName, Name: evil}}})
		check := func(what, text string) {
			t.Helper()
			for _, k := range model.Keys(text) {
				if k == "monitor64.state.crit" {
					t.Errorf("%s: %s enthaelt ein Token des Geraets: %q", w, what, text)
				}
			}
			if strings.Contains(modeltest.DE(text), "Kritisch") {
				t.Errorf("%s: %s uebersetzt den Text des Geraets: %q", w, what, modeltest.DE(text))
			}
		}
		for round := 0; round < 2; round++ {
			svcs, err := c.Collect(context.Background())
			if err != nil {
				check("Fehler", err.Error())
			}
			if len(svcs) == 0 {
				t.Fatalf("%s: keine Dienste (%v)", w, err)
			}
			for _, s := range svcs {
				check(s.Key+" Name", s.Name)
				check(s.Key+" Text", s.Text)
				for _, f := range s.Facts {
					check(s.Key+" Fact "+f.Code, f.Text)
				}
			}
			*now = now.Add(time.Minute)
		}
		d, err := c.Discover(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", w, err)
		}
		check("Zusammenfassung", d.Summary)
		check("Warnung", d.Warning)
	}
}

// isText: der Wert ist lesbarer Text (kein MAC-Adresse, Bitfeld ...).
func isText(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return true
}
