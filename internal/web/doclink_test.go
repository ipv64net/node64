package web

import (
	"strings"
	"testing"
)

// Doku-Links: Sprache der Oberflaeche, Sprungmarke, Uebersicht ohne Seite, Ausgabe escaped.
func TestDocURL(t *testing.T) {
	de, en := &View{Lang: "de"}, &View{Lang: "en"}
	for _, c := range []struct {
		v        *View
		ref, url string
	}{
		{de, "dyndns#ziele", "https://node64.de/docs/dyndns/#ziele"},
		{en, "dyndns#ziele", "https://node64.de/en/docs/dyndns/#ziele"},
		{de, "", "https://node64.de/docs/"},
		{en, "cdn64-online", "https://node64.de/en/docs/cdn64-online/"},
		{de, `x"><script>#a b`, "https://node64.de/docs/x%22%3E%3Cscript%3E/#a%20b"},
	} {
		if got := c.v.DocURL(c.ref); got != c.url {
			t.Errorf("%s %q: %s, want %s", c.v.Lang, c.ref, got, c.url)
		}
	}
	if strings.Contains(de.DocURL(`"<>`), `"`) {
		t.Error("unescaped")
	}
}
