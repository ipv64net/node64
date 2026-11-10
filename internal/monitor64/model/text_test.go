package model

import (
	"fmt"
	"strings"
	"testing"
)

// Kleines Woerterbuch wie i18n.Bundle.T: unbekannte Schluessel kommen als Schluessel zurueck.
var testTexts = map[string]map[string]string{
	"de": {"monitor64.txt.free": "{v} frei", "monitor64.svc.fs": "Dateisystem {name}", "monitor64.txt.readonly": "nur lesbar",
		"monitor64.detail.threshold": "{metric} {value} (Schwelle {limit})", "monitor64.kind.mem_used": "RAM belegt",
		"monitor64.unit.days": "Tage", "monitor64.state.ok": "OK"},
	"en": {"monitor64.txt.free": "{v} free", "monitor64.svc.fs": "Filesystem {name}", "monitor64.txt.readonly": "read-only",
		"monitor64.detail.threshold": "{metric} {value} (threshold {limit})", "monitor64.kind.mem_used": "RAM used",
		"monitor64.unit.days": "days", "monitor64.state.ok": "OK"},
}

func tr(lang string) func(string, ...any) string {
	return func(key string, args ...any) string {
		msg, ok := testTexts[lang][key]
		if !ok {
			return key
		}
		for i := 0; i+1 < len(args); i += 2 {
			msg = strings.ReplaceAll(msg, "{"+fmt.Sprint(args[i])+"}", fmt.Sprint(args[i+1]))
		}
		return msg
	}
}

func TestToken(t *testing.T) {
	if got := T("monitor64.txt.readonly"); got != "i18n:monitor64.txt.readonly" {
		t.Fatalf("ohne Werte: %q", got)
	}
	// Werte werden kodiert (sortiert nach Namen), Zahlen direkt
	if got := T("monitor64.svc.fs", "name", "/mnt/a b&c;d", "n", 3); got != "i18n:monitor64.svc.fs?n=3&name=%2Fmnt%2Fa+b%26c%3Bd" {
		t.Fatalf("mit Werten: %q", got)
	}
	if k, ok := Key(T("monitor64.svc.fs", "name", "x")); !ok || k != "monitor64.svc.fs" {
		t.Fatalf("Key = %q %v", k, ok)
	}
	for _, s := range []string{"", "Dateisystem /", "x i18n:monitor64.txt.free", "i18n:other.key", "i18n:monitor64.txt.free?v=%zz", "i18n:monitor64.txt.free extra"} {
		if _, ok := Key(s); ok {
			t.Errorf("Key(%q) gilt als Token", s)
		}
	}
	if got := Join("", "ONLINE", "", T("monitor64.txt.readonly")); got != "ONLINE · i18n:monitor64.txt.readonly" {
		t.Fatalf("Join = %q", got)
	}
}

// Zusammengesetzte Texte: mehrere Token und feste Teile, in beiden Sprachen; Groessen bleiben, wie sie sind.
func TestTranslateComposite(t *testing.T) {
	s := "ONLINE · " + T("monitor64.txt.free", "v", "3,0 GB") + " · " + T("monitor64.txt.readonly") + ", 45 °C"
	if got := Translate(s, tr("de")); got != "ONLINE · 3,0 GB frei · nur lesbar, 45 °C" {
		t.Errorf("de = %q", got)
	}
	if got := Translate(s, tr("en")); got != "ONLINE · 3,0 GB free · read-only, 45 °C" {
		t.Errorf("en = %q", got)
	}
	// Satzzeichen direkt nach dem Token gehoeren nicht dazu (ausser . - _ ~)
	for in, want := range map[string]string{
		"(" + T("monitor64.txt.readonly") + ")":                                           "(nur lesbar)",
		T("monitor64.txt.readonly") + ": x; " + T("monitor64.state.ok"):                   "nur lesbar: x; OK",
		T("monitor64.svc.fs", "name", "/") + ", " + T("monitor64.svc.fs", "name", "/var"): "Dateisystem /, Dateisystem /var",
		"SSH: " + T("monitor64.txt.free", "v", "1 B") + "\nzweite Zeile":                  "SSH: 1 B frei\nzweite Zeile",
	} {
		if got := Translate(in, tr("de")); got != want {
			t.Errorf("%q = %q, erwartet %q", in, got, want)
		}
	}
	// ohne Token, leere und alte gespeicherte deutsche Texte bleiben unveraendert
	for _, s := range []string{"", "Arbeitsspeicher", "Dateisystem / · 3 GB frei", "gestoppt, soll laufen (beim Booten starten)"} {
		if got := Translate(s, tr("en")); got != s {
			t.Errorf("alter Text %q = %q", s, got)
		}
	}
	if got := Translate(T("monitor64.txt.readonly"), nil); got != T("monitor64.txt.readonly") {
		t.Errorf("ohne Uebersetzer = %q", got)
	}
}

// Ein Parameter mit eigenem Text (Sub) wird mit uebersetzt; alle anderen Werte sind fertige Texte.
func TestTranslateSub(t *testing.T) {
	s := T("monitor64.detail.threshold", "metric", Sub(T("monitor64.kind.mem_used")), "value", Sub("92 %"),
		"limit", Sub("7 "+T("monitor64.unit.days")))
	if got := Translate(s, tr("de")); got != "RAM belegt 92 % (Schwelle 7 Tage)" {
		t.Errorf("de = %q", got)
	}
	if got := Translate(s, tr("en")); got != "RAM used 92 % (threshold 7 days)" {
		t.Errorf("en = %q", got)
	}
	// zu tiefe Verschachtelung: kein Absturz, kein Token im Ergebnis
	deep := T("monitor64.state.ok")
	for i := 0; i < 7; i++ {
		deep = T("monitor64.svc.fs", "name", Sub(deep))
	}
	if got := Translate(deep, tr("de")); len(Keys(got)) != 0 || !strings.HasPrefix(got, "Dateisystem Dateisystem ") {
		t.Errorf("tief = %q", got)
	}
}

// Ein Geraet darf kein eigenes Token einschleusen: weder als Parameter noch als fester Teil (Raw), und das Ergebnis
// einer Uebersetzung wird bei einem zweiten Durchlauf nicht noch einmal uebersetzt.
func TestNoInjection(t *testing.T) {
	evil := "i18n:monitor64.state.ok"
	// als Parameter: bleibt Text
	s := T("monitor64.svc.fs", "name", evil)
	got := Translate(s, tr("de"))
	if strings.Contains(got, "OK") || got != "Dateisystem i18n: monitor64.state.ok" {
		t.Errorf("Parameter = %q", got)
	}
	if again := Translate(got, tr("de")); again != got {
		t.Errorf("zweiter Durchlauf aendert %q in %q", got, again)
	}
	// verschachtelt kodiert (Parameter im Parameter)
	s = T("monitor64.svc.fs", "name", T("monitor64.svc.fs", "name", evil))
	if got := Translate(s, tr("de")); strings.Contains(got, "OK") || len(Keys(got)) != 0 {
		t.Errorf("verschachtelt = %q", got)
	}
	// als fester Teil neben einem Token
	s = "ZFS " + Raw(evil+" tank") + " · " + T("monitor64.txt.readonly")
	if got := Translate(s, tr("de")); got != "ZFS i18n: monitor64.state.ok tank · nur lesbar" {
		t.Errorf("fester Teil = %q", got)
	}
	// Raw: nur Text mit Token-Anfang aendert sich, mehrfach angewendet bleibt er gleich
	for in, want := range map[string]string{"": "", "eth0": "eth0", "i18n:": "i18n:", "x i18n:a.b y i18n:c": "x i18n: a.b y i18n: c",
		"I18N:monitor64.x": "I18N:monitor64.x", "i18n: schon": "i18n: schon"} {
		if got := Raw(in); got != want || Raw(got) != got || len(Keys(got)) != 0 {
			t.Errorf("Raw(%q) = %q", in, got)
		}
	}
	// fremde und kaputte Token werden nicht uebersetzt und sind danach keine Token mehr
	for _, in := range []string{"i18n:nav.dashboard", "i18n:monitor64.txt.free?v=%zz", "i18n:monitor64.txt.free?v=a;b"} {
		got := Translate(in, tr("de"))
		if strings.Contains(got, "frei") && in != "i18n:monitor64.txt.free?v=a;b" {
			t.Errorf("%q uebersetzt: %q", in, got)
		}
		if again := Translate(got, tr("de")); again != got {
			t.Errorf("%q: zweiter Durchlauf aendert %q in %q", in, got, again)
		}
	}
	// HTML bleibt Sache des Aufrufers: Werte kommen unveraendert (und werden danach escaped)
	if got := Translate(T("monitor64.svc.fs", "name", `<script>alert(1)</script>`), tr("de")); got != "Dateisystem <script>alert(1)</script>" {
		t.Errorf("HTML = %q", got)
	}
}

// Unbekannte Schluessel (Text einer neueren Version): Schluessel und Werte zeigen statt des rohen Tokens.
func TestTranslateUnknownKey(t *testing.T) {
	if got := Translate(T("monitor64.txt.neu", "a", "1", "b", "zwei"), tr("de")); got != "txt.neu (1, zwei)" {
		t.Errorf("unbekannt = %q", got)
	}
	if got := Translate(T("monitor64.txt.neu"), tr("de")); got != "txt.neu" {
		t.Errorf("unbekannt ohne Werte = %q", got)
	}
}

func TestKeys(t *testing.T) {
	s := "a " + T("monitor64.txt.free", "v", "1") + " b " + T("monitor64.svc.fs", "name", "i18n:monitor64.state.ok")
	if got := strings.Join(Keys(s), ","); got != "monitor64.txt.free,monitor64.svc.fs" {
		t.Errorf("Keys = %q", got)
	}
}
