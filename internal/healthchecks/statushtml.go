package healthchecks

import (
	"errors"
	"io"
)

// Statusseiten: HTML der oeffentlichen Seite (eigenstaendig, ohne die Oberflaeche der Node), Badges.
// PLATZHALTER: wird von der Sitzung "Statusseite Oberflaeche" ersetzt (Signaturen bleiben).

// statusRenderOpts steuert die Ausgabe der oeffentlichen Seite.
type statusRenderOpts struct {
	Base          string                               // URL-Praefix der Seite: "/status/<slug>" (Node-Port) oder "" (eigene Domain)
	Lang          string                               // de | en
	Nonce         string                               // CSP-Nonce fuer das eingebettete <style>/<script>
	NoIndex       bool                                 // <meta name="robots" content="noindex">
	NeedPassword  bool                                 // statt der Seite das Passwortformular zeigen
	PasswordWrong bool                                 // Hinweis "Passwort falsch"
	Preview       bool                                 // Vorschau in der Verwaltung (Banner "Vorschau")
	T             func(key string, args ...any) string // Uebersetzung (hc.status.pub.*, hc.reasons.*)
}

// renderStatusHTML schreibt die ganze Seite (v darf bei NeedPassword nil sein).
func renderStatusHTML(w io.Writer, v *StatusView, o statusRenderOpts) error {
	return errors.New("status pages: html not implemented yet")
}

// statusBadgeSVG erzeugt ein Badge im ueblichen Stil (links label, rechts value in color).
func statusBadgeSVG(label, value, color string) []byte {
	return nil
}
