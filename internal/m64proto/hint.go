package m64proto

import (
	"regexp"
	"strings"
)

// Hinweise als Code. Agent und SSH-Abfrage kennen die Sprache der Oberflaeche nicht: bekannte Hinweise und
// Fehlerteile stehen deshalb als Code im Text – "{m64:reading}", mit Werten "{m64:missing=smartctl}", auch mitten
// im Text ("smartctl: {m64:timeout}"). Die Node ersetzt sie durch den Text in der Sprache des Betrachters
// (monitor64.note.<code>, Werte als {a}, {b}); alles andere (Meldungen von Programmen) bleibt, wie es ist. Aeltere
// Agents schicken deutsche Texte ohne Code, die zeigt die Node unveraendert. Neue Codes nur anhaengen; eine Node,
// die einen Code nicht kennt, zeigt ihn roh.
const (
	HintReading       = "{m64:reading}"        // wird gelesen (erster Lauf im Hintergrund noch nicht fertig)
	HintTimeout       = "{m64:timeout}"        // Zeitlimit
	HintNotFound      = "{m64:not_found}"      // Programm fehlt
	HintFormat        = "{m64:format}"         // unbekanntes Format
	HintNoSystemd     = "{m64:no_systemd}"     // kein systemd
	HintNoPkgManager  = "{m64:no_pkg_manager}" // kein Paketverwalter erkannt
	HintUpgradeLocked = "{m64:upgrade_locked}" // System verweigert Upgrades ueber den Paketverwalter (UGOS)
	HintSecUnknown    = "{m64:sec_unknown}"    // Sicherheitsupdates unbekannt (danach ": " und der Grund)
	HintNotParsable   = "{m64:not_parsable}"   // keine Auswertung moeglich
	HintNoOutput      = "{m64:no_output}"      // keine Monitor64-Ausgabe
	HintIncomplete    = "{m64:incomplete}"     // Ausgabe unvollstaendig (Zeitlimit oder Abbruch)
	HintNoSmartDisks  = "{m64:no_smart_disks}" // keine Platten mit SMART gefunden
	HintNoJSON        = "{m64:no_json}"        // keine JSON-Ausgabe (smartctl < 7?)
	HintSmartUnavail  = "{m64:smart_unavail}"  // SMART nicht verfuegbar
	HintSmartDisabled = "{m64:smart_disabled}" // SMART ausgeschaltet
	HintDevUnreadable = "{m64:dev_unreadable}" // Geraet nicht lesbar
	HintUnreadable    = "{m64:unreadable}"     // Ausgabe nicht lesbar
	HintUnknownError  = "{m64:unknown_error}"  // unbekannter Fehler
	HintNoCount       = "{m64:no_count}"       // keine Anzahl geliefert
	HintPkgMissing    = "{m64:pkg_missing}"    // pkg nicht installiert (FreeBSD)
	HintNoRepo        = "{m64:no_repo}"        // keine Paketquelle eingeschaltet (FreeBSD)
	HintNoVulnDB      = "{m64:no_vuln_db}"     // keine Schwachstellen-Datenbank (pkg audit -F)
	HintNoDisks       = "{m64:no_disks}"       // keine Platten gefunden (Windows)

	HintCountersUnreadable = "{m64:counters_unreadable}" // Zuverlaessigkeitszaehler nicht lesbar (Administratorrechte noetig?)
)

// Codes mit Werten (Hint).
const (
	HintMissing    = "missing"      // a fehlt (Programm)
	HintHung       = "hung"         // haengt seit a
	HintExitCode   = "exit_code"    // Exit-Code a
	HintNoOutputOf = "no_output_of" // keine Ausgabe von a
	HintSudoDenied = "sudo_denied"  // sudo -n a nicht erlaubt
	HintTooLarge   = "too_large"    // Ausgabe zu gross (a Bytes, hoechstens b)
	HintDevErrors  = "dev_errors"   // Geraetefehler a (ZFS: "READ 0 WRITE 0 CKSUM 12")
	HintSlowFailed = "slow_failed"  // langsame Abfrage fehlgeschlagen (danach ": " und der Grund)
	HintMember     = "member"       // Mitglied a (Bond-Mitglied ohne Namen)
	HintRunning    = "running"      // laeuft: a (laufender Kernel bei "Neustart noetig")
	HintLargerThan = "larger_than"  // Ausgabe groesser als a Byte
)

// Hint baut einen Hinweis-Code mit Werten: Hint(HintMissing, "smartctl") -> "{m64:missing=smartctl}". Werte sind
// kurze Texte (Programmname, Zahl, Dauer); Klammern und Semikolon darin werden ersetzt.
func Hint(code string, args ...string) string {
	if len(args) == 0 {
		return "{m64:" + code + "}"
	}
	vals := make([]string, len(args))
	for i, a := range args {
		vals[i] = hintArg.Replace(a)
	}
	return "{m64:" + code + "=" + strings.Join(vals, ";") + "}"
}

var (
	hintArg = strings.NewReplacer("{", "(", "}", ")", ";", ",")
	reHint  = regexp.MustCompile(`\{m64:([a-z0-9_]+)(?:=([^{}]*))?\}`)
)

// ReplaceHints ruft f fuer jeden Hinweis-Code in s auf und setzt dessen Ergebnis ein; liefert f false (Code
// unbekannt), bleibt der Code stehen. text bearbeitet die Teile dazwischen (freier Text vom Host; nil = unveraendert).
// Die Aufrufe kommen in der Reihenfolge des Texts.
func ReplaceHints(s string, f func(code string, args []string) (string, bool), text func(string) string) string {
	if text == nil {
		text = func(t string) string { return t }
	}
	if !strings.Contains(s, "{m64:") {
		return text(s)
	}
	var b strings.Builder
	pos := 0
	for _, m := range reHint.FindAllStringSubmatchIndex(s, -1) {
		b.WriteString(text(s[pos:m[0]]))
		var args []string
		if m[4] >= 0 {
			args = strings.Split(s[m[4]:m[5]], ";")
		}
		if out, ok := f(s[m[2]:m[3]], args); ok {
			b.WriteString(out)
		} else {
			b.WriteString(text(s[m[0]:m[1]]))
		}
		pos = m[1]
	}
	b.WriteString(text(s[pos:]))
	return b.String()
}

// Localize wendet f genau einmal auf die Texte der Abschnittsfehler und Hinweise an (die Node macht daraus Texte
// fuer die Anzeige, siehe ReplaceHints); weitere Aufrufe aendern nichts.
func (r *Report) Localize(f func(string) string) {
	if r == nil || r.localized {
		return
	}
	r.localized = true
	for i := range r.Errors {
		r.Errors[i].Error = f(r.Errors[i].Error)
	}
	for i := range r.Notes {
		r.Notes[i].Note = f(r.Notes[i].Note)
	}
}
