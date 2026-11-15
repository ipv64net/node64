package module

import "strings"

// CSVCell schuetzt eine Zelle eines CSV-Exports vor Formel-Einschleusung: Tabellenprogramme werten = + - @ (und
// Tab/CR) am Anfang als Formel aus, davor kommt ein Hochkomma.
func CSVCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
