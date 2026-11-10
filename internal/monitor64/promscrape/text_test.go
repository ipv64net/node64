package promscrape

import (
	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// de ist der deutsche Text, den ein Betrachter sieht (Texte und Fehler des Sammlers sind uebersetzbar).
func de(s string) string { return modeltest.DE(s) }

// deErr: deutscher Text eines Fehlers ("" bei nil).
func deErr(err error) string {
	if err == nil {
		return ""
	}
	return de(err.Error())
}

// deRes: Ergebnis von "Verbindung testen" mit deutschen Texten.
func deRes(r apis.TestResult) apis.TestResult {
	r.Error, r.Warning, r.Summary = de(r.Error), de(r.Warning), de(r.Summary)
	return r
}
