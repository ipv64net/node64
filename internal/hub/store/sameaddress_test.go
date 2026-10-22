package store

import "testing"

// Gleiche Nummer bzw. Adresse in anderer Schreibweise setzt die Bestaetigung nicht zurueck, eine andere schon.
func TestSameAddress(t *testing.T) {
	for _, x := range []struct {
		k, old, v string
		want      bool
	}{
		{"number", "491771234567", "00491771234567", true},   // Portal: "+49 177 …" ohne Plus gespeichert
		{"number", "00491771234567", "00491771234567", true}, // Portal: "0049 177 …"
		{"number", "491771234568", "00491771234567", false},
		{"number", "", "00491771234567", false},
		{"email", "Dennis@Example.de", "dennis@example.de", true},
		{"email", "a@example.de", "b@example.de", false},
	} {
		if got := sameAddress(x.k, x.old, x.v); got != x.want {
			t.Fatalf("%s %q %q: %v", x.k, x.old, x.v, got)
		}
	}
}
