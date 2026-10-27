package store

import (
	"testing"

	"github.com/ipv64net/node64/internal/checks"
)

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

// Lange Serien ohne Wechsel duerfen die SMALLINT-Spalten nicht sprengen.
func TestSmallCount(t *testing.T) {
	for _, x := range []struct{ in, want int }{{0, 0}, {5, 5}, {32767, 32767}, {40000, 32767}, {-3, 0}} {
		if got := smallCount(x.in); got != x.want {
			t.Fatalf("%d: %d", x.in, got)
		}
	}
}

// Docker- und Proxmox-Checks misst ipv64 nie online, auch wenn sie in der Datenbank auf online stehen (frueher setzte
// das Entfernen einer Node im Portal sie dorthin).
func TestSingleNodeNeverOnline(t *testing.T) {
	for typ, want := range map[string]bool{"docker": false, "proxmox": false, "http": true} {
		c := &Check{Execution: "online", Locations: []string{"nbg"}}
		c.Type = checks.Type(typ)
		if got := c.MeasuredHere("nbg", nil); got != want {
			t.Errorf("%s online: measured %v, want %v", typ, got, want)
		}
	}
}
