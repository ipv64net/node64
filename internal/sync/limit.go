package sync

import (
	"encoding/json"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/wire"
)

// Groesse der Nachrichten zwischen Node und hub: Der hub liest hoechstens 1 MB je Nachricht und trennt sonst die
// Sitzung – ohne Begrenzung kaeme derselbe zu grosse Stapel nach jedem Neuverbinden wieder. Stapel werden darum nach
// ihrer JSON-Groesse geteilt, einzelne uebergrosse Eintraege gekuerzt. Der hub schickt die Konfiguration grosser
// Accounts in einer Nachricht; die Node liest deshalb mehr.
const (
	maxUploadBytes = 512 << 10 // Nutzdaten je Nachricht an den hub
	maxItemBytes   = 16 << 10  // je Eintrag; darueber Details weg und Texte gekuerzt
	maxItemText    = 1024      // Laenge gekuerzter Texte (Bytes)
	maxReadBytes   = 16 << 20  // Nachrichten des hubs
)

func jsonSize(v any) int {
	b, err := json.Marshal(v)
	if err != nil {
		return 0
	}
	return len(b)
}

// chunks teilt Eintraege in Stapel von hoechstens maxUploadBytes (als JSON), mindestens ein Eintrag je Stapel.
func chunks[T any](items []T) [][]T {
	var out [][]T
	start, size := 0, 0
	for i := range items {
		n := jsonSize(items[i]) + 1
		if i > start && size+n > maxUploadBytes {
			out = append(out, items[start:i])
			start, size = i, 0
		}
		size += n
	}
	if start < len(items) {
		out = append(out, items[start:])
	}
	return out
}

// cutText kuerzt auf hoechstens n Bytes (gueltiges UTF-8).
func cutText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// shrinkMeasurements kuerzt uebergrosse Messpunkte (Details weg, Text gekuerzt); die Eingabe bleibt unveraendert.
func shrinkMeasurements(in []wire.Measurement) []wire.Measurement {
	out := make([]wire.Measurement, len(in))
	copy(out, in)
	for i := range out {
		if jsonSize(out[i]) > maxItemBytes {
			out[i].Details = map[string]any{"truncated": true}
			out[i].Message = cutText(out[i].Message, maxItemText)
			out[i].Reason = cutText(out[i].Reason, maxItemText)
		}
	}
	return out
}

// shrinkStates wie shrinkMeasurements fuer Zustaende.
func shrinkStates(in []wire.State) []wire.State {
	out := make([]wire.State, len(in))
	copy(out, in)
	for i := range out {
		if jsonSize(out[i]) > maxItemBytes {
			out[i].Message = cutText(out[i].Message, maxItemText)
			out[i].Reason = cutText(out[i].Reason, maxItemText)
		}
	}
	return out
}

// shrinkEvents wie shrinkMeasurements fuer Statuswechsel.
func shrinkEvents(in []wire.Event) []wire.Event {
	out := make([]wire.Event, len(in))
	copy(out, in)
	for i := range out {
		if jsonSize(out[i]) > maxItemBytes {
			out[i].Message = cutText(out[i].Message, maxItemText)
			out[i].Reason = cutText(out[i].Reason, maxItemText)
		}
	}
	return out
}
