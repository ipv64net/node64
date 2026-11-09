// Package eval enthaelt die reine Bewertungslogik von Monitor64 (Plan docs/PLAN-NODE64-MONITOR64.md):
// Schwellen und Regeln mit drei Stufen, Standard-Schwellen, Zustandsautomat je Messgroesse, Dienst- und
// Host-Zustand, Trend fuer Fuellstaende, Ereignisse fuer die Benachrichtigung und Wartungsfenster.
//
// Das Paket hat keine Datenbank, kein Netz und keine Uhr: jede Zeit kommt als Parameter. Zustaende, die
// gespeichert werden muessen (Tracker, Notifier), sind als JSON serialisierbar.
package eval

import (
	"fmt"
	"strings"
)

// State ist der Zustand einer Messgroesse, eines Dienstes oder Hosts. Die Zahlen entsprechen der ueblichen
// Nagios-Zaehlung (fuer Prometheus node64_monitor_state 0-3).
type State uint8

const (
	OK      State = 0
	Warn    State = 1
	Crit    State = 2
	Unknown State = 3
)

var stateNames = [...]string{"ok", "warn", "crit", "unknown"}

func (s State) String() string {
	if int(s) < len(stateNames) {
		return stateNames[s]
	}
	return fmt.Sprintf("state(%d)", s)
}

// MarshalText speichert den Zustand als Wort ("ok", "warn", "crit", "unknown").
func (s State) MarshalText() ([]byte, error) {
	if int(s) >= len(stateNames) {
		return nil, fmt.Errorf("eval: ungueltiger Zustand %d", s)
	}
	return []byte(stateNames[s]), nil
}

// UnmarshalText liest einen Zustand; unbekannte Woerter sind ein Fehler.
func (s *State) UnmarshalText(b []byte) error {
	for i, n := range stateNames {
		if strings.EqualFold(string(b), n) {
			*s = State(i)
			return nil
		}
	}
	return fmt.Errorf("eval: unbekannter Zustand %q", b)
}

// Rank ordnet nach Schwere: OK < Warnung < Unbekannt < Kritisch (wie CheckMK).
func (s State) Rank() int {
	switch s {
	case Warn:
		return 1
	case Unknown:
		return 2
	case Crit:
		return 3
	}
	return 0
}

// Worse meldet, ob s schlimmer ist als o.
func (s State) Worse(o State) bool { return s.Rank() > o.Rank() }

// Worst liefert den schlimmsten Zustand (leer = OK).
func Worst(states ...State) State {
	w := OK
	for _, s := range states {
		if s.Worse(w) {
			w = s
		}
	}
	return w
}

// NotifySeverity ist die Schwere fuer das Routing an Kanaele: Unbekannt wird wie Warnung gemeldet.
func (s State) NotifySeverity() State {
	if s == Unknown {
		return Warn
	}
	return s
}
