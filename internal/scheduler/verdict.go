package scheduler

import "github.com/ipv64net/node64/internal/checks"

// SourceState ist der Zustand einer Messstelle (Node oder ipv64-Standort).
type SourceState struct {
	Source     string // "node:<id>", "loc:nbg", ...
	State      State
	LastStatus checks.Status
	Fresh      bool // aktuelle Daten vorhanden (nicht offline/ausgefallen)
}

// Overall berechnet den Gesamtzustand nach der Regel policy (all, any,
// majority). Gleiche Funktion auf Node und Server.
//
// Zaehlt nur Messstellen mit frischen Daten im Zustand up/down/stabilizing/
// flapping; stabilizing gilt als up (LastStatus up), flapping nach LastStatus.
// Alle anderen (pending, paused, dependent, nicht frisch) bleiben aussen vor.
func Overall(policy string, sources []SourceState) State {
	var up, down int
	flapping := false
	for _, s := range sources {
		if !s.Fresh {
			continue
		}
		switch s.State {
		case StateUp, StateStabilizing:
			up++
		case StateDown:
			down++
		case StateFlapping:
			flapping = true
			if s.LastStatus == checks.Down {
				down++
			} else {
				up++
			}
		}
	}
	total := up + down
	if total == 0 {
		return StatePending
	}
	var isDown bool
	switch policy {
	case "any":
		isDown = down > 0
	case "majority":
		isDown = down*2 > total
	default: // all
		isDown = down == total
	}
	switch {
	case isDown && flapping:
		return StateFlapping
	case isDown:
		return StateDown
	case down > 0:
		return StateDegraded
	default:
		return StateUp
	}
}
