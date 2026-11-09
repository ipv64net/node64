package eval

import "time"

// DefaultInterval ist das Abfrage-Intervall, wenn der Tracker keines kennt.
const DefaultInterval = time.Minute

// Sample ist eine Messung. Zeit ist die Empfangszeit der Node.
type Sample struct {
	At    time.Time
	Value float64 // Wert in der Einheit der Art; Zustandsregel: Bool(bedingung)
	Free  float64 // nur Fuellstaende: freie Bytes (fuer Modus "GB frei")
}

// Tracker ist der Zustandsautomat einer Messgroesse. Er ist als JSON serialisierbar; die Regel wird bei jedem
// Aufruf uebergeben (Aenderungen wirken sofort, siehe Recheck).
//
// Regeln:
//   - Schwelle oben: Problem ab Wert >= Schwelle; unten: Wert < Schwelle.
//   - Dauer: eine Stufe gilt erst, wenn alle Messungen seit mindestens For ueber der Schwelle liegen.
//   - Hysterese: eine aktive Stufe bleibt, bis der Wert die um Hyst verschobene Schwelle verlaesst
//     (Warnung ab 80, Hyst 2: OK erst unter 78). Die Rueckkehr wartet nicht auf die Dauer.
//   - Lueckenhafte Daten (mehr als UnknownAfter Intervalle) oder eine rueckwaerts springende Uhr setzen die
//     Dauer neu an; die aktive Stufe bleibt fuer die Hysterese erhalten.
//   - Ohne Daten seit mehr als UnknownAfter Intervallen ist der Zustand Unbekannt.
type Tracker struct {
	Interval  Dur       `json:"iv,omitzero"`         // Abfrage-Intervall (setzt der Kern), 0 = DefaultInterval
	Level     State     `json:"level"`               // Ergebnis der Schwellen (OK, Warn, Crit), ohne Unbekannt
	Changed   time.Time `json:"changed,omitzero"`    // seit wann Level gilt
	LastAt    time.Time `json:"last_at,omitzero"`    // letzte Messung
	Last      float64   `json:"last"`                // letzter Wert
	LastFree  float64   `json:"last_free,omitzero"`  // letzte freie Bytes
	WarnSince time.Time `json:"warn_since,omitzero"` // seit wann ununterbrochen ueber der Warnschwelle
	CritSince time.Time `json:"crit_since,omitzero"` // seit wann ununterbrochen ueber der Kritisch-Schwelle
}

// Status ist das Ergebnis fuer Oberflaeche und Benachrichtigung.
type Status struct {
	State     State     `json:"state"`          // inkl. Unbekannt
	Level     State     `json:"level"`          // Ergebnis der Schwellen ohne Unbekannt
	Since     time.Time `json:"since,omitzero"` // Zustand seit
	At        time.Time `json:"at,omitzero"`    // letzte Messung (zero = noch nie)
	Value     float64   `json:"value"`          // bewerteter Wert (Modus "GB frei": GB frei)
	Threshold Limit     `json:"threshold"`      // Schwelle der aktiven Stufe, sonst Off
	// Dauer laeuft: "seit PendingSince ueber PendingLimit – Pending ab PendingAt".
	Pending      State     `json:"pending"`
	PendingSince time.Time `json:"pending_since,omitzero"`
	PendingAt    time.Time `json:"pending_at,omitzero"`
	PendingLimit Limit     `json:"pending_limit"`
}

func (t *Tracker) interval() time.Duration {
	if t.Interval <= 0 {
		return DefaultInterval
	}
	return time.Duration(t.Interval)
}

func (t *Tracker) staleAfter() time.Duration { return UnknownAfter * t.interval() }

// value ist der bewertete Wert der letzten Messung.
func (t *Tracker) value(e Effective) float64 {
	if !e.IsState && e.Mode == ModeFree {
		return t.LastFree / GB
	}
	return t.Last
}

// over meldet, ob v jenseits der Schwelle liegt (oben: >=, unten: <).
func over(v, limit float64, dir Direction) bool {
	if dir == Down {
		return v < limit
	}
	return v >= limit
}

// relaxed verschiebt die Schwelle um die Hysterese zur sicheren Seite.
func relaxed(limit float64, dir Direction, h float64) float64 {
	if dir == Down {
		return limit + h
	}
	return limit - h
}

// Observe nimmt eine Messung auf und liefert den Status zum Zeitpunkt der Messung.
func (t *Tracker) Observe(e Effective, s Sample) Status {
	if !t.LastAt.IsZero() && (s.At.Before(t.LastAt) || s.At.Sub(t.LastAt) > t.staleAfter()) {
		// Luecke oder Uhr rueckwaerts: Dauer neu ansetzen.
		t.WarnSince, t.CritSince = time.Time{}, time.Time{}
	}
	t.LastAt, t.Last, t.LastFree = s.At, s.Value, s.Free
	t.step(e, s.At)
	return t.Status(e, s.At)
}

// Recheck bewertet die letzte Messung mit einer (geaenderten) Regel neu, z. B. nach dem Speichern einer
// Schwelle. Ohne Messung bleibt alles, wie es ist.
func (t *Tracker) Recheck(e Effective, now time.Time) Status {
	if !t.LastAt.IsZero() {
		t.step(e, t.LastAt)
	}
	return t.Status(e, now)
}

func (t *Tracker) step(e Effective, at time.Time) {
	w, c, dir, h := e.Levels()
	v := t.value(e)
	t.CritSince = sinceOver(t.CritSince, !c.Off && over(v, c.V, dir), at)
	t.WarnSince = sinceOver(t.WarnSince, !w.Off && over(v, w.V, dir), at)
	dur := time.Duration(e.For)
	crit := !c.Off && ((t.Level == Crit && over(v, relaxed(c.V, dir, h), dir)) || held(t.CritSince, at, dur))
	warn := !w.Off && ((t.Level != OK && over(v, relaxed(w.V, dir, h), dir)) || held(t.WarnSince, at, dur))
	lvl := OK
	if crit {
		lvl = Crit
	} else if warn {
		lvl = Warn
	}
	if lvl != t.Level || t.Changed.IsZero() {
		t.Level, t.Changed = lvl, at
	}
}

func sinceOver(since time.Time, isOver bool, at time.Time) time.Time {
	if !isOver {
		return time.Time{}
	}
	if since.IsZero() {
		return at
	}
	return since
}

func held(since, at time.Time, dur time.Duration) bool {
	return !since.IsZero() && at.Sub(since) >= dur
}

// Status liefert den Zustand zum Zeitpunkt now (Unbekannt, wenn seit mehr als UnknownAfter Intervallen keine
// Messung kam oder noch nie eine).
func (t *Tracker) Status(e Effective, now time.Time) Status {
	w, c, _, _ := e.Levels()
	st := Status{State: t.Level, Level: t.Level, Since: t.Changed, At: t.LastAt, Value: t.value(e),
		Threshold: Limit{Off: true}, PendingLimit: Limit{Off: true}}
	switch t.Level {
	case Crit:
		st.Threshold = c
	case Warn:
		st.Threshold = w
	}
	dur := time.Duration(e.For)
	switch {
	case t.Level != Crit && !c.Off && !t.CritSince.IsZero():
		st.Pending, st.PendingSince, st.PendingAt, st.PendingLimit = Crit, t.CritSince, t.CritSince.Add(dur), c
	case t.Level == OK && !w.Off && !t.WarnSince.IsZero():
		st.Pending, st.PendingSince, st.PendingAt, st.PendingLimit = Warn, t.WarnSince, t.WarnSince.Add(dur), w
	}
	if t.LastAt.IsZero() {
		st.State, st.Since = Unknown, time.Time{}
	} else if now.Sub(t.LastAt) > t.staleAfter() {
		st.State, st.Since = Unknown, t.LastAt.Add(t.staleAfter())
	}
	return st
}
