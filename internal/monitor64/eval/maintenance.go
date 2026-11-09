package eval

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Clock ist eine Uhrzeit in Minuten ab Mitternacht (0 bis 1440), im JSON "HH:MM" ("24:00" fuer Tagesende).
type Clock int

// At ist eine Kurzform fuer eine Uhrzeit.
func At(h, m int) Clock { return Clock(h*60 + m) }

func (c Clock) String() string { return fmt.Sprintf("%02d:%02d", int(c)/60, int(c)%60) }

func (c Clock) MarshalText() ([]byte, error) {
	if c < 0 || c > 24*60 {
		return nil, fmt.Errorf("eval: Uhrzeit %d ausserhalb 00:00-24:00", int(c))
	}
	return []byte(c.String()), nil
}

func (c *Clock) UnmarshalText(b []byte) error {
	var h, m int
	if n, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d:%d", &h, &m); err != nil || n != 2 {
		return fmt.Errorf("eval: Uhrzeit %q nicht im Format HH:MM", b)
	}
	if h < 0 || m < 0 || m > 59 || h*60+m > 24*60 {
		return fmt.Errorf("eval: Uhrzeit %q ausserhalb 00:00-24:00", b)
	}
	*c = Clock(h*60 + m)
	return nil
}

// Recurrence ist ein wiederkehrendes Fenster in Ortszeit der Node, z. B. jeden Sonntag 02:00-04:00.
// To <= From laeuft ueber Mitternacht (Tage beziehen sich auf den Beginn); From == To ist ein ganzer Tag.
// Es zaehlt die Uhrzeit an der Wand: beim Wechsel auf Sommerzeit faellt die fehlende Stunde aus (02-04 Uhr
// dauert dann eine Stunde), beim Wechsel auf Winterzeit zaehlt die doppelte Stunde zweimal.
type Recurrence struct {
	Days []time.Weekday `json:"days,omitempty"` // leer = jeden Tag (0 = Sonntag)
	From Clock          `json:"from"`
	To   Clock          `json:"to"`
}

// Window ist ein Wartungsfenster fuer Hosts, Gruppen und Tags: jetzt (Start = jetzt, End leer bis beendet
// oder Start+Dauer), geplant (Start-End) oder wiederkehrend (Recurring, optional begrenzt durch Start/End).
type Window struct {
	ID        string      `json:"id,omitempty"`
	Hosts     []string    `json:"hosts,omitempty"`  // Host-IDs
	Groups    []string    `json:"groups,omitempty"` //
	Tags      []string    `json:"tags,omitempty"`   //
	Start     time.Time   `json:"start,omitzero"`   // Beginn (inklusive); leer = sofort
	End       time.Time   `json:"end,omitzero"`     // Ende (exklusive); leer = bis beendet
	Recurring *Recurrence `json:"recurring,omitempty"`
	Reason    string      `json:"reason,omitempty"`
}

// Applies meldet, ob das Fenster den Host betrifft.
func (w Window) Applies(h HostRef) bool {
	if slices.Contains(w.Hosts, h.ID) {
		return true
	}
	for _, g := range w.Groups {
		if g != "" && strings.EqualFold(g, h.Group) {
			return true
		}
	}
	for _, t := range w.Tags {
		if t != "" && h.HasTag(t) {
			return true
		}
	}
	return false
}

// Active meldet, ob das Fenster zum Zeitpunkt at fuer den Host gilt; loc ist die Zeitzone der Node
// (nil = UTC).
func (w Window) Active(at time.Time, h HostRef, loc *time.Location) bool {
	if !w.Applies(h) {
		return false
	}
	if !w.Start.IsZero() && at.Before(w.Start) {
		return false
	}
	if !w.End.IsZero() && !at.Before(w.End) {
		return false
	}
	if w.Recurring == nil {
		return true
	}
	if loc == nil {
		loc = time.UTC
	}
	return w.Recurring.active(at.In(loc))
}

func (r Recurrence) day(d time.Weekday) bool {
	return len(r.Days) == 0 || slices.Contains(r.Days, d)
}

func (r Recurrence) active(t time.Time) bool {
	mod := Clock(t.Hour()*60 + t.Minute())
	wd := t.Weekday()
	if r.From < r.To {
		return r.day(wd) && mod >= r.From && mod < r.To
	}
	// ueber Mitternacht: Abend des Starttags oder Morgen des Folgetags
	return (r.day(wd) && mod >= r.From) || (r.day((wd+6)%7) && mod < r.To)
}

// InMaintenance meldet, ob ein Fenster der Liste fuer den Host gilt, und liefert das erste.
func InMaintenance(ws []Window, at time.Time, h HostRef, loc *time.Location) (bool, *Window) {
	for i := range ws {
		if ws[i].Active(at, h, loc) {
			return true, &ws[i]
		}
	}
	return false, nil
}
