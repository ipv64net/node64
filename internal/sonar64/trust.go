package sonar64

import (
	"time"

	"github.com/ipv64net/node64/internal/sonar"
)

// Vertrauensstufen (Plan Abschnitt 6, Startwerte). Die Stufe vergibt allein ipv64; hier nur Anzeige und ein
// Richtwert fuer den Fortschritt zur naechsten Stufe.
const (
	TrustNew        = "new"
	TrustStable     = "stable"
	TrustTrusted    = "trusted"
	TrustPillar     = "pillar"
	TrustAnchor     = "anchor"
	TrustQuarantine = "quarantine"
)

// trustStep ist die Bedingung fuer eine Stufe.
type trustStep struct {
	level    string
	days     int
	uptime   float64 // Anteil 0..1 (30 Tage)
	measured bool    // muss auch gemessen werden
}

// trustSteps: Aufstieg in dieser Reihenfolge (Saeule: sehr stabil und gemessen).
var trustSteps = []trustStep{
	{TrustStable, 7, 0.90, false},
	{TrustTrusted, 60, 0.97, false},
	{TrustPillar, 180, 0.97, true},
}

// trustView ist die Vertrauensstufe fuer die Oberflaeche.
type trustView struct {
	Level        string  `json:"level"`
	Class        string  `json:"class"`          // Badge-Klasse
	Next         string  `json:"next,omitempty"` // naechste Stufe, leer = hoechste bzw. Quarantaene
	Pct          int     `json:"pct"`            // Fortschritt 0..100 (Richtwert)
	Days         int     `json:"days"`
	NeedDays     int     `json:"need_days,omitempty"`
	Uptime       float64 `json:"uptime"` // Prozent
	NeedUptime   float64 `json:"need_uptime,omitempty"`
	NeedMeasured bool    `json:"need_measured,omitempty"` // naechste Stufe braucht „auch gemessen“
}

// TrustClass: Farbe der Stufe (grau neu, blau stabil, gruen vertraut, gold Saeule, violett Anker, rot Quarantaene).
func TrustClass(level string) string {
	switch level {
	case TrustStable:
		return "text-bg-primary"
	case TrustTrusted:
		return "text-bg-success"
	case TrustPillar:
		return "s64-gold"
	case TrustAnchor:
		return "s64-violet"
	case TrustQuarantine:
		return "text-bg-danger"
	}
	return "text-bg-secondary"
}

// trustOf berechnet Stufe und Fortschritt aus dem eigenen Knoten (nil = noch unbekannt: neu, 0 %).
func trustOf(me *sonar.Me, measured bool, now time.Time) trustView {
	level := TrustNew
	var since time.Time
	var uptime float64
	if me != nil {
		if me.Trust != "" {
			level = me.Trust
		}
		since, uptime = me.Since, me.Uptime30
	}
	v := trustView{Level: level, Class: TrustClass(level), Uptime: min(max(uptime, 0), 1) * 100}
	if !since.IsZero() && now.After(since) {
		v.Days = int(now.Sub(since) / (24 * time.Hour))
	}
	idx := -1
	switch level {
	case TrustNew:
		idx = 0
	case TrustStable:
		idx = 1
	case TrustTrusted:
		idx = 2
	case TrustPillar, TrustAnchor:
		v.Pct = 100
		return v
	default: // Quarantaene (oder unbekannt): kein Aufstieg
		return v
	}
	st := trustSteps[idx]
	v.Next, v.NeedDays, v.NeedUptime, v.NeedMeasured = st.level, st.days, st.uptime*100, st.measured
	ratio := min(float64(v.Days)/float64(st.days), min(max(uptime, 0), 1)/st.uptime, 1)
	if st.measured && !measured {
		ratio = min(ratio, 0.99)
	}
	v.Pct = int(ratio * 100)
	return v
}
