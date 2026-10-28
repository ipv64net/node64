package healthchecks

import "time"

// Oeffentliche Sicht einer Statusseite (status.json und Grundlage der HTML-Seite). Enthaelt nur, was Besucher sehen
// duerfen: keine Ziele, IPs, Ports, Tokens oder Rohmeldungen. Berechnung in statusview.go.

// StatusView ist die ganze Seite.
type StatusView struct {
	Slug        string            `json:"slug"`
	Title       string            `json:"title"`
	Description string            `json:"description"` // Markdown-Quelltext (die Seite rendert sicher)
	Footer      string            `json:"footer"`
	Layout      string            `json:"layout"`
	Theme       string            `json:"theme"`
	Accent      string            `json:"accent"`
	Days        int               `json:"days"`
	ShowUptime  bool              `json:"show_uptime"`
	RefreshSec  int               `json:"refresh_sec"`
	PoweredBy   bool              `json:"powered_by"`
	Overall     string            `json:"overall"` // up | degraded | down | maintenance | unknown
	Groups      []StatusViewGroup `json:"groups"`
	Notices     []StatusNotice    `json:"notices"`     // offen und (bei ShowHistory) erledigte der letzten 30 Tage
	Maintenance []StatusViewMaint `json:"maintenance"` // laufend und die naechsten 7 Tage
	Incidents   []StatusViewIncid `json:"incidents"`   // automatisch aus den Checks, letzte 30 Tage (bei ShowHistory)
	Generated   time.Time         `json:"generated"`

	Logo string `json:"logo,omitempty"` // eigenes Logo: Pfad relativ zur Seite ("logo?v=<unix>"), leer = keins (dann Node64)
}

// StatusViewGroup ist eine Gruppe.
type StatusViewGroup struct {
	Name    string           `json:"name"`
	Overall string           `json:"overall"` // wie StatusView.Overall
	Items   []StatusViewItem `json:"items"`
}

// StatusViewItem ist ein Eintrag (Check). ID ist die Eintrags-ID (fuer Details und Badges), nie der Token.
type StatusViewItem struct {
	ID     int64           `json:"id"`
	Label  string          `json:"label"`
	State  string          `json:"state"`  // up | down | degraded | maintenance | paused | unknown
	Uptime float64         `json:"uptime"` // Prozent ueber Days, -1 = keine Daten
	Bars   []StatusViewDay `json:"bars"`   // aelteste zuerst, genau Days Eintraege
}

// StatusViewDay ist ein Tagesbalken.
type StatusViewDay struct {
	Day      string  `json:"day"`      // 2006-01-02 (Zeitzone der Node)
	State    string  `json:"state"`    // up | partial | down | maintenance | none
	Uptime   float64 `json:"uptime"`   // Prozent, -1 = keine Daten
	DownMins int     `json:"down_min"` // Minuten gestoert (aus den Stoerungen)
}

// StatusViewMaint ist ein Wartungsfenster (nur Titel und Zeit).
type StatusViewMaint struct {
	Title  string    `json:"title"`
	Start  time.Time `json:"start"`
	End    time.Time `json:"end"`
	Active bool      `json:"active"`
	Items  []string  `json:"items"` // betroffene Eintraege (Anzeigenamen)
}

// StatusViewIncid ist eine automatisch erkannte Stoerung eines Eintrags.
type StatusViewIncid struct {
	Item   string    `json:"item"` // Anzeigename
	Start  time.Time `json:"start"`
	End    time.Time `json:"end,omitzero"` // leer = laeuft
	Reason string    `json:"reason"`       // allgemeiner Grund (i18n-Schluessel hc.reasons.<x>), nie die Rohmeldung
}

// StatusItemDetail sind die Details eines Eintrags (Klick auf der Seite): /status/<slug>/item/<id>.json
type StatusItemDetail struct {
	ID        int64             `json:"id"`
	Label     string            `json:"label"`
	State     string            `json:"state"`
	Since     time.Time         `json:"since,omitzero"`
	Uptime24h float64           `json:"uptime_24h"`
	Uptime7d  float64           `json:"uptime_7d"`
	Uptime30d float64           `json:"uptime_30d"`
	Latency   float64           `json:"latency_ms"` // Mittel 24 h, -1 = keine Daten
	Hours     []StatusViewDay   `json:"hours"`      // letzte 24 Stunden (Day = Stunde "2006-01-02T15")
	Incidents []StatusViewIncid `json:"incidents"`  // letzte 5 (nur bei ShowHistory)
	// Einstellungen der Seite: ohne ShowUptime sind Verfuegbarkeit und Latenz -1, ohne ShowHistory fehlen die Stoerungen
	ShowUptime  bool `json:"show_uptime"`
	ShowHistory bool `json:"show_history"`
}
