package module

import (
	"context"
	"strings"
	"time"
)

// StatusFeed liefert Eintraege einer anderen Quelle als der Healthchecks fuer die Statusseiten (Monitor64: Hosts und
// einzeln aufgenommene Dienste). Die Quelle eines Eintrags ist ein Text mit eigenem Praefix (Monitor64:
// "m64:host:<uid>" bzw. "m64:svc:<uid>/<key>"), der statt des Check-Tokens am Eintrag steht. Die Statusseite zeigt
// davon nur Name und Zustand; die Quelle liefert deshalb keine Werte, Adressen oder Fehlertexte.
type StatusFeed interface {
	// StatusTargets liefert die Auswahl fuer den Editor (je Host der Host, danach seine Dienste).
	StatusTargets(ctx context.Context) ([]StatusTarget, error)
	// StatusSources liefert Zustand, Balken, Stoerungen und Wartungen der Quellen. Unbekannte Quellen (Host oder Dienst
	// entfernt, Eintrag einer anderen Node) fehlen im Ergebnis.
	StatusSources(ctx context.Context, q StatusQuery) (map[string]*StatusSource, error)
}

// StatusTarget ist ein Eintrag zur Auswahl im Editor.
type StatusTarget struct {
	Source string   // Quelle des Eintrags
	Host   string   // Name des Hosts
	Name   string   // Name des Dienstes ("" = der Host selbst)
	Group  string   // Gruppe des Hosts
	Tags   []string // Tags des Hosts (Filter im Editor)
	Paused bool
}

// StatusQuery beschreibt, was eine Statusseite braucht.
type StatusQuery struct {
	Sources []string
	Lang    string        // Sprache fuer Namen aus der Quelle ("" = Standard der Quelle)
	Bounds  []time.Time   // Grenzen der Balken (aufsteigend, Balken i = Bounds[i]..Bounds[i+1]); weniger als 2 = keine Balken
	History time.Time     // Stoerungen, die nach diesem Zeitpunkt noch liefen (leer = keine)
	Ahead   time.Duration // Wartungen: laufende und die bis Now+Ahead beginnenden
	Now     time.Time
}

// Zustaende einer Quelle (StatusSource.State).
const (
	StatusOK          = "ok"
	StatusWarn        = "warn"
	StatusCrit        = "crit"
	StatusUnknown     = "unknown"
	StatusUnreachable = "unreachable"
	StatusMaintenance = "maintenance"
	StatusPaused      = "paused"
)

// StatusSource ist der Stand einer Quelle.
type StatusSource struct {
	Name        string           // Vorgabe fuer die Bezeichnung (Host bzw. "Host – Dienst")
	Group       string           // Gruppe (Anzeige "nach Gruppen")
	State       string           // Status* (siehe oben)
	Since       time.Time        // seit wann der Zustand gilt (leer = unbekannt)
	Bars        []StatusBar      // je Balken der Anfrage
	Incidents   []StatusIncident // Stoerungen (kritisch bzw. nicht erreichbar, ohne Wartung und Pause), neueste zuerst
	Maintenance []StatusMaint    // laufende und geplante Wartungen (je Fenster der naechste Termin)
}

// StatusBar sind die Zeiten eines Balkens.
type StatusBar struct {
	Observed time.Duration // beobachtete Zeit (nach dem Anlegen, ohne Wartung und Pause)
	Down     time.Duration // davon gestoert (kritisch, nicht erreichbar)
	Warn     time.Duration // davon eingeschraenkt (Warnung, unbekannt), ohne die gestoerte Zeit
	Maint    time.Duration // Wartung im Balken
}

// StatusIncident ist eine Stoerung.
type StatusIncident struct {
	Start  time.Time
	End    time.Time // leer = laeuft
	Reason string    // allgemeiner Grund: "unreachable" oder "crit"
}

// StatusMaint ist ein Termin eines Wartungsfensters.
type StatusMaint struct {
	ID     string // Kennung des Fensters (mehrere Eintraege, ein Fenster)
	Title  string
	Start  time.Time
	End    time.Time // leer = bis beendet
	Active bool
}

// Quelle eines Monitor64-Eintrags auf einer Statusseite: "m64:host:<uid>" bzw. "m64:svc:<uid>/<schluessel>". Eine
// Stelle fuer Monitor64 (liefert) und die Statusseiten (pruefen, verlinken) - frueher je eine Kopie, die gleich
// bleiben musste.
const (
	StatusSourcePrefix = "m64:"
	statusSrcHost      = "m64:host:"
	statusSrcSvc       = "m64:svc:"
	StatusMaxKey       = 200 // Laenge eines Dienst-Schluessels in Bytes
)

// ParseStatusSource zerlegt eine Quelle (key "" = Host) und prueft sie.
func ParseStatusSource(s string) (host, key string, ok bool) {
	if uid, found := strings.CutPrefix(s, statusSrcHost); found {
		return uid, "", ValidStatusUID(uid)
	}
	if rest, found := strings.CutPrefix(s, statusSrcSvc); found {
		uid, key, cut := strings.Cut(rest, "/")
		return uid, key, cut && ValidStatusUID(uid) && ValidStatusKey(key)
	}
	return "", "", false
}

// ValidStatusKey: Dienst-Schluessel mit 1-200 Bytes ohne Steuerzeichen.
func ValidStatusKey(k string) bool {
	if k == "" || len(k) > StatusMaxKey {
		return false
	}
	for i := 0; i < len(k); i++ {
		if k[i] < 0x20 || k[i] == 0x7f {
			return false
		}
	}
	return true
}

// ValidStatusUID: Kennung eines Hosts (1-64 Zeichen A-Z a-z 0-9 - _).
func ValidStatusUID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
