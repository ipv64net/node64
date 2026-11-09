package eval

import "strings"

// MetricStatus ist der Status einer Messgroesse eines Dienstes.
type MetricStatus struct {
	Name   string `json:"name"` // z. B. "in", "errrate", "temp"
	Status Status `json:"status"`
	Notify bool   `json:"notify"` // Regel meldet (Effective.Notify), false = nur anzeigen
}

// ServiceResult ist der Zustand eines Dienstes.
type ServiceResult struct {
	State       State `json:"state"`        // schlimmste Messgroesse (Anzeige)
	Cause       int   `json:"cause"`        // Index der ausloesenden Messgroesse, -1 = alles OK
	Notify      State `json:"notify"`       // schlimmste meldende Messgroesse (Eingang fuer den Notifier)
	NotifyCause int   `json:"notify_cause"` // deren Index, -1 = keine
	ShowOnly    bool  `json:"show_only"`    // keine Messgroesse meldet
}

// ServiceState: Dienst-Zustand = schlimmste Messgroesse; bei Gleichstand nennt Cause die erste. Messgroessen
// mit "nur anzeigen" zaehlen fuer die Anzeige, aber nicht fuer Notify.
func ServiceState(ms []MetricStatus) ServiceResult {
	r := ServiceResult{Cause: -1, NotifyCause: -1, ShowOnly: true}
	for i, m := range ms {
		s := m.Status.State
		if s != OK && (r.Cause < 0 || s.Worse(r.State)) {
			r.State, r.Cause = s, i
		}
		if m.Notify {
			r.ShowOnly = false
			if s != OK && (r.NotifyCause < 0 || s.Worse(r.Notify)) {
				r.Notify, r.NotifyCause = s, i
			}
		}
	}
	return r
}

// UnreachableRounds: so viele Runden in Folge ohne Antwort machen einen Zugang (bzw. alle: den Host) gestoert.
const UnreachableRounds = 2

// Access ist ein Zugang eines Hosts mit der Zahl der Runden in Folge ohne Antwort.
type Access struct {
	Name     string `json:"name"` // "Agent", "SSH", "SNMP", "API" …
	Failures int    `json:"failures"`
}

// AccessServiceKey ist der Dienst-Schluessel fuer einen gestoerten Zugang ("access:ssh").
func AccessServiceKey(name string) string { return "access:" + strings.ToLower(name) }

// HostInput sind die Eingaben fuer den Host-Zustand.
type HostInput struct {
	Maintenance bool     `json:"maintenance"`
	Accesses    []Access `json:"accesses"`
	Services    []State  `json:"services"`
}

// HostView ist die Anzeige des Hosts (Kachel, Statusseite).
type HostView string

const (
	ViewOK          HostView = "ok"
	ViewWarn        HostView = "warn"
	ViewCrit        HostView = "crit"
	ViewUnknown     HostView = "unknown"
	ViewUnreachable HostView = "unreachable"
	ViewMaintenance HostView = "maintenance"
)

// HostResult ist der Zustand eines Hosts.
type HostResult struct {
	View         HostView `json:"view"`          // Wartung > nicht erreichbar > schlimmster Dienst
	State        State    `json:"state"`         // schlimmster Dienst inkl. gestoerter Zugaenge; nicht erreichbar = Kritisch
	Unreachable  bool     `json:"unreachable"`   // alle Zugaenge UnreachableRounds Runden in Folge ohne Antwort
	Maintenance  bool     `json:"maintenance"`   //
	FailedAccess []string `json:"failed_access"` // je Eintrag ein Dienst "Zugang X" (Warnung); leer, wenn nicht erreichbar
}

// HostState ermittelt den Host-Zustand. Ein Host ohne Zugang gilt als erreichbar.
func HostState(in HostInput) HostResult {
	r := HostResult{Maintenance: in.Maintenance}
	failed := 0
	for _, a := range in.Accesses {
		if a.Failures >= UnreachableRounds {
			failed++
			r.FailedAccess = append(r.FailedAccess, a.Name)
		}
	}
	r.Unreachable = len(in.Accesses) > 0 && failed == len(in.Accesses)
	if r.Unreachable {
		r.FailedAccess = nil
		r.State = Crit
	} else {
		r.State = Worst(in.Services...)
		if len(r.FailedAccess) > 0 {
			r.State = Worst(r.State, Warn)
		}
	}
	switch {
	case r.Maintenance:
		r.View = ViewMaintenance
	case r.Unreachable:
		r.View = ViewUnreachable
	default:
		r.View = HostView(r.State.String())
	}
	return r
}
