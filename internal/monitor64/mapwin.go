package monitor64

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Zuordnung der Windows-Abschnitte des Agent-Berichts (m64win). Noch nicht in MapReport verdrahtet: dort ersetzt
// mapWinSvc die Schleife ueber cur.WinSvc (siehe Bericht des Windows-Agents).

// winSvcIgnore: Dienste mit Starttyp Automatisch, die sich nach getaner Arbeit selbst beenden (Updater von Browsern,
// Lizenzdienst ...). Sie zaehlen in der Zusammenfassung nicht als gestoppt; einzeln uebernommen werden sie trotzdem
// ueberwacht.
var winSvcIgnore = regexp.MustCompile(`(?i)^(gupdate|gupdatem|GoogleUpdater(Internal)?Service.*|edgeupdate|edgeupdatem|` +
	`MicrosoftEdgeElevationService|BraveUpdate.*|brave|bravem|MozillaMaintenance|sppsvc|RemoteRegistry|MapsBroker|` +
	`clr_optimization_v.*|SysmonLog|TrustedInstaller|wuauserv|UsoSvc|WaaSMedicSvc|ShellHWDetection|tiledatamodelsvc)$`)

// winSvcStopped: Zustand, der als "laeuft nicht" zaehlt (Uebergaenge wie start_pending nicht, sonst flackert es).
func winSvcStopped(state string) bool {
	switch state {
	case "stopped", "paused":
		return true
	}
	return false
}

// mapWinSvc bildet die Windows-Dienste ab: ein zusammenfassender Dienst "Windows-Dienste" (wie systemd: gestoppte
// Dienste mit Starttyp Automatisch, Fact winsvc_stopped) und je Dienst ein Eintrag, der nur auf Wunsch uebernommen
// wird (Default false; uebernommen meldet er winsvc_stopped, sobald er nicht laeuft). Ohne Dienste im Bericht (Abschnitt
// fehlt) kommt nichts.
func mapWinSvc(list []m64proto.WinService) []Service {
	if len(list) == 0 {
		return nil
	}
	sum := Service{Key: "winsvc", Name: "Windows-Dienste", Kind: "winsvc", Default: true}
	var stopped []string
	auto := 0
	out := make([]Service, 0, len(list)+1)
	out = append(out, Service{}) // Platz fuer die Zusammenfassung vorne
	for _, w := range list {
		if w.Name == "" {
			continue
		}
		name := firstNonEmpty(w.Display, w.Name)
		s := Service{Key: "winsvc:" + w.Name, Name: name, Kind: "winsvc", Text: w.State}
		run := 0.0
		if w.State == "running" {
			run = 1
		}
		s.Metrics = []Metric{{Name: "running", Value: run}}
		if winSvcStopped(w.State) {
			s.Facts = append(s.Facts, Fact{Code: "winsvc_stopped", Text: fmt.Sprintf("%s (%s): %s", name, w.Name, w.State)})
		}
		out = append(out, s)
		if w.StartType != "auto" {
			continue
		}
		auto++
		if winSvcStopped(w.State) && !winSvcIgnore.MatchString(w.Name) {
			stopped = append(stopped, name)
		}
	}
	sum.Metrics = []Metric{{Name: "auto", Value: float64(auto)}, {Name: "stopped", Value: float64(len(stopped))}}
	if len(stopped) > 0 {
		list := strings.Join(limitList(stopped, 5), ", ")
		sum.Facts = append(sum.Facts, Fact{Code: "winsvc_stopped", Text: list})
		sum.Text = fmt.Sprintf("%d von %d automatischen Diensten gestoppt: %s", len(stopped), auto, list)
	} else {
		sum.Text = fmt.Sprintf("%d automatische Dienste, keiner gestoppt", auto)
	}
	out[0] = sum
	return out
}
