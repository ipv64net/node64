package monitor64

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Zuordnung der Windows-Abschnitte des Agent-Berichts (m64win bzw. windows_exporter ueber promscrape); MapReport ruft
// mapWinSvc fuer cur.WinSvc auf.

// winSvcIgnore: Dienste mit Starttyp Automatisch, die sich nach getaner Arbeit selbst beenden (Updater von Browsern,
// Lizenzdienst, Dienste mit Trigger-Start wie die Uebermittlungsoptimierung ...) und Dienste je Benutzer (Vorlage
// ohne bzw. Instanz mit "_<hex>" dahinter). Der Monitor64-Agent laesst Trigger- und Benutzerdienste schon beim Lesen
// weg, windows_exporter liefert sie ungefiltert. Sie zaehlen in der Zusammenfassung nicht als gestoppt; einzeln
// uebernommen werden sie trotzdem ueberwacht.
var winSvcIgnore = regexp.MustCompile(`(?i)^(gupdate|gupdatem|GoogleUpdater(Internal)?Service.*|edgeupdate|edgeupdatem|` +
	`MicrosoftEdgeElevationService|BraveUpdate.*|brave|bravem|MozillaMaintenance|sppsvc|RemoteRegistry|MapsBroker|` +
	`clr_optimization_v.*|SysmonLog|TrustedInstaller|wuauserv|UsoSvc|WaaSMedicSvc|ShellHWDetection|tiledatamodelsvc|` +
	`DoSvc|SgrmBroker|uhssvc|` +
	`(OneSyncSvc|WpnUserService|CDPUserSvc|PimIndexMaintenanceSvc|UnistoreSvc|UserDataSvc|MessagingService|cbdhsvc|` +
	`BcastDVRUserService|DevicesFlowUserSvc|DevicePickerUserSvc|DeviceAssociationBrokerSvc|PrintWorkflowUserSvc|` +
	`BluetoothUserService|CaptureService|ConsentUxUserSvc|CredentialEnrollmentManagerUserSvc|UdkUserSvc|` +
	`webthreatdefusersvc|NPSMSvc|P9RdrService|PenService|AarSvc|CloudBackupRestoreSvc)(_[0-9a-f]{4,8})?)$`)

// winSvcInstance: Name einer Instanz eines Benutzerdienstes (Vorlage + "_" + LUID in Hex).
var winSvcInstance = regexp.MustCompile(`^(.+)_[0-9a-fA-F]{4,8}$`)

// winSvcPerUser erkennt Benutzerdienste auch ohne Eintrag in winSvcIgnore: Vorlage und Instanz stehen beide in der
// Liste (die Instanz heisst wie die Vorlage mit "_<hex>" dahinter).
func winSvcPerUser(list []m64proto.WinService) map[string]bool {
	names := make(map[string]bool, len(list))
	for _, w := range list {
		names[strings.ToLower(w.Name)] = true
	}
	out := map[string]bool{}
	for _, w := range list {
		if m := winSvcInstance.FindStringSubmatch(w.Name); m != nil && names[strings.ToLower(m[1])] {
			out[strings.ToLower(w.Name)], out[strings.ToLower(m[1])] = true, true
		}
	}
	return out
}

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
	sum := Service{Key: "winsvc", Name: model.T("monitor64.svc.winsvc"), Kind: "winsvc", Default: true}
	perUser := winSvcPerUser(list)
	var stopped []string
	auto := 0
	out := make([]Service, 0, len(list)+1)
	out = append(out, Service{}) // Platz fuer die Zusammenfassung vorne
	for _, w := range list {
		if w.Name == "" {
			continue
		}
		name := model.Raw(firstNonEmpty(w.Display, w.Name)) // Namen und Zustand liefert der Host
		s := Service{Key: "winsvc:" + w.Name, Name: name, Kind: "winsvc", Text: model.Raw(w.State)}
		run := 0.0
		if w.State == "running" {
			run = 1
		}
		s.Metrics = []Metric{{Name: "running", Value: run}}
		if winSvcStopped(w.State) {
			s.Facts = append(s.Facts, Fact{Code: "winsvc_stopped", Text: fmt.Sprintf("%s (%s): %s", name, model.Raw(w.Name), model.Raw(w.State))})
		}
		out = append(out, s)
		if w.StartType != "auto" || perUser[strings.ToLower(w.Name)] {
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
		sum.Text = model.T("monitor64.txt.winsvc_stopped", "n", len(stopped), "total", auto, "list", list)
	} else {
		sum.Text = model.T("monitor64.txt.winsvc_ok", "n", auto)
	}
	out[0] = sum
	return out
}
