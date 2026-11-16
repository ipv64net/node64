package monitor64

import (
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/monitor64/model/modeltest"
)

// Windows "Neustart noetig": Gruende lesbar - neue Agents liefern Hinweis-Codes, aeltere (bis 0.1.9) rohe
// Registry-Namen, die die Node uebersetzt.
func TestRebootReasonsWindows(t *testing.T) {
	text := func(pk ...string) string {
		t.Helper()
		for _, s := range MapReport(nil, &m64proto.Report{V: 1, Reboot: &m64proto.Reboot{Required: true, Packages: pk}}) {
			if s.Key == "reboot" && len(s.Facts) == 1 {
				return modeltest.DE(s.Facts[0].Text)
			}
		}
		t.Fatal("kein Dienst reboot mit Befund")
		return ""
	}
	if got := text("Windows Update", m64proto.HintRebootCBS, m64proto.Hint(m64proto.HintRebootRename, "2", `C:\Program Files\App\app.dll`)); got !=
		`Windows Update, Windows-Komponenten (CBS), 2 Datei(en) werden beim Neustart ersetzt, z. B. C:\Program Files\App\app.dll` {
		t.Errorf("neuer Agent: %q", got)
	}
	if got := text("Component Based Servicing", "PendingFileRenameOperations"); strings.Contains(got, "Component Based") ||
		!strings.Contains(got, "Windows-Komponenten (CBS)") || !strings.Contains(got, "ausstehende Dateiaktionen") {
		t.Errorf("alter Agent: %q", got)
	}
}
