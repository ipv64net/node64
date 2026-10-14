package healthchecks

import (
	"context"

	"github.com/ipv64net/node64/internal/checks"
)

// Tageskontingent der Online-Checks: Hochrechnung des taeglichen Verbrauchs (Online-Messungen je
// Standort) wie der hub zaehlt. Pushes haengen vom Absender ab und werden nicht hochgerechnet.

// onlineLocs ist die Zahl der Standorte, an denen der hub einen Check misst (leer = beide, bei
// Accounts mit nur einem Standort je Check hoechstens einer).
func onlineLocs(c *Check, accLocs int) int {
	n := len(c.Locations)
	if n == 0 {
		n = 2
	}
	if accLocs == 1 && n > 1 {
		n = 1
	}
	return n
}

// CheckDailyCost: Online-Messungen pro Tag fuer einen Check (0 = lokal, pausiert oder Push).
func CheckDailyCost(c *Check, accLocs int) int {
	if c.Execution == "local" || c.Execution == "" || c.Paused || c.Type == checks.TypePush || c.Interval <= 0 {
		return 0
	}
	return 86400 / int(c.Interval.Seconds()) * onlineLocs(c, accLocs)
}

// DailyProjection rechnet den Tagesverbrauch aller aktiven Online-/Hybrid-Checks des Accounts hoch
// (ohne exclude, z. B. den gerade bearbeiteten Check).
func (m *Module) DailyProjection(ctx context.Context, exclude string, accLocs int) int {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return 0
	}
	sum := 0
	for _, c := range list {
		if c.Token != exclude {
			sum += CheckDailyCost(c, accLocs)
		}
	}
	return sum
}
