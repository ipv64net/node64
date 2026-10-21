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

// OnlinePoints: belegte Online-Messstellen (Check x Standort) wie der hub zaehlt: alle Online- und Hybrid-Checks
// des Accounts, auch pausierte; ohne exclude (der gerade bearbeitete Check).
func (m *Module) OnlinePoints(ctx context.Context, exclude string, accLocs int) int {
	list, err := m.st.Checks(ctx)
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range list {
		if c.Token != exclude {
			n += CheckOnlinePoints(c, accLocs)
		}
	}
	return n
}

// CheckOnlinePoints: belegte Online-Messstellen eines Checks (wie OnlinePoints, fuer eine schon geladene Liste).
func CheckOnlinePoints(c *Check, accLocs int) int {
	if c.Execution == "online" || c.Execution == "both" {
		return onlineLocs(c, accLocs)
	}
	return 0
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
