package healthchecks

import (
	"context"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/module"
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

// hcQuota: Karte unter der Check-Tabelle – Verbrauch heute, Hochrechnung aus den aktiven Online-/Hybrid-Checks und
// wann das Kontingent voraussichtlich erreicht ist. Der hub zaehlt ab Mitternacht Europe/Berlin.
type hcQuota struct {
	Today, Limit int64
	PerDay       int64 // Messungen an einem ganzen Tag mit den aktiven Checks
	AtMidnight   int64 // voraussichtlicher Stand um Mitternacht
	Pct          int
	Bar          float64
	Class        string
	Reached      bool      // heute schon erreicht
	Short        bool      // reicht heute nicht: EmptyAt liegt vor Mitternacht
	Tomorrow     bool      // ein ganzer Tag braucht mehr als das Kontingent
	EmptyAt      time.Time // voraussichtlich erreicht (nur bei Short)
	ResetAt      time.Time // naechste Mitternacht
}

var quotaZone = func() *time.Location {
	if l, err := time.LoadLocation("Europe/Berlin"); err == nil {
		return l
	}
	return time.UTC
}()

func newHCQuota(today, limit, perDay int, now time.Time) *hcQuota {
	q := &hcQuota{Today: int64(today), Limit: int64(limit), PerDay: int64(perDay)}
	b := now.In(quotaZone)
	q.ResetAt = time.Date(b.Year(), b.Month(), b.Day()+1, 0, 0, 0, 0, quotaZone)
	rate := float64(perDay) / 86400 // Messungen je Sekunde
	q.AtMidnight = int64(today) + int64(rate*q.ResetAt.Sub(now).Seconds())
	q.Pct = min(100, today*100/limit)
	q.Reached = today >= limit
	q.Tomorrow = perDay > limit
	if !q.Reached && q.AtMidnight > q.Limit && rate > 0 {
		q.Short = true
		q.EmptyAt = now.Add(time.Duration(float64(limit-today)/rate) * time.Second)
	}
	q.Bar, q.Class = module.BarWidth(float64(q.Pct), today > 0), module.BarClassOf(float64(q.Pct), q.Short)
	return q
}
