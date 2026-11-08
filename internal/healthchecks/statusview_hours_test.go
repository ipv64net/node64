package healthchecks

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/scheduler"
)

// Zeitraum 24 h: 24 Stundenbalken (Beschriftung in der Zeitzone der Node), 7 Tage: 7 Tagesbalken; ungueltig = 90.
func TestStatusHourBars(t *testing.T) {
	m, _ := newStatusModule(t)
	now := statusFixNow(t, m) // 20.10.2026 08:00 UTC = 10:00 Europe/Berlin
	rt := scheduler.Runtime{State: scheduler.StateUp, Since: now.Add(-time.Hour), LastCheck: now.Add(-30 * time.Second)}
	a := statusAddCheck(t, m, "A", rt)
	// laufende Stunde (08 UTC): up; 06 UTC: 1 von 2 down -> down (50 %); 25 h alt: ausserhalb
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 20, 7, 59, 0, 0, time.UTC), true, 0)
	statusMeasure(t, m, a.Token, now, true, 0)
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 20, 6, 10, 0, 0, time.UTC), true, 0)
	statusMeasure(t, m, a.Token, time.Date(2026, 10, 20, 6, 20, 0, 0, time.UTC), false, 0)
	statusMeasure(t, m, a.Token, now.Add(-25*time.Hour), false, 0)
	// aeltere Stunde aus hc_hourly (Einzelpunkte schon verdichtet): 20.10. 00 UTC up
	if _, err := m.st.w.Exec(`INSERT INTO hc_hourly (token, hour, count, up_count, min_ms, avg_ms, max_ms) VALUES (?,?,?,?,1,2,3)`,
		a.Token, "2026-10-20T00:00:00.000Z", 60, 60); err != nil {
		t.Fatal(err)
	}

	p := statusSavePage(t, m, &StatusPage{Slug: "hours", Title: "H", Enabled: true, Layout: "list", Days: 1, ShowUptime: true,
		Groups: []StatusGroup{{Name: "G", Items: []StatusItem{{Token: a.Token}}}}}, "")
	if p.Days != 1 {
		t.Fatalf("days stored: %d", p.Days)
	}
	v, err := m.statusView(context.Background(), p, "de")
	if err != nil {
		t.Fatal(err)
	}
	bars := v.Groups[0].Items[0].Bars
	if v.Days != 1 || len(bars) != 24 {
		t.Fatalf("days %d bars %d", v.Days, len(bars))
	}
	// letzte Stunde 08 UTC = 10 Uhr Berlin, erste 09 UTC am Vortag = 11 Uhr Berlin
	if bars[23].Day != "2026-10-20T10" || bars[0].Day != "2026-10-19T11" {
		t.Fatalf("labels %s .. %s", bars[0].Day, bars[23].Day)
	}
	if bars[23].State != "up" || bars[21].State != "down" || bars[21].Uptime != 50 || bars[22].State != "up" || bars[15].State != "up" || bars[1].State != "none" {
		t.Errorf("states: 23=%+v 22=%+v 21=%+v 15=%+v 1=%+v", bars[23], bars[22], bars[21], bars[15], bars[1])
	}
	v.Layout = "list"
	html := stRender(t, v, statusRenderOpts{Lang: "de"})
	if !strings.Contains(html, `data-h="2026-10-19T11"`) || strings.Contains(html, `data-s=`) || !strings.Contains(html, "hc.status.pub.bars.aria_h") ||
		!strings.Contains(html, "20.10. 08:00") {
		t.Errorf("html: hourly attributes/labels missing")
	}

	p.Days = 7
	p = statusSavePage(t, m, p, "")
	v, err = m.statusView(context.Background(), p, "de")
	if err != nil {
		t.Fatal(err)
	}
	if b := v.Groups[0].Items[0].Bars; v.Days != 7 || len(b) != 7 || b[6].Day != "2026-10-20" {
		t.Fatalf("7 days: %d %d", v.Days, len(b))
	}
	p.Days = 14 // ungueltig
	p = statusSavePage(t, m, p, "")
	if p.Days != 90 {
		t.Fatalf("invalid days -> %d", p.Days)
	}
}
