package sync

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/healthchecks"
)

// Verlauf fremder Messstellen vom hub nachladen (nach Zuruecksetzen, neuer Verknuepfung, Offline-Zeit):
// Einzelmessungen der letzten 2 Tage dort, wo eine Luecke ist, und einmal je Verknuepfung die Stundenwerte
// davor (bis 90 Tage, so lange haelt der hub sie). Laeuft im Hintergrund, ein Abruf je Check und Seite.

const (
	SetHistoryHourly = "sync.history_hourly" // Verknuepfung (linked_at), fuer die die Stundenwerte geholt sind
	historyRaw       = 48 * time.Hour
	historyHourly    = 90 * 24 * time.Hour
	historyPage      = 5000
)

// startBackfill haelt die Luecken fest, bevor die ersten Live-Werte kommen, und laedt dann im Hintergrund nach.
func (c *Live) startBackfill(ctx context.Context) {
	if m := c.d.Modules; m != nil && !m.IsRunning(healthchecks.Name) {
		return
	}
	gaps := c.d.HC.HistoryGaps(ctx, historyRaw)
	go c.backfill(gaps)
}

func (c *Live) backfill(gaps map[string]time.Time) {
	if !c.histMu.TryLock() {
		return // laeuft schon
	}
	defer c.histMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	hub, tok := c.hubURL(), c.token()
	raw, hourly := 0, 0
	for token, since := range gaps {
		for page := 0; page < 50; page++ {
			pts, err := c.history(ctx, hub, tok, token, "raw", since, time.Time{})
			if err != nil {
				c.log.Debug("history", "token", token, "err", err)
				break
			}
			raw += c.d.HC.StoreHistory(ctx, token, pts)
			if len(pts) < historyPage {
				break
			}
			since = pts[len(pts)-1].Time
		}
		time.Sleep(50 * time.Millisecond)
	}
	if linked := c.setting(SetLinkedAt, ""); linked != "" && c.setting(SetHistoryHourly, "") != linked {
		now := time.Now().UTC()
		ok := true
		for _, token := range c.d.HC.HistoryTokens(ctx) {
			since := now.Add(-historyHourly)
			for page := 0; page < 20; page++ {
				pts, err := c.history(ctx, hub, tok, token, "hourly", since, now.Add(-historyRaw))
				if err != nil {
					ok = false
					break
				}
				hourly += c.d.HC.StoreHistoryHourly(ctx, token, pts)
				if len(pts) < historyPage {
					break
				}
				since = pts[len(pts)-1].Time
			}
			time.Sleep(50 * time.Millisecond)
		}
		if ok {
			c.set(SetHistoryHourly, linked)
		}
	}
	if raw > 0 || hourly > 0 {
		c.log.Info("history loaded from ipv64", "points", raw, "hourly", hourly, "checks", len(gaps))
	}
}

func (c *Live) history(ctx context.Context, hub, tok, token, kind string, since, until time.Time) ([]healthchecks.HistoryPoint, error) {
	u := hub + "/v1/nodes/me/history?token=" + url.QueryEscape(token) + "&kind=" + kind + "&limit=" + strconv.Itoa(historyPage) +
		"&since=" + url.QueryEscape(since.UTC().Format(time.RFC3339Nano))
	if !until.IsZero() {
		u += "&until=" + url.QueryEscape(until.UTC().Format(time.RFC3339Nano))
	}
	b, err := c.get(ctx, u, tok)
	if err != nil {
		return nil, err
	}
	var out struct {
		Points []healthchecks.HistoryPoint `json:"points"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out.Points, nil
}
