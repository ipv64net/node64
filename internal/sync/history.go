package sync

import (
	"context"
	"encoding/json"
	"net/url"
	"strconv"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/healthchecks"
)

// Verlauf fremder Messstellen vom hub nachladen (nach Zuruecksetzen, neuer Verknuepfung, Offline-Zeit):
// Einzelmessungen der letzten 2 Tage dort, wo eine Luecke ist, und einmal je Verknuepfung die Stundenwerte
// davor (bis 90 Tage, so lange haelt der hub sie). Laeuft im Hintergrund, ein Abruf je Check und Seite.

const (
	SetHistoryHourly = "sync.history_full" // Verknuepfung (linked_at), fuer die der Verlauf davor geholt ist
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
	loadRaw := func(token string, since, until time.Time) bool {
		for page := 0; page < 50; page++ {
			pts, err := c.history(ctx, hub, tok, token, "raw", since, until)
			if err != nil {
				c.log.Debug("history", "token", checks.TokenHint(token), "err", err)
				return false
			}
			raw += c.d.HC.StoreHistory(ctx, token, pts)
			if len(pts) < historyPage {
				return true
			}
			since = pts[len(pts)-1].Time
		}
		return true
	}
	for token, since := range gaps { // Luecke am Ende (Offline-Zeit)
		loadRaw(token, since, time.Time{})
		time.Sleep(50 * time.Millisecond)
	}
	if linked := c.setting(SetLinkedAt, ""); linked != "" && c.setting(SetHistoryHourly, "") != linked {
		// einmal je Verknuepfung: Einzelpunkte vor dem aeltesten eigenen Stand, davor Stundenwerte
		now := time.Now().UTC()
		cut := now.Add(-historyRaw).Truncate(time.Hour) // davor Stundenwerte, ab hier Einzelpunkte (keine Ueberschneidung)
		ok := true
		earliest := c.d.HC.HistoryEarliest(ctx)
		for _, token := range c.d.HC.HistoryTokens(ctx) {
			if e, has := earliest[token]; has && e.After(cut) {
				ok = loadRaw(token, cut, e) && ok
			}
			c.d.HC.DropSourceHourlyFrom(ctx, token, cut) // ab hier gibt es Einzelpunkte
			since := now.Add(-historyHourly)
			for page := 0; page < 20; page++ {
				pts, err := c.history(ctx, hub, tok, token, "hourly", since, cut)
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
