// Package netstat zaehlt den Netzwerkverkehr des Containers (alle Schnittstellen ausser lo)
// aus /proc/net/dev und fuehrt eine Gesamtsumme ueber Neustarts in den Einstellungen.
package netstat

import (
	"bufio"
	"context"
	"os"
	"strconv"
	"strings"
	"time"
)

// Settings ist der Teil des Stores, den der Zaehler braucht.
type Settings interface {
	SettingOr(ctx context.Context, key, def string) string
	SetSetting(ctx context.Context, key, value string) error
}

const (
	keyRxTotal = "stats.net_rx_total"
	keyTxTotal = "stats.net_tx_total"
	keyRxLast  = "stats.net_rx_last"
	keyTxLast  = "stats.net_tx_last"
	keySince   = "stats.net_since"
)

// Read liefert empfangene und gesendete Bytes seit Start des Netzwerk-Namensraums.
func Read() (rx, tx int64, ok bool) {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.TrimSpace(line[:i]) == "lo" {
			continue
		}
		fs := strings.Fields(line[i+1:])
		if len(fs) < 9 {
			continue
		}
		r, _ := strconv.ParseInt(fs[0], 10, 64)
		t, _ := strconv.ParseInt(fs[8], 10, 64)
		rx += r
		tx += t
		ok = true
	}
	return rx, tx, ok
}

// Totals liefert die Gesamtsummen (ueber Neustarts) und den Beginn der Zaehlung.
func Totals(ctx context.Context, s Settings) (rx, tx int64, since time.Time) {
	rx, _ = strconv.ParseInt(s.SettingOr(ctx, keyRxTotal, "0"), 10, 64)
	tx, _ = strconv.ParseInt(s.SettingOr(ctx, keyTxTotal, "0"), 10, 64)
	since, _ = time.Parse(time.RFC3339, s.SettingOr(ctx, keySince, ""))
	return rx, tx, since
}

// Loop schreibt alle 10 Minuten und beim Beenden die Zuwaechse in die Gesamtsumme (Zaehler-Ruecksprung =
// Neustart); unveraenderte Werte werden nicht geschrieben (schont SD-Karten).
func Loop(ctx context.Context, s Settings) {
	wctx := context.WithoutCancel(ctx) // auch beim Beenden noch schreiben
	update := func() {
		rx, tx, ok := Read()
		if !ok {
			return
		}
		if s.SettingOr(wctx, keySince, "") == "" {
			_ = s.SetSetting(wctx, keySince, time.Now().UTC().Format(time.RFC3339))
		}
		add := func(totalKey, lastKey string, cur int64) {
			last, _ := strconv.ParseInt(s.SettingOr(wctx, lastKey, "-1"), 10, 64)
			delta := cur - last
			if last < 0 || delta < 0 {
				delta = cur // erster Lauf oder Zaehler neu (Container neu gestartet)
				if last < 0 {
					delta = 0
				}
			}
			if delta == 0 && last == cur {
				return
			}
			total, _ := strconv.ParseInt(s.SettingOr(wctx, totalKey, "0"), 10, 64)
			_ = s.SetSetting(wctx, totalKey, strconv.FormatInt(total+delta, 10))
			_ = s.SetSetting(wctx, lastKey, strconv.FormatInt(cur, 10))
		}
		add(keyRxTotal, keyRxLast, rx)
		add(keyTxTotal, keyTxLast, tx)
	}
	update()
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			update()
			return
		case <-t.C:
			update()
		}
	}
}
