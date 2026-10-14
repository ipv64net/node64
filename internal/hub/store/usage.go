package store

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Tageskontingent der Online-Healthchecks wie im alten System (Klasse: healthcheck_update_limit,
// 0 = unbegrenzt): jede Online-Messung je Standort und jeder Push an die Online-Adresse zaehlt. Ist das
// Kontingent erschoepft, pausieren Online-Messungen und Push-Auswertung des Accounts bis zum naechsten
// Tag (Europe/Berlin). Lokale Messungen der Nodes zaehlen nicht. Gezaehlt wird im Speicher, alle 30 s
// gebuendelt in hc2_usage_daily geschrieben und mit dem Stand des anderen hubs zusammengefuehrt.

// ErrDailyLimit: Tageskontingent erschoepft (Push wird nicht angenommen).
var ErrDailyLimit = errors.New("daily check limit reached")

type usage struct {
	mu      sync.Mutex
	day     string
	pending map[int64]int       // seit dem letzten Schreiben
	total   map[int64]int       // Stand heute (Datenbank + eigene seither)
	limit   map[int64]int       // Klassenlimit je Account (0 = unbegrenzt)
	limitAt map[int64]time.Time // wann das Limit geladen wurde
	blocked map[int64]bool
	warned  bool // Tabelle fehlt: nur einmal melden
}

var berlin = func() *time.Location {
	if l, err := time.LoadLocation("Europe/Berlin"); err == nil {
		return l
	}
	return time.UTC
}()

func usageDay(t time.Time) string { return t.In(berlin).Format("2006-01-02") }

// rollover setzt die Zaehler am Tageswechsel zurueck (u.mu gehalten). Liefert die bisher gesperrten Accounts.
func (u *usage) rollover(now time.Time) []int64 {
	day := usageDay(now)
	if u.day == day && u.total != nil {
		return nil
	}
	var freed []int64
	for id, b := range u.blocked {
		if b {
			freed = append(freed, id)
		}
	}
	if u.limit == nil {
		u.limit, u.limitAt = map[int64]int{}, map[int64]time.Time{}
	}
	u.day, u.pending, u.total, u.blocked = day, map[int64]int{}, map[int64]int{}, map[int64]bool{}
	return freed
}

// DailyBlocked: Tageskontingent des Accounts erschoepft.
func (s *Store) DailyBlocked(userID int64) bool {
	u := &s.use
	u.mu.Lock()
	freed := u.rollover(time.Now())
	b := u.blocked[userID]
	u.mu.Unlock()
	s.usageFlipped(freed, false)
	return b
}

// countUse zaehlt eine Online-Messung bzw. einen Push.
func (s *Store) countUse(userID int64) {
	if userID <= 0 {
		return
	}
	u := &s.use
	u.mu.Lock()
	freed := u.rollover(time.Now())
	u.pending[userID]++
	u.total[userID]++
	flip := false
	if lim := u.limit[userID]; lim > 0 && u.total[userID] >= lim && !u.blocked[userID] {
		u.blocked[userID], flip = true, true
	}
	u.mu.Unlock()
	s.usageFlipped(freed, false)
	if flip {
		s.usageFlipped([]int64{userID}, true)
	}
}

// AllowRun ist das Tor des Schedulers: Messungen zaehlen, Push-Auswertungen nicht; bei erschoepftem
// Kontingent wird beides ausgesetzt (keine Fehlalarme wegen ausbleibender Pushes).
func (s *Store) AllowRun(token string, push bool) bool {
	s.mu.RLock()
	uid := s.users[token]
	s.mu.RUnlock()
	if uid <= 0 {
		return true
	}
	if s.DailyBlocked(uid) {
		return false
	}
	if !push {
		s.countUse(uid)
	}
	return true
}

// TrackUsage nimmt Accounts in den Abgleich auf (verbundene Nodes), auch wenn dieser hub ihre Checks
// nicht misst: so kennt der hub ihren Stand und meldet Sperre/Freigabe an die Nodes.
func (s *Store) TrackUsage(ids []int64) {
	u := &s.use
	u.mu.Lock()
	freed := u.rollover(time.Now())
	for _, id := range ids {
		if _, ok := u.total[id]; !ok {
			u.total[id] = 0
		}
	}
	u.mu.Unlock()
	s.usageFlipped(freed, false)
}

// DailyUsage liefert den heutigen Verbrauch und das Klassenlimit (0 = unbegrenzt) aus dem Speicher.
func (s *Store) DailyUsage(userID int64) (today, limit int, known bool) {
	u := &s.use
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.day != usageDay(time.Now()) {
		return 0, u.limit[userID], false
	}
	_, known = u.limitAt[userID]
	return u.total[userID], u.limit[userID], known
}

func (s *Store) usageFlipped(ids []int64, blocked bool) {
	if len(ids) == 0 {
		return
	}
	for _, id := range ids {
		s.log.Info("daily check limit", "user", id, "blocked", blocked)
	}
	if f := s.OnUsageFlip; f != nil {
		for _, id := range ids {
			f(id, blocked)
		}
	}
}

// UsageLoop schreibt den Verbrauch alle 30 s und gleicht ihn mit dem anderen hub ab.
func (s *Store) UsageLoop(ctx context.Context) {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			s.FlushUsage(fctx)
			cancel()
			return
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			s.FlushUsage(fctx)
			cancel()
		}
	}
}

// FlushUsage schreibt die offenen Zaehler, liest die Tagesstaende und Limits und setzt die Sperren neu.
func (s *Store) FlushUsage(ctx context.Context) {
	u := &s.use
	u.mu.Lock()
	freed := u.rollover(time.Now())
	day, pending := u.day, u.pending
	u.pending = map[int64]int{}
	var ids []int64
	for id := range u.total {
		ids = append(ids, id)
	}
	var needLimit []int64
	for _, id := range ids {
		if at, ok := u.limitAt[id]; !ok || time.Since(at) > 10*time.Minute {
			needLimit = append(needLimit, id)
		}
	}
	u.mu.Unlock()
	s.usageFlipped(freed, false)

	if len(pending) > 0 {
		var ph []string
		var args []any
		for id, n := range pending {
			ph = append(ph, "(?,?,?)")
			args = append(args, id, day, n)
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO hc2_usage_daily (userid, day, checks) VALUES `+strings.Join(ph, ",")+` ON DUPLICATE KEY UPDATE checks = checks + VALUES(checks)`, args...); err != nil {
			u.mu.Lock()
			if !u.warned {
				s.log.Warn("daily usage not stored (only counted on this hub)", "err", err)
				u.warned = true
			}
			u.mu.Unlock()
		}
	}
	dbTotal := map[int64]int{}
	limits := map[int64]int{}
	for len(ids) > 0 || len(needLimit) > 0 {
		n := min(len(ids), 500)
		if n > 0 {
			part := ids[:n]
			ids = ids[n:]
			ph, args := inArgs(part)
			if rows, err := s.db.QueryContext(ctx, `SELECT userid, checks FROM hc2_usage_daily WHERE day = ? AND userid IN (`+ph+`)`, append([]any{day}, args...)...); err == nil {
				for rows.Next() {
					var id int64
					var c int
					if rows.Scan(&id, &c) == nil {
						dbTotal[id] = c
					}
				}
				rows.Close()
			}
		}
		m := min(len(needLimit), 500)
		if m > 0 {
			part := needLimit[:m]
			needLimit = needLimit[m:]
			ph, args := inArgs(part)
			if rows, err := s.db.QueryContext(ctx, `SELECT v.id, c.healthcheck_update_limit FROM ipv64.hc2_users_v v JOIN ipv64.user_class c ON c.id = v.user_class WHERE v.id IN (`+ph+`)`, args...); err == nil {
				for rows.Next() {
					var id int64
					var l int
					if rows.Scan(&id, &l) == nil {
						limits[id] = l
					}
				}
				rows.Close()
			}
		}
	}

	var on, off []int64
	u.mu.Lock()
	if u.day == day {
		now := time.Now()
		for id, l := range limits {
			u.limit[id], u.limitAt[id] = l, now
		}
		for id, c := range dbTotal {
			if v := c + u.pending[id]; v > u.total[id] {
				u.total[id] = v // der andere hub hat mitgezaehlt
			}
		}
		for id, total := range u.total {
			b := u.limit[id] > 0 && total >= u.limit[id]
			if b != u.blocked[id] {
				u.blocked[id] = b
				if b {
					on = append(on, id)
				} else {
					off = append(off, id)
				}
			}
		}
	}
	u.mu.Unlock()
	s.usageFlipped(on, true)
	s.usageFlipped(off, false)
}

// PruneUsage loescht Tageszaehler aelter als 35 Tage (taeglich durch den Housekeeper).
func (s *Store) PruneUsage(ctx context.Context) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM hc2_usage_daily WHERE day < ?`, usageDay(time.Now().AddDate(0, 0, -35)))
}

func inArgs(ids []int64) (string, []any) {
	ph := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		ph[i], args[i] = "?", id
	}
	return strings.Join(ph, ","), args
}
