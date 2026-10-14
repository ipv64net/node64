package ipv64api

import (
	"context"
	"strconv"
	"sync"
	"time"
)

// Account-Uebersicht fuer das Dashboard: alle Limits des Accounts direkt aus der API v2 (GET /me, fuer
// Healthchecks 2.0 zusaetzlich GET /hc2/account), im Speicher zwischengespeichert.

// Limit ist ein Verbrauch mit Grenze.
type Limit struct {
	Key       string  // z. B. dyndns_domains, hc_points
	Used      float64 // bei Traffic in GB
	Max       float64
	Unlimited bool
}

// Pct ist der Verbrauch in Prozent (0 bei unbegrenzt, hoechstens 100).
func (l Limit) Pct() int {
	if l.Unlimited || l.Max <= 0 {
		return 0
	}
	p := int(l.Used * 100 / l.Max)
	return min(p, 100)
}

// UsedText / MaxText: ganze Zahlen ohne, Traffic mit zwei Nachkommastellen.
func (l Limit) UsedText() string { return numText(l.Used) }
func (l Limit) MaxText() string  { return numText(l.Max) }

func numText(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}

// Warn: ab 80 %; Full: ausgeschoepft.
func (l Limit) Warn() bool { return !l.Unlimited && l.Max > 0 && l.Pct() >= 80 }
func (l Limit) Full() bool { return !l.Unlimited && l.Max > 0 && l.Used >= l.Max }

// Overview ist der Stand des Accounts hinter dem zentralen Key.
type Overview struct {
	Account   string
	Plan      string
	PlanUntil time.Time
	Limits    []Limit
	At        time.Time
	Err       string // letzter Fehler (die Werte stammen dann vom letzten Erfolg)
}

// Reihenfolge der Anzeige; hc_* kommen aus /hc2/account (Healthchecks 2.0), sonst aus /me.
var limitOrder = []string{"dyndns_domains", "own_domains", "dyndns_updates_24h", "hc_points", "hc_checks_today", "sms_24h",
	"failover_policies", "failover_monitors", "failover_rules", "cdn_domains", "cdn_traffic_gb", "vpn_traffic_gb", "dns64_clients"}

type usage struct {
	Used  float64  `json:"used"`
	Limit *float64 `json:"limit"` // null = unbegrenzt
}

func (u usage) limit(key string) Limit {
	l := Limit{Key: key, Used: u.Used, Unlimited: u.Limit == nil}
	if u.Limit != nil {
		l.Max = *u.Limit
	}
	return l
}

func (c *Client) overview(ctx context.Context, key string) (*Overview, error) {
	var me struct {
		Email    string  `json:"email"`
		Username *string `json:"username"`
		Plan     struct {
			Name       string     `json:"name"`
			ValidUntil *time.Time `json:"valid_until"`
		} `json:"plan"`
		Usage map[string]usage `json:"usage"`
	}
	if err := c.get(ctx, key, "/me", &me); err != nil {
		return nil, err
	}
	ov := &Overview{Account: me.Email, Plan: me.Plan.Name, At: time.Now()}
	if me.Username != nil && *me.Username != "" {
		ov.Account = *me.Username
	}
	if me.Plan.ValidUntil != nil && me.Plan.ValidUntil.After(time.Now()) { // altes Datum bei Dauertarifen nicht zeigen
		ov.PlanUntil = *me.Plan.ValidUntil
	}
	// Healthchecks 2.0: Online-Messstellen und Tageskontingent; ohne die Route (Account noch nicht
	// umgestellt) die Werte des alten Systems aus /me
	var hc struct {
		Points usage  `json:"online_measuring_points"`
		Daily  *usage `json:"checks_per_day"`
	}
	src := map[string]usage{}
	for k, u := range me.Usage {
		src[k] = u
	}
	if err := c.get(ctx, key, "/hc2/account", &hc); err == nil {
		src["hc_points"] = hc.Points
		if hc.Daily != nil {
			src["hc_checks_today"] = *hc.Daily
		}
	} else {
		if u, ok := me.Usage["healthchecks"]; ok {
			src["hc_points"] = u
		}
		if u, ok := me.Usage["healthcheck_pings_24h"]; ok {
			src["hc_checks_today"] = u
		}
	}
	for _, k := range limitOrder {
		u, ok := src[k]
		if !ok {
			continue
		}
		l := u.limit(k)
		if !l.Unlimited && l.Max == 0 && l.Used == 0 {
			continue // nicht im Tarif und nicht benutzt
		}
		ov.Limits = append(ov.Limits, l)
	}
	return ov, nil
}

type overviewCache struct {
	mu      sync.Mutex
	ov      *Overview
	key     string // fuer welchen Key (neuer Key = neu laden)
	loading bool
}

// ResetOverview verwirft den Zwischenstand; der naechste Aufruf von Overview fragt sofort neu.
func (k *Key) ResetOverview() {
	k.ovc.mu.Lock()
	if !k.ovc.loading {
		k.ovc.ov = nil
	}
	k.ovc.mu.Unlock()
}

// Overview liefert den Account-Stand: ohne Zwischenstand sofort abgefragt, sonst aus dem Speicher und,
// wenn aelter als maxAge, im Hintergrund erneuert. nil = kein Key hinterlegt.
func (k *Key) Overview(ctx context.Context, maxAge time.Duration) *Overview {
	key := k.Get(ctx)
	if key == "" {
		return nil
	}
	c := &k.ovc
	c.mu.Lock()
	have := c.ov != nil && c.key == key
	stale := !have || time.Since(c.ov.At) > maxAge
	start := stale && !c.loading
	if start {
		c.loading = true
	}
	c.mu.Unlock()
	if start {
		load := func() {
			lctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			ov, err := k.client.overview(lctx, key)
			cancel()
			c.mu.Lock()
			defer c.mu.Unlock()
			c.loading = false
			if err != nil {
				if c.ov != nil && c.key == key {
					cp := *c.ov
					cp.Err, cp.At = err.Error(), time.Now() // alte Werte behalten, nicht sofort erneut fragen
					c.ov = &cp
				} else {
					c.ov, c.key = &Overview{Err: err.Error(), At: time.Now()}, key
				}
				return
			}
			c.ov, c.key = ov, key
		}
		if have {
			go load()
		} else {
			load()
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ov == nil || c.key != key {
		return &Overview{}
	}
	cp := *c.ov
	return &cp
}
