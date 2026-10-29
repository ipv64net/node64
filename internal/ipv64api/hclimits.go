package ipv64api

import (
	"context"
	"sync"
	"time"
)

// HCLimits sind die Healthchecks-Grenzen des Accounts aus GET /hc2/account: fuer Nodes ohne eigene Verknuepfung,
// die Online-/Hybrid-Checks ueber den Cluster anlegen (der hub prueft dieselben Grenzen erst bei der
// weiterreichenden Node). 0 bei Limits = unbegrenzt.
type HCLimits struct {
	Plan         string
	Locations    int // Standorte je Check
	OnlinePoints int // Online-Messstellen (Check x Standort)
	ChecksToday  int
	ChecksPerDay int
}

var hcl struct {
	mu  sync.Mutex
	key string
	at  time.Time
	v   HCLimits
	ok  bool
}

// hcLimitsAge: so lange gilt der zuletzt gelesene Stand.
const hcLimitsAge = 5 * time.Minute

// HCLimits liest die Grenzen (zwischengespeichert); ok=false ohne Key oder wenn ipv64 nicht antwortet.
func (k *Key) HCLimits(ctx context.Context) (HCLimits, bool) {
	key := k.Get(ctx)
	if key == "" {
		return HCLimits{}, false
	}
	hcl.mu.Lock()
	if hcl.key == key && hcl.ok && time.Since(hcl.at) < hcLimitsAge {
		v := hcl.v
		hcl.mu.Unlock()
		return v, true
	}
	hcl.mu.Unlock()
	var in struct {
		Plan   string `json:"plan"`
		Points struct {
			Limit *int `json:"limit"`
		} `json:"online_measuring_points"`
		Locations int `json:"locations_per_check"`
		Daily     struct {
			Used  int  `json:"used"`
			Limit *int `json:"limit"`
		} `json:"checks_per_day"`
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := k.client.get(cctx, key, "/hc2/account", &in); err != nil || in.Plan == "" {
		return HCLimits{}, false
	}
	v := HCLimits{Plan: in.Plan, Locations: in.Locations, ChecksToday: in.Daily.Used}
	if in.Points.Limit != nil {
		v.OnlinePoints = *in.Points.Limit
	}
	if in.Daily.Limit != nil {
		v.ChecksPerDay = *in.Daily.Limit
	}
	hcl.mu.Lock()
	hcl.key, hcl.at, hcl.v, hcl.ok = key, time.Now(), v, true
	hcl.mu.Unlock()
	return v, true
}
