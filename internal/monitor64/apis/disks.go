package apis

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// slowDisks haelt die Platten-Dienste zwischen den SMART-Abfragen (Proxmox VE und PBS).
type slowDisks struct {
	at      time.Time
	svcs    []model.Service
	sectors map[string]uint64 // Schluessel -> Sektoren der vorigen Abfrage
}

// collect liefert die Platten-Dienste; faellig alle every, sonst der letzte Stand. Schlaegt disks/list fehl, bleibt
// der vorige Stand stehen (Dienste verschwinden nicht, naechste Runde neu) und der Fehler geht an part. param baut den Wert fuer
// ?disk= (Proxmox VE: /dev/sda, PBS: sda).
func (s *slowDisks) collect(ctx context.Context, c *proxmox.Client, node string, now time.Time, every time.Duration,
	param func(diskEntry) string, part *partial) []model.Service {
	if every <= 0 {
		every = DefaultSmartEvery
	}
	if !s.at.IsZero() && now.Sub(s.at) < every {
		return s.svcs
	}
	if s.sectors == nil {
		s.sectors = map[string]uint64{}
	}
	base := "/nodes/" + url.PathEscape(node) + "/disks"
	var list []diskEntry
	if err := c.Get(ctx, base+"/list", &list); err != nil {
		part.add("disks/list", err, "disk:")
		if !s.at.IsZero() && now.Sub(s.at) > 4*every {
			s.svcs = nil // keine ewig alten Werte
		}
		return s.svcs
	}
	type res struct {
		sm  *smartData
		bad bool
	}
	results := make([]res, len(list))
	idx := make([]int, len(list))
	for i := range list {
		idx[i] = i
	}
	var authOnce sync.Once
	runParallel(ctx, idx, func(ctx context.Context, i int) {
		var r smartResp
		if err := c.Get(ctx, base+"/smart?disk="+url.QueryEscape(param(list[i])), &r); err != nil {
			results[i].bad = true
			if authErr(err) {
				authOnce.Do(func() { part.add("disks/smart", err, "disk:") })
			}
			return
		}
		d := parseSmart(r)
		results[i].sm = &d
	})
	out := make([]model.Service, 0, len(list))
	seen := map[string]bool{}
	keys := diskKeys(list)
	for i, d := range list {
		if seen[keys[i]] {
			continue // gleiche Seriennummer und WWN zweimal (Multipath): einmal
		}
		svc := diskService(keys[i], d, results[i].sm, results[i].bad, s.sectors)
		seen[svc.Key] = true
		out = append(out, svc)
	}
	for k := range s.sectors {
		if !seen[k] {
			delete(s.sectors, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.at, s.svcs = now, out
	return out
}

// slowUpdates haelt den Dienst "updates" zwischen den Abfragen.
type slowUpdates struct {
	at  time.Time
	svc *model.Service
}

// aptGetter fragt einen API-Pfad ab (Proxmox VE/PBS: proxmox.Client, Mail Gateway: PMG).
type aptGetter interface {
	Get(ctx context.Context, path string, out any) error
}

func (s *slowUpdates) collect(ctx context.Context, c aptGetter, node string, now time.Time, every time.Duration, part *partial) *model.Service {
	if every <= 0 {
		every = DefaultUpdatesEvery
	}
	if !s.at.IsZero() && now.Sub(s.at) < every {
		return s.svc
	}
	var list []aptUpdate
	if err := c.Get(ctx, "/nodes/"+url.PathEscape(node)+"/apt/update", &list); err != nil {
		var pe *proxmox.Error
		if (errors.As(err, &pe) && pe.Status == http.StatusForbidden) || errors.Is(err, errWebPerm) {
			// dem Token fehlt das Recht (Proxmox VE: Sys.Modify, die Rolle PVEAuditor reicht nicht): kein Teilfehler,
			// der Dienst nennt den Grund; neuer Versuch erst nach every
			svc := model.Service{Key: "updates", Name: "Updates", Kind: "updates", Default: true, Text: model.T("monitor64.txt.updates_forbidden")}
			s.at, s.svc = now, &svc
			return s.svc
		}
		part.add("apt/update", err, "updates")
		if !s.at.IsZero() && now.Sub(s.at) > 4*every {
			s.svc = nil
		}
		return s.svc
	}
	svc := updatesService(list)
	s.at, s.svc = now, &svc
	return s.svc
}
