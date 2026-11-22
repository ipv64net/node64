package apis

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
	"github.com/ipv64net/node64/internal/proxmox"
)

// slowDisks haelt die Platten-Dienste zwischen den SMART-Abfragen (Proxmox VE und PBS).
type slowDisks struct {
	at      time.Time
	svcs    []model.Service
	sectors map[string]uint64 // Schluessel -> Sektoren der vorigen Abfrage
	again   atomic.Bool       // ohne SMART: Plattenliste in der naechsten Runde neu lesen ("Dienste erkennen")
}

// refresh: ohne SMART die Plattenliste in der naechsten Runde neu lesen.
func (s *slowDisks) refresh() { s.again.Store(true) }

// collect liefert die Platten-Dienste; faellig alle every, sonst der letzte Stand. Schlaegt disks/list fehl, bleibt
// der vorige Stand stehen (Dienste verschwinden nicht, naechste Runde neu) und der Fehler geht an part. param baut den Wert fuer
// ?disk= (Proxmox VE: /dev/sda, PBS: sda). noSmart: Platten ohne SMART - disks/list mit skipsmart=1 und kein
// disks/smart; Proxmox ruft dafuer smartctl ohne "-n standby" auf und weckt schlafende Platten (#215). Auch
// disks/list mit skipsmart=1 greift auf die Platten zu und weckt sie: ohne SMART liest collect die Liste (Groesse,
// Modell, Seriennummer) daher nur einmal (Start, geaenderter Zugang) und nach refresh ("Dienste erkennen").
func (s *slowDisks) collect(ctx context.Context, c *proxmox.Client, node string, now time.Time, every time.Duration, noSmart bool,
	param func(diskEntry) string, part *partial) []model.Service {
	if every <= 0 {
		every = DefaultSmartEvery
	}
	if noSmart {
		if again := s.again.Swap(false); !s.at.IsZero() && !again {
			return s.svcs
		}
	} else if !s.at.IsZero() && now.Sub(s.at) < every {
		return s.svcs
	}
	if s.sectors == nil {
		s.sectors = map[string]uint64{}
	}
	base := "/nodes/" + url.PathEscape(node) + "/disks"
	var list []diskEntry
	listPath := base + "/list"
	if noSmart {
		listPath += "?skipsmart=1"
	}
	if err := c.Get(ctx, listPath, &list); err != nil {
		part.add("disks/list", err, "disk:")
		if noSmart {
			s.again.Store(true) // naechste Runde neu versuchen; der vorige Stand bleibt (aendert sich ohne SMART kaum)
			return s.svcs
		}
		if !s.at.IsZero() && now.Sub(s.at) > 4*every {
			s.svcs = nil // keine ewig alten Werte
		}
		return s.svcs
	}
	type res struct {
		sm  *smartData
		raw smartResp
		bad bool
	}
	results := make([]res, len(list))
	idx := make([]int, len(list))
	for i := range list {
		idx[i] = i
	}
	var authOnce sync.Once
	if noSmart {
		idx = nil
		for i := range list { // Zustand und Verschleiss stammen aus SMART: ohne Abfrage nicht werten
			list[i].Health, list[i].Status, list[i].Wearout = "", "", optNum{}
		}
	}
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
		results[i].sm, results[i].raw = &d, r
	})
	out := make([]model.Service, 0, len(list))
	seen := map[string]bool{}
	keys := diskKeys(list)
	for i, d := range list {
		if seen[keys[i]] {
			continue // gleiche Seriennummer und WWN zweimal (Multipath): einmal
		}
		svc := diskService(keys[i], d, results[i].sm, results[i].bad, s.sectors)
		if sm := results[i].sm; sm != nil { // alle Werte zum Nachschlagen (Dialog in der Dienste-Tabelle)
			svc.Smart = smartDetailOf(results[i].raw, d, sm.passed, now)
		}
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
