package environment

import (
	"context"
	"sync"
	"time"
)

// Status der hinzugefuegten Nodes fuer die Liste: kurz gemerkt statt bei jedem Seitenaufruf neu (je Node eine
// TLS-Verbindung, bis zu 3 s). Frisch (30 s) kommt er aus dem Speicher; bis 10 min alt ebenso, waehrend im
// Hintergrund neu gefragt wird; sonst wird gewartet. Ein abgelehnter Schluessel (widerrufen, Benutzer gesperrt) wird
// 10 min lang nicht neu versucht - sonst zaehlte jeder Seitenaufruf bei der anderen Node als Fehlversuch. Aendern der
// Node (neuer Schluessel) verwirft den gemerkten Stand.

const (
	statusFresh = 30 * time.Second
	statusKeep  = 10 * time.Minute
)

type statusEntry struct {
	st   AddedStatus
	at   time.Time
	ver  time.Time // UpdatedAt der Node beim Abfragen
	busy bool      // Abfrage im Hintergrund laeuft
}

type statusCache struct {
	mu sync.Mutex
	m  map[string]*statusEntry
}

func (s *Service) statusTTL() time.Duration {
	if s.d.StatusTTL != 0 {
		return s.d.StatusTTL
	}
	return statusFresh
}

// CachedStatus liefert den Status einer hinzugefuegten Node fuer die Liste (siehe oben).
func (s *Service) CachedStatus(ctx context.Context, n *AddedNode) AddedStatus {
	if s.statusTTL() < 0 {
		return s.Status(ctx, n)
	}
	now := s.d.Now()
	c := &s.sc
	c.mu.Lock()
	if e := c.m[n.UID]; e != nil && e.ver.Equal(n.UpdatedAt) {
		age, ttl := now.Sub(e.at), s.statusTTL()
		if e.st.Denied {
			ttl = statusKeep
		}
		switch {
		case age < ttl:
			st := e.st
			c.mu.Unlock()
			return st
		case age < statusKeep:
			if !e.busy {
				e.busy = true
				nc := *n
				go func() {
					bctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), statusTimeout+time.Second)
					defer cancel()
					s.putStatus(&nc, s.Status(bctx, &nc))
				}()
			}
			st := e.st
			c.mu.Unlock()
			return st
		}
	}
	c.mu.Unlock()
	st := s.Status(ctx, n)
	s.putStatus(n, st)
	return st
}

func (s *Service) putStatus(n *AddedNode, st AddedStatus) {
	now := s.d.Now()
	c := &s.sc
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]*statusEntry{}
	}
	for k, e := range c.m {
		if now.Sub(e.at) > statusKeep {
			delete(c.m, k)
		}
	}
	c.m[n.UID] = &statusEntry{st: st, at: now, ver: n.UpdatedAt}
}

// markDenied merkt sich, dass die andere Node den Schluessel abgelehnt hat (z. B. beim Oeffnen).
func (s *Service) markDenied(n *AddedNode, msg string) {
	s.putStatus(n, AddedStatus{Online: true, KeyErr: msg, Denied: true})
}
