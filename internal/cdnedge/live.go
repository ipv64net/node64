package cdnedge

import (
	"net/netip"
	"sync"
)

// Offene Verbindungen je Name: Sperre (z. B. Traffic aufgebraucht), Liste und Modus werden beim Aufbau geprueft -
// lange Verbindungen (Portmapper, WebSocket, QUIC-Fluesse, Downloads) prueft der Server nach jeder neuen
// Konfiguration erneut und trennt, was nicht mehr erlaubt ist.

type liveConns struct {
	mu sync.Mutex
	m  map[*liveConn]struct{}
}

type liveConn struct {
	name   string
	mode   int
	client netip.Addr // ungueltig = nicht nach Adresse pruefen
	cancel func()
}

// track merkt sich eine Verbindung; die Rueckgabe vergisst sie wieder (am Ende der Verbindung).
func (s *Server) track(name string, mode int, client netip.Addr, cancel func()) func() {
	l := &liveConn{name: name, mode: mode, client: client.Unmap(), cancel: cancel}
	s.live.mu.Lock()
	if s.live.m == nil {
		s.live.m = map[*liveConn]struct{}{}
	}
	s.live.m[l] = struct{}{}
	s.live.mu.Unlock()
	return func() {
		s.live.mu.Lock()
		delete(s.live.m, l)
		s.live.mu.Unlock()
	}
}

// recheckLive trennt Verbindungen, deren Name gesperrt, entfernt oder umgestellt ist bzw. deren Besucher die Liste
// nicht mehr zulaesst. Gibt die Zahl der getrennten Verbindungen zurueck.
func (s *Server) recheckLive() int {
	rs := s.routes.Load()
	var cut []func()
	s.live.mu.Lock()
	for l := range s.live.m {
		re := rs.lookup(l.name)
		if re == nil || re.Mode != l.mode || re.Blocked != "" || (l.client.IsValid() && !re.allows(l.client)) {
			delete(s.live.m, l)
			cut = append(cut, l.cancel)
		}
	}
	s.live.mu.Unlock()
	for _, f := range cut {
		f()
	}
	return len(cut)
}

// liveCount fuer /health und Tests.
func (s *Server) liveCount() int {
	s.live.mu.Lock()
	defer s.live.mu.Unlock()
	return len(s.live.m)
}
