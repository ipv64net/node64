package m64agent

import (
	"sync"
	"sync/atomic"
	"time"
)

// Status ist der Stand des laufenden Agents fuer die Anzeige am Host (Windows: Symbol im Infobereich). Enthaelt
// nichts Geheimes: Version, Startzeit, Zeit der letzten Abfrage und die Version, die die Node als verfuegbar gemeldet
// hat ("info latest=<version>").
type Status struct {
	Version     string `json:"version"`
	PID         int    `json:"pid,omitempty"`
	Started     int64  `json:"started"`                // Unix-Sekunden
	LastRequest int64  `json:"last_request,omitempty"` // letzte Abfrage einer Node (collect/info), Unix-Sekunden
	Latest      string `json:"latest,omitempty"`       // von der Node gemeldete verfuegbare Version
	LatestAt    int64  `json:"latest_at,omitempty"`    // wann gemeldet, Unix-Sekunden
}

// statusState haelt den Stand im Server.
type statusState struct {
	started time.Time
	lastReq atomic.Int64
	mu      sync.Mutex
	latest  string
	at      int64
}

// Status liefert den aktuellen Stand.
func (s *Server) Status() Status {
	st := Status{Version: s.cfg.Version, Started: s.status.started.Unix(), LastRequest: s.status.lastReq.Load()}
	s.status.mu.Lock()
	st.Latest, st.LatestAt = s.status.latest, s.status.at
	s.status.mu.Unlock()
	return st
}

// SetLatest merkt die von einer Node gemeldete verfuegbare Version (auch zum Vorbelegen nach einem Neustart).
func (s *Server) SetLatest(version string, at time.Time) {
	if !validLatest(version) {
		return
	}
	s.status.mu.Lock()
	s.status.latest, s.status.at = version, at.Unix()
	s.status.mu.Unlock()
}

// noteRequest merkt die Zeit einer beantworteten Abfrage.
func (s *Server) noteRequest() { s.status.lastReq.Store(time.Now().Unix()) }

// validLatest prueft eine gemeldete Version: kurz, nur Ziffern, Buchstaben, Punkt, Minus und Plus.
func validLatest(v string) bool {
	if v == "" || len(v) > 40 {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && c != '.' && c != '-' && c != '+' {
			return false
		}
	}
	return true
}
