package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

// Neuer Schluessel (API-Key, MCP-Key) nach dem Anlegen: Weiterleitung auf die Seite (POST-Redirect-GET) statt
// direkter Antwort auf den POST - sonst schickt Neuladen das Formular erneut und legt den naechsten an (#44). Der
// Schluessel bleibt nur im Speicher, ist einmal abrufbar, hoechstens newKeyTTL lang und nur fuer denselben Benutzer;
// im Cookie steht nur eine zufaellige Kennung.

const (
	newKeyCookie = "node64_newkey"
	newKeyTTL    = 2 * time.Minute
)

type newKeyEntry struct {
	user  int64
	kind  string // "api" | "mcp"
	key   string
	until time.Time
}

type newKeyStore struct {
	mu sync.Mutex
	m  map[string]newKeyEntry
}

// keepNewKey merkt sich den eben angelegten Schluessel fuer die naechste Seite (kind trennt API- und MCP-Seite).
func (s *Server) keepNewKey(w http.ResponseWriter, r *http.Request, user int64, kind, key string) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return
	}
	id := hex.EncodeToString(b)
	now := time.Now()
	s.newKeys.mu.Lock()
	if s.newKeys.m == nil {
		s.newKeys.m = map[string]newKeyEntry{}
	}
	for k, e := range s.newKeys.m { // Abgelaufene weg
		if now.After(e.until) {
			delete(s.newKeys.m, k)
		}
	}
	s.newKeys.m[id] = newKeyEntry{user: user, kind: kind, key: key, until: now.Add(newKeyTTL)}
	s.newKeys.mu.Unlock()
	s.setCookie(w, r, newKeyCookie, id, int(newKeyTTL/time.Second))
}

// takeNewKey liefert den gemerkten Schluessel einmal ("" = keiner, abgelaufen, anderer Benutzer bzw. andere Seite).
func (s *Server) takeNewKey(w http.ResponseWriter, r *http.Request, user int64, kind string) string {
	c, err := r.Cookie(cookieName(r, newKeyCookie))
	if err != nil || c.Value == "" {
		return ""
	}
	s.newKeys.mu.Lock()
	e, ok := s.newKeys.m[c.Value]
	if ok && e.kind == kind {
		delete(s.newKeys.m, c.Value)
	}
	s.newKeys.mu.Unlock()
	if !ok || e.kind != kind {
		return ""
	}
	s.clearCookie(w, r, newKeyCookie)
	if e.user != user || time.Now().After(e.until) {
		return ""
	}
	return e.key
}
