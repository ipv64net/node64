package web

import (
	"net"
	"net/http"
	"net/netip"
)

// LoginWatcher bekommt jeden Fehlversuch an der Anmeldung (Passwort, TOTP, Passkey, SSO ohne Konto, ungueltiger
// API- bzw. MCP-Key) – nur Quell-IP, lokaler Port und TLS, nie Benutzername oder Passwort. Honeypot64 wertet das
// aus (Regel node64/login@1); verbunden in cmd/node64/main.go. Muss sofort zurueckkehren.
type LoginWatcher interface {
	LoginFailed(src netip.Addr, port int, tls bool)
}

// SetLoginWatcher haengt den Beobachter an (nil = keiner).
func (s *Server) SetLoginWatcher(w LoginWatcher) {
	if w == nil {
		s.loginWatch.Store(nil)
		return
	}
	s.loginWatch.Store(&w)
}

// loginFailed meldet einen Fehlversuch an den Beobachter. ip ist die Adresse wie im Audit (clientIP).
func (s *Server) loginFailed(r *http.Request, ip string) {
	p := s.loginWatch.Load()
	if p == nil || *p == nil {
		return
	}
	src, err := netip.ParseAddr(ip)
	if err != nil {
		return
	}
	port := 0
	if a, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && a != nil {
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			port = int(ap.Port())
		}
	}
	(*p).LoginFailed(src, port, r.TLS != nil)
}
