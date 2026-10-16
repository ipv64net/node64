package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Forward-Auth: Ein vorgeschalteter Reverse-Proxy mit Authelia, Authentik o. ae. meldet den angemeldeten Benutzer
// im Kopf Remote-User. Das gilt nur fuer Anfragen, deren Verbindung (RemoteAddr, nie X-Forwarded-For) aus einer
// eingetragenen Proxy-Adresse kommt, und nur fuer lokale Benutzer mit genau diesem Namen. Abgeschaltet als
// Voreinstellung. Geprueft wird je Anfrage: wer sich beim Proxy abmeldet, ist auch hier abgemeldet.

const (
	setFwdEnabled = "auth.forward.enabled"
	setFwdTrusted = "auth.forward.trusted" // Adressen bzw. Netze des Proxys, durch Leerzeichen/Komma getrennt
	setFwdHeader  = "auth.forward.header"
	fwdDefaultHdr = "Remote-User"
)

type fwdSettings struct {
	Enabled bool
	Trusted []*net.IPNet
	Raw     string // wie eingegeben (Anzeige)
	Header  string
}

type fwdCache struct {
	sync.RWMutex
	loaded bool
	s      fwdSettings
	seen   map[string]time.Time // Benutzer -> letzter Audit-Eintrag (einmal je 12 h)
}

func parseTrusted(raw string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, f := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' }) {
		if !strings.Contains(f, "/") {
			if ip := net.ParseIP(f); ip != nil {
				if ip.To4() != nil {
					f += "/32"
				} else {
					f += "/128"
				}
			}
		}
		_, n, err := net.ParseCIDR(f)
		if err != nil {
			return nil, errFwdAddress
		}
		if ones, _ := n.Mask.Size(); ones == 0 {
			return nil, errFwdAll // 0.0.0.0/0 oder ::/0 hiesse: jeder darf sich als jeder ausgeben
		}
		out = append(out, n)
	}
	return out, nil
}

var (
	errFwdAddress = errors.New("invalid address or network")
	errFwdAll     = errors.New("trusting all addresses is not allowed")
	errFwdNone    = errors.New("at least one proxy address is required")
)

func (s *Server) fwdSettings(ctx context.Context) fwdSettings {
	s.fwd.RLock()
	if s.fwd.loaded {
		v := s.fwd.s
		s.fwd.RUnlock()
		return v
	}
	s.fwd.RUnlock()
	raw := s.Store.SettingOr(ctx, setFwdTrusted, "")
	nets, _ := parseTrusted(raw)
	v := fwdSettings{Enabled: s.Store.SettingOr(ctx, setFwdEnabled, "") == "1" && len(nets) > 0, Trusted: nets, Raw: raw,
		Header: s.Store.SettingOr(ctx, setFwdHeader, fwdDefaultHdr)}
	s.fwd.Lock()
	s.fwd.s, s.fwd.loaded = v, true
	s.fwd.Unlock()
	return v
}

// fwdSave prueft und speichert die Einrichtung.
func (s *Server) fwdSave(ctx context.Context, enabled bool, trusted, header string) error {
	nets, err := parseTrusted(trusted)
	if err != nil {
		return err
	}
	if enabled && len(nets) == 0 {
		return errFwdNone
	}
	header = strings.TrimSpace(header)
	if header == "" {
		header = fwdDefaultHdr
	}
	if len(header) > 64 || strings.ContainsAny(header, " :\r\n") {
		return errFwdAddress
	}
	on := ""
	if enabled {
		on = "1"
	}
	for k, v := range map[string]string{setFwdEnabled: on, setFwdTrusted: strings.TrimSpace(trusted), setFwdHeader: header} {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	s.fwd.Lock()
	s.fwd.loaded = false
	s.fwd.Unlock()
	return nil
}

// remoteIP: Adresse der Verbindung selbst (fuer Forward-Auth bewusst ohne X-Forwarded-For).
func remoteIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

func (f fwdSettings) trusts(ip net.IP) bool {
	for _, n := range f.Trusted {
		if ip != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardUser liefert den Benutzer aus dem Kopf des Proxys (nil = keine Forward-Auth fuer diese Anfrage).
func (s *Server) forwardUser(r *http.Request) *store.User {
	f := s.fwdSettings(r.Context())
	if !f.Enabled {
		return nil
	}
	name := strings.TrimSpace(r.Header.Get(f.Header))
	if name == "" || len(name) > 64 || !f.trusts(remoteIP(r)) {
		return nil
	}
	u, err := s.Store.UserByName(r.Context(), name)
	if err != nil || u == nil {
		return nil
	}
	s.fwd.Lock()
	if s.fwd.seen == nil {
		s.fwd.seen = map[string]time.Time{}
	}
	first := time.Since(s.fwd.seen[u.Username]) > 12*time.Hour
	if first {
		s.fwd.seen[u.Username] = time.Now()
	}
	s.fwd.Unlock()
	if first {
		_ = s.Store.TouchUserLogin(r.Context(), u.ID)
		s.auditEntry(r.Context(), store.AuditEntry{Actor: u.Username, Action: "login", Details: "forward-auth " + f.Header, IP: remoteIP(r).String()})
		s.log.Info("login", "user", u.Username, "via", "forward-auth", "ip", remoteIP(r).String())
	}
	return u
}
