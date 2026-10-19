package cdn64

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Ueberwachung durch Healthchecks: Die Liste der Hosts zeigt, ob ein Check genau dieses Ziel prueft (Host und Port;
// angelegt ueber "Healthcheck fuer dieses Ziel" oder von Hand). Die Checks liefert das Hauptprogramm aus dem
// Modul Healthchecks (SetCheckFinder); CDN64 vergleicht nur die Ziele.

// CheckRef ist ein Healthcheck, wie ihn das Hauptprogramm liefert.
type CheckRef struct {
	Token, Name, Type, Target string
	Params                    json.RawMessage
	State                     string // up, down, … (leer = noch nicht gemessen)
	Paused                    bool
	Local                     bool // misst diese Node (nicht nur die ipv64-Server bzw. andere Nodes)
	LastCheck                 time.Time
}

// CheckFinder liefert alle Healthchecks (nil = Modul aus).
type CheckFinder func(ctx context.Context) []CheckRef

// SetCheckFinder haengt die Anzeige "von Healthchecks ueberwacht" an.
func (m *Module) SetCheckFinder(f CheckFinder) { m.findChecks = f }

// Watch ist ein Healthcheck auf das Ziel eines Hosts.
type Watch struct {
	Token     string    `json:"token"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	State     string    `json:"state"`
	Paused    bool      `json:"paused"`
	Local     bool      `json:"local"`
	HostOnly  bool      `json:"host_only,omitempty"` // Ping: nur der Host, nicht der Port
	LastCheck time.Time `json:"last_check,omitzero"`
}

// normHost: Kleinschreibung, ohne Klammern und Punkt am Ende, IPs in Grundform.
func normHost(h string) string {
	h = strings.TrimSuffix(strings.ToLower(strings.Trim(strings.TrimSpace(h), "[]")), ".")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

// checkEndpoint: Host und Port, die ein Check prueft (Port 0 = nur Host, z. B. Ping).
func checkEndpoint(c CheckRef) (string, int, bool) {
	switch c.Type {
	case "http", "keyword", "json":
		u, err := url.Parse(strings.TrimSpace(c.Target))
		if err != nil || u.Hostname() == "" {
			return "", 0, false
		}
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = 80
			if u.Scheme == "https" {
				port = 443
			}
		}
		return normHost(u.Hostname()), port, true
	case "tcp", "port", "cert":
		var p struct {
			Port int `json:"port"`
		}
		_ = json.Unmarshal(c.Params, &p)
		host := c.Target
		if h, ps, err := net.SplitHostPort(c.Target); err == nil {
			host = h
			if n, err := strconv.Atoi(ps); err == nil && p.Port == 0 {
				p.Port = n
			}
		}
		if p.Port == 0 && c.Type == "cert" {
			p.Port = 443
		}
		if p.Port == 0 {
			return "", 0, false
		}
		return normHost(host), p.Port, true
	case "icmp":
		return normHost(c.Target), 0, c.Target != ""
	}
	return "", 0, false
}

// watchIndex ordnet die Checks nach Ziel; einmal je Seite gebaut.
type watchIndex map[string][]Watch

func (m *Module) watchIndex(ctx context.Context) watchIndex {
	if m.findChecks == nil {
		return nil
	}
	idx := watchIndex{}
	for _, c := range m.findChecks(ctx) {
		host, port, ok := checkEndpoint(c)
		if !ok {
			continue
		}
		w := Watch{Token: c.Token, Name: c.Name, Type: c.Type, State: c.State, Paused: c.Paused, Local: c.Local, HostOnly: port == 0, LastCheck: c.LastCheck}
		key := net.JoinHostPort(host, strconv.Itoa(port))
		idx[key] = append(idx[key], w)
	}
	return idx
}

// of: Checks auf host:port (genau) und Pings auf host.
func (idx watchIndex) of(host string, port int) []Watch {
	if idx == nil || host == "" {
		return nil
	}
	h := normHost(host)
	out := append([]Watch{}, idx[net.JoinHostPort(h, strconv.Itoa(port))]...)
	return append(out, idx[net.JoinHostPort(h, "0")]...)
}
