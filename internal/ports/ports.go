// Package ports fuehrt die Ports, die Teile von Node64 belegen (Oberflaeche, gemeinsamer Eingang, DNS64,
// spaeter Streams), und prueft vor dem Oeffnen auf Ueberschneidung. Ein Port ist je Adresse und Protokoll nur
// einmal zu oeffnen; ohne Pruefung scheitert der zweite Teil sonst erst beim Start mit einer knappen Meldung.
package ports

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
)

// Proto ist das Transportprotokoll.
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// Claim ist ein belegter (oder eingestellter) Port.
type Claim struct {
	Owner   string `json:"owner"`          // web, edge, dns64, cdn64 …
	Purpose string `json:"purpose"`        // z. B. "HTTPS", "DoH", "DNS"
	Proto   Proto  `json:"proto"`          // tcp oder udp
	Port    int    `json:"port"`           // 1–65535
	Bind    string `json:"bind,omitempty"` // Adresse, "" = alle
	Active  bool   `json:"active"`         // derzeit geoeffnet bzw. eingeschaltet
}

func (c Claim) String() string {
	s := strconv.Itoa(c.Port) + "/" + string(c.Proto)
	if c.Bind != "" && !allAddrs(c.Bind) {
		s = net.JoinHostPort(c.Bind, strconv.Itoa(c.Port)) + "/" + string(c.Proto)
	}
	return s
}

// Provider liefert die Ports eines Teils (aus seiner aktuellen Einstellung).
type Provider func(ctx context.Context) []Claim

// Registry sammelt die Ports aller Teile.
type Registry struct {
	mu        sync.Mutex
	owners    []string
	providers map[string]Provider
}

func New() *Registry { return &Registry{providers: map[string]Provider{}} }

// Provide meldet die Ports eines Teils an (ersetzt eine fruehere Anmeldung).
func (r *Registry) Provide(owner string, p Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.providers[owner]; !ok {
		r.owners = append(r.owners, owner)
	}
	r.providers[owner] = p
}

// All liefert alle Ports, sortiert nach Nummer und Protokoll.
func (r *Registry) All(ctx context.Context) []Claim { return r.collect(ctx, "") }

// collect fragt alle Teile ausser skip (der eigene Teil bei Check: er kann dabei gesperrt sein).
func (r *Registry) collect(ctx context.Context, skip string) []Claim {
	r.mu.Lock()
	var owners []string
	var providers []Provider
	for _, o := range r.owners {
		if skip != "" && o == skip {
			continue
		}
		owners = append(owners, o)
		providers = append(providers, r.providers[o])
	}
	r.mu.Unlock()
	var out []Claim
	for i, p := range providers {
		for _, c := range p(ctx) {
			if c.Owner == "" {
				c.Owner = owners[i]
			}
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out
}

// ConflictError: ein gewuenschter Port ist schon von einem anderen Teil belegt.
type ConflictError struct {
	Want, With Claim
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("port %s is already used by %s (%s)", e.Want, e.With.Owner, e.With.Purpose)
}

// Check prueft gewuenschte Ports eines Teils gegen die aktiven Ports der anderen Teile (der eigene Stand zaehlt
// nicht, er wird ja ersetzt, und wird auch nicht abgefragt). Liefert den ersten Konflikt als *ConflictError.
func (r *Registry) Check(ctx context.Context, owner string, want []Claim) error {
	all := r.collect(ctx, owner)
	for _, w := range want {
		for _, c := range all {
			if c.Owner != owner && c.Active && Overlap(w, c) {
				return &ConflictError{Want: w, With: c}
			}
		}
	}
	return nil
}

// Entry ist ein Port in der Uebersicht, mit den Teilen, mit denen er sich ueberschneidet.
type Entry struct {
	Claim
	Conflicts []string `json:"conflicts,omitempty"` // "dns64 (DoH)" …
}

// Overview: alle Ports mit Ueberschneidungen zwischen verschiedenen Teilen (beide aktiv bzw. einer aktiv und
// einer eingestellt, der dann nicht starten kann).
func (r *Registry) Overview(ctx context.Context) []Entry {
	all := r.All(ctx)
	out := make([]Entry, len(all))
	for i, c := range all {
		out[i].Claim = c
		for j, o := range all {
			if i != j && o.Owner != c.Owner && (o.Active || c.Active) && Overlap(c, o) {
				out[i].Conflicts = append(out[i].Conflicts, o.Owner+" ("+o.Purpose+")")
			}
		}
	}
	return out
}

// Overlap: gleiches Protokoll und gleicher Port auf ueberschneidenden Adressen.
func Overlap(a, b Claim) bool {
	if a.Proto != b.Proto || a.Port != b.Port {
		return false
	}
	return allAddrs(a.Bind) || allAddrs(b.Bind) || a.Bind == b.Bind
}

func allAddrs(bind string) bool {
	return bind == "" || bind == "0.0.0.0" || bind == "::" || bind == "[::]"
}

// Probe versucht, den Port kurz zu oeffnen (nur fuer Ports, die Node64 selbst gerade nicht offen hat): so
// faellt auf, wenn ein anderes Programm auf dem Host ihn belegt.
func Probe(p Proto, bind string, port int) error {
	addr := net.JoinHostPort(bind, strconv.Itoa(port))
	switch p {
	case TCP:
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		return ln.Close()
	case UDP:
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	return fmt.Errorf("unknown protocol %q", p)
}
