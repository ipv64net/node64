package sonar

// Messen und Antworten (Vertrag docs/SONAR64-VERTRAG.md, Abschnitte UDP 6464 und Messung). GERUEST: Die Koerper
// fuellt der Teil „Messung“; der Kern nutzt nur Prober und Responder.

import (
	"context"
	"net/http"
	"time"
)

// HTTPDoer ist der HTTP-Client des Kerns (Tests ersetzen ihn).
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Prober misst ein Ziel. Grenzen (Pakete pro Sekunde, Tagesbudget) setzt der Runner davor durch; der Prober misst
// nur, was er bekommt, prueft aber selbst: keine privaten/reservierten Adressen, Count 1..5, MaxTTL 1..30.
type Prober interface {
	// Ping misst per ICMP oder UDP 6464 (t.Method) und liefert die Zusammenfassung (Round/Target/At setzt der Prober).
	Ping(ctx context.Context, t Target, round time.Time) Result
	// Trace macht eine Paris-Traceroute (gleicher Flow je Hop) und liefert Hops.
	Trace(ctx context.Context, t Target, round time.Time) Result
	// ICMPAllowed sagt, ob ICMP-Echo moeglich ist (Raw-Socket mit cap_net_raw oder Linux-Ping-Socket).
	ICMPAllowed() bool
}

// ProbeConfig stellt den Prober ein.
type ProbeConfig struct {
	NodeID  string        // fuer die Kurzform in UDP-Proben (8 Hex = erste 4 Byte von SHA-256(NodeID))
	Timeout time.Duration // je Paket, Standard 1 s
	Gap     time.Duration // Abstand zwischen Paketen einer Messung, Standard 500 ms (= 2 Pakete/s)
}

// NewProber liefert den echten Prober.
func NewProber(cfg ProbeConfig) Prober { return nil }

// Responder beantwortet Proben auf UDP 6464 (nur Format „S64?“, Antwort nie groesser als die Anfrage, Grenzen je
// Quelle und gesamt, siehe Vertrag).
type Responder struct{}

// NewResponder oeffnet UDP 6464 (IPv4 und IPv6). addr leer = ":6464".
func NewResponder(addr, nodeID string) (*Responder, error) { return nil, ErrNotImplemented }

// Run beantwortet bis ctx endet.
func (r *Responder) Run(ctx context.Context) error { return ErrNotImplemented }

// Drain liefert die seit dem letzten Aufruf beantworteten Proben (zusammengefasst je Quelle und Familie).
func (r *Responder) Drain() []Inbound { return nil }
