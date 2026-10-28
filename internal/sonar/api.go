package sonar

// Oeffentliche Go-Schnittstelle des Kerns (Vertrag docs/SONAR64-VERTRAG.md, Abschnitt Go). cmd/sonar64 und das
// Node64-Modul internal/sonar64 nutzen nur, was hier steht. GERUEST: Die Koerper fuellt der Teil „Kern“.

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrNotImplemented markiert Teile des Geruests, die noch fehlen.
var ErrNotImplemented = errors.New("sonar: not implemented")

// Config ist die Einstellung eines Knotens.
type Config struct {
	APIBase    string       // leer = https://ipv64.net/api/v2 (nur Tests aendern das)
	Token      string       // Sonar-Token (s64_… oder Anker s64a_…)
	DataDir    string       // Ablage fuer Schluessel, Node-ID, Seq, Puffer (ein paar KB); leer = nur im Speicher (Tests)
	Mode       string       // module | headless | anchor
	Version    string       // Programmversion (Health, Register)
	Measured   bool         // UDP 6464 beantworten und gemessen werden
	Budget     string       // sparsam | normal | grosszuegig (lokale Obergrenze, Abschnitt Grenzen)
	Quiet      [2]int       // Ruhezeit Stunden [von, bis) in lokaler Zeit; {0,0} = keine
	Log        *slog.Logger // nil = slog.Default()
	Prober     Prober       // nil = NewProber(ProbeConfig{})
	PlanKeys   []string     // nil = PlanKeys aus keys.go (Tests setzen eigene)
	HTTPClient HTTPDoer     // nil = eigener Client mit Timeout
}

// Status ist der Zustand fuer Oberflaeche, Mini-Status und Log.
type Status struct {
	NodeID      string    `json:"node_id"`
	Registered  bool      `json:"registered"`
	Mode        string    `json:"mode"`
	Measured    bool      `json:"measured"`
	Budget      string    `json:"budget"`
	Responder   bool      `json:"responder"` // UDP 6464 offen
	PlanIssued  time.Time `json:"plan_issued,omitzero"`
	PlanExpires time.Time `json:"plan_expires,omitzero"`
	AnchorsOnly bool      `json:"anchors_only"` // kein gueltiger Plan, nur Anker
	Paused      string    `json:"paused,omitempty"`
	SentToday   int       `json:"sent_today"`
	LastReport  time.Time `json:"last_report,omitzero"`
	Buffered    int       `json:"buffered"` // noch nicht gemeldete Ergebnisse
	LastError   string    `json:"last_error,omitempty"`
}

// Runner fuehrt einen Knoten aus.
type Runner struct {
	cfg Config
}

// New prueft die Einstellung und laedt bzw. erzeugt Schluessel und Node-ID im DataDir.
func New(cfg Config) (*Runner, error) { return &Runner{cfg: cfg}, ErrNotImplemented }

// Run laeuft bis ctx endet: anmelden (Register, einmal), Plan holen (alle 15 min, ETag), Runden messen, alle 5 min
// melden, Antworter auf UDP 6464 (wenn Measured).
func (r *Runner) Run(ctx context.Context) error { return ErrNotImplemented }

// Status liefert den aktuellen Zustand.
func (r *Runner) Status() Status { return Status{} }

// Recent liefert die letzten n eigenen Messungen (neueste zuerst) und die letzten n auf UDP 6464 beantworteten Proben.
// Ziel-Adressen sind darin nicht enthalten (nur Target-ID).
func (r *Runner) Recent(n int) ([]Result, []Inbound) { return nil, nil }

// Me holt den eigenen Knoten von ipv64.
func (r *Runner) Me(ctx context.Context) (*Me, error) { return nil, ErrNotImplemented }

// UpdateMe setzt Name, Standort, Anschlussart, Geraet, Measured, Budget (PUT /sonar/me) und uebernimmt Measured
// und Budget sofort lokal.
func (r *Runner) UpdateMe(ctx context.Context, m Me) (*Me, error) { return nil, ErrNotImplemented }

// Inbound holt, wer mich seit since gemessen hat (GET /sonar/inbound, aus den Ergebnissen bei ipv64).
func (r *Runner) Inbound(ctx context.Context, since time.Time) ([]InboundRow, error) {
	return nil, ErrNotImplemented
}

// CreateToken legt mit dem API-Key des Accounts ein Sonar-Token an (POST /sonar/tokens). Node64 nutzt das beim Opt-in.
func CreateToken(ctx context.Context, apiBase, apiKey, name string) (string, error) {
	return "", ErrNotImplemented
}
