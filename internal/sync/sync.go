// Package sync ist der Platzhalter fuer die spaetere Anbindung an ipv64.net.
//
// Im ersten Entwurf laeuft der Node nur standalone. Das Interface steht,
// damit Scheduler und Store spaeter ohne Umbau einen echten Client bekommen.
// Vorgesehen laut Konzept: ausgehende Dauerverbindung, Konfigurations-Sync
// mit Revisionen (Server fuehrend), Messergebnisse append-only mit
// Sequenznummern je Node, Outbox bei Verbindungsverlust.
package sync

import "context"

// State beschreibt den Verbindungszustand fuer die Anzeige im UI.
type State struct {
	Linked     bool
	Connected  bool
	AccountID  string
	LastSyncAt string
	Outbox     int
	LastError  string
}

// Client ist die spaetere Verbindung zu ipv64.net.
type Client interface {
	// State liefert den aktuellen Zustand.
	State() State
	// Start startet die Verbindung, Stop beendet sie.
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
}

// NoOp ist der Standalone-Client: nicht verknuepft, tut nichts.
type NoOp struct{}

func (NoOp) State() State                { return State{} }
func (NoOp) Start(context.Context) error { return nil }
func (NoOp) Stop(context.Context) error  { return nil }
