package peer

import (
	"context"
	"errors"
)

// Aussetzen von Mitgliedern (im Aufbau).

// Suspended: das Mitglied ist ausgesetzt, keine Kommunikation mit ihm.
func (x Member) Suspended() bool { return x.State == "suspended" }

// Resume nimmt ein ausgesetztes Mitglied wieder auf (prueft erneut, ob es passt).
func (m *Manager) Resume(ctx context.Context, nodeID string) error { return errors.New("not implemented") }
