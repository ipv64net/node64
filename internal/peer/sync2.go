package peer

import "context"

// Allgemeiner Abgleich der Module ueber /peer/v2/sync (im Aufbau).

// ClusterChange meldet eine Aenderung eines Eintrags (Hook des Moduls, auch bei Uebernahmen von anderen Nodes:
// die Herkunft steht dann in ctx, siehe ClusterOrigin).
func (m *Manager) ClusterChange(ctx context.Context, module, item, id string, deleted bool) {}
