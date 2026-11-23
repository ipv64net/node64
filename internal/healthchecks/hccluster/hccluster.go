// Package hccluster verbindet die Statusseiten der Healthchecks mit dem Cluster (internal/peer), ohne dass
// healthchecks von peer abhaengt: Provider fuer den Bereich healthchecks/statuspages (Weg /peer/v2/sync). Die frueheren
// Bereiche healthchecks/proxmox und healthchecks/docker gibt es nicht mehr (nach Monitor64 umgezogen). Dazu die Anfrage
// "Jetzt pruefen" an die messende Node (ohne ipv64, #271).
package hccluster

import (
	"context"

	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet und ClusterApply kommen aus healthchecks.Module.
type provider struct{ *healthchecks.Module }

func (p provider) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: "healthchecks", TitleKey: "cluster.mod.healthchecks", Items: []peer.ItemInfo{
		{ID: healthchecks.ClusterItemStatusPages, TitleKey: "cluster.item.statuspages"},
	}}
}

// Register meldet den Bereich beim Cluster an (vor peer.Run) und haengt das Modul an.
func Register(pm *peer.Manager, m *healthchecks.Module) {
	pm.RegisterProvider(provider{m})
	pm.RegisterCall("healthchecks", healthchecks.ClusterCallRun, func(ctx context.Context, _ string, body []byte) (any, error) {
		if err := m.HandleClusterRun(ctx, body); err != nil {
			return nil, err
		}
		return map[string]bool{"ok": true}, nil
	})
	m.SetCluster(healthchecks.ClusterHooks{
		Change: func(ctx context.Context, item, id string, deleted bool) {
			pm.ClusterChange(ctx, "healthchecks", item, id, deleted)
		},
		RunNow: func(ctx context.Context, node, token string) error {
			return pm.Call(ctx, node, "healthchecks", healthchecks.ClusterCallRun, map[string]string{"token": token}, nil)
		},
	})
}
