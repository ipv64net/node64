// Package dns64cluster verbindet DNS64 mit dem Cluster (internal/peer), ohne dass dns64 von peer abhaengt:
// Provider-Huelle mit den Typen des Clusters und Weiterleitung der Aenderungen.
package dns64cluster

import (
	"context"

	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet und ClusterApply kommen aus dns64.Module.
type provider struct{ *dns64.Module }

func (p provider) ClusterModule() peer.ModuleInfo { return Module() }

// Module: DNS64 mit seinen Bereichen (alle ohne Einstellung aus).
func Module() peer.ModuleInfo {
	mi := peer.ModuleInfo{ID: dns64.ClusterModuleID, TitleKey: dns64.ClusterTitleKey}
	for _, it := range dns64.ClusterItems() {
		mi.Items = append(mi.Items, peer.ItemInfo{ID: it.ID, TitleKey: it.TitleKey})
	}
	return mi
}

// Register meldet DNS64 beim Cluster an (vor peer.Run) und leitet seine Aenderungen dorthin.
func Register(pm *peer.Manager, m *dns64.Module) {
	pm.RegisterProvider(provider{m})
	m.SetCluster(func(ctx context.Context, item, id string, deleted bool) {
		pm.ClusterChange(ctx, dns64.ClusterModuleID, item, id, deleted)
	})
}
