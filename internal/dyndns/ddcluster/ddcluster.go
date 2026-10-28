// Package ddcluster verbindet DynDNS mit dem Cluster (internal/peer), ohne dass dyndns von peer abhaengt: Provider
// fuer den Bereich dyndns/config (Weg /peer/v2/sync) und die Mitglieder fuer die Wahl der zustaendigen Node.
package ddcluster

import (
	"context"

	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet, ClusterApply und ClusterRunning kommen aus dyndns.Module.
type provider struct{ *dyndns.Module }

func (p provider) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: dyndns.ClusterModuleID, TitleKey: dyndns.ClusterTitleKey, Items: []peer.ItemInfo{
		{ID: dyndns.ClusterItemConfig, TitleKey: "cluster.item.dyndns_config", HintKey: "cluster.dyndns_hint"},
	}}
}

// Register meldet DynDNS beim Cluster an (vor peer.Run) und haengt das Modul an. nodeID liefert die Kennung dieser
// Node.
func Register(pm *peer.Manager, m *dyndns.Module, nodeID func() string) {
	pm.RegisterProvider(provider{m})
	m.SetCluster(dyndns.ClusterHooks{
		Change: func(ctx context.Context, id string, deleted bool) {
			pm.ClusterChange(ctx, dyndns.ClusterModuleID, dyndns.ClusterItemConfig, id, deleted)
		},
		Members: func(ctx context.Context) []dyndns.ClusterPeer {
			list := pm.AreaMembers(ctx, dyndns.ClusterModuleID, dyndns.ClusterItemConfig)
			out := make([]dyndns.ClusterPeer, 0, len(list))
			for _, x := range list {
				out = append(out, dyndns.ClusterPeer{ID: x.NodeID, Name: x.Name, Online: x.Online()})
			}
			return out
		},
		Self: nodeID,
	})
}
