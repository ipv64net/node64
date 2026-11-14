// Package ipamcluster verbindet IPAM64 mit dem Cluster (internal/peer), ohne dass ipam64 von peer abhaengt: Provider
// fuer die Bereiche ipam64/prefixes, ipam64/ranges und ipam64/addresses (Weg /peer/v2/sync).
package ipamcluster

import (
	"context"

	"github.com/ipv64net/node64/internal/ipam64"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet, ClusterApply und ClusterRunning kommen aus ipam64.Module.
type provider struct{ *ipam64.Module }

func (p provider) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: ipam64.ClusterModuleID, TitleKey: ipam64.ClusterTitleKey, Default: true, Items: []peer.ItemInfo{
		{ID: ipam64.ClusterItemPrefixes, TitleKey: "cluster.item.ipam64_prefixes", Default: true},
		{ID: ipam64.ClusterItemRanges, TitleKey: "cluster.item.ipam64_ranges", Default: true},
		{ID: ipam64.ClusterItemAddresses, TitleKey: "cluster.item.ipam64_addresses", HintKey: "cluster.ipam64_hint", Default: true},
	}}
}

// Register meldet IPAM64 beim Cluster an (vor peer.Run) und haengt das Modul an.
func Register(pm *peer.Manager, m *ipam64.Module) {
	pm.RegisterProvider(provider{m})
	m.SetCluster(ipam64.ClusterHooks{
		Change: func(ctx context.Context, item, id string, deleted bool) {
			pm.ClusterChange(ctx, ipam64.ClusterModuleID, item, id, deleted)
		},
	})
}
