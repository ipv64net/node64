// Package ipamcluster verbindet IPAM64 mit dem Cluster (internal/peer), ohne dass ipam64 von peer abhaengt: Provider
// fuer die Bereiche ipam64/prefixes, ipam64/ranges und ipam64/addresses (Weg /peer/v2/sync).
package ipamcluster

import (
	"context"

	"github.com/ipv64net/node64/internal/dns64"
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
		ForeignDNS64: func(ctx context.Context) bool { return foreignDNS64(ctx, pm) },
		Stale: func(ctx context.Context, item, id string) bool {
			from, _, ok := peer.ClusterOrigin(ctx)
			return ok && from != "" && pm.EntryOrigin(ipam64.ClusterModuleID, item, id) == from
		},
	})
}

// foreignDNS64: eine Node gleicht Eintraege, Reservierungen oder Netze (Ausnahmen) von DNS64 mit dieser ab, aber nicht
// die Adressen von IPAM64 - ihre gekennzeichneten Eintraege kommen hier an, ohne dass IPAM64 die Adressen kennt.
func foreignDNS64(ctx context.Context, pm *peer.Manager) bool {
	ipam := map[string]bool{}
	for _, x := range pm.AreaMembers(ctx, ipam64.ClusterModuleID, ipam64.ClusterItemAddresses) {
		ipam[x.NodeID] = true
	}
	for _, item := range []string{dns64.ItemRecords, dns64.ItemDHCPRes, dns64.ItemDHCPScopes} {
		for _, x := range pm.AreaMembers(ctx, dns64.ClusterModuleID, item) {
			if !ipam[x.NodeID] {
				return true
			}
		}
	}
	return false
}
