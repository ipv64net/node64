// Package hccluster verbindet die Proxmox-VE- und Docker-Ueberwachung und die Statusseiten der Healthchecks mit dem
// Cluster (internal/peer), ohne dass healthchecks von peer abhaengt: Provider fuer die Bereiche healthchecks/proxmox,
// healthchecks/docker und healthchecks/statuspages (Weg /peer/v2/sync) und die Mitglieder, die solche Checks
// mitmessen koennen.
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
		{ID: healthchecks.ClusterItemProxmox, TitleKey: "cluster.item.proxmox"},
		{ID: healthchecks.ClusterItemDocker, TitleKey: "cluster.item.docker"},
		{ID: healthchecks.ClusterItemStatusPages, TitleKey: "cluster.item.statuspages"},
	}}
}

// Register meldet die Bereiche beim Cluster an (vor peer.Run) und haengt das Modul an.
func Register(pm *peer.Manager, m *healthchecks.Module) {
	pm.RegisterProvider(provider{m})
	m.SetCluster(healthchecks.ClusterHooks{
		Change: func(ctx context.Context, item, id string, deleted bool) {
			pm.ClusterChange(ctx, "healthchecks", item, id, deleted)
		},
		Members: func(ctx context.Context, item string) []healthchecks.Peer {
			list := pm.HCItemMembers(ctx, item)
			out := make([]healthchecks.Peer, 0, len(list))
			for _, x := range list {
				out = append(out, healthchecks.Peer{ID: x.NodeID, Name: x.Name, Location: "LAN", Online: x.Online()})
			}
			return out
		},
	})
}
