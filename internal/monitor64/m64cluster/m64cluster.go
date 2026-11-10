// Package m64cluster verbindet Monitor64 mit dem Cluster (internal/peer), ohne dass monitor64 von peer abhaengt:
// Provider fuer die Bereiche monitor64/config und monitor64/status (Weg /peer/v2/sync), die Mitglieder fuer die
// zustaendige Node je Host und die Anfragen zwischen den Nodes (Verlauf live, Anstoss, Erreichbarkeit).
package m64cluster

import (
	"context"
	"encoding/json"

	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet, ClusterApply, ClusterRunning und ClusterJoined kommen aus monitor64.Module.
type provider struct{ *monitor64.Module }

func (p provider) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: monitor64.ClusterModuleID, TitleKey: monitor64.ClusterTitleKey, Items: []peer.ItemInfo{
		{ID: monitor64.ClusterItemConfig, TitleKey: "cluster.item.monitor64_config", HintKey: "cluster.monitor64_hint", Default: true},
		{ID: monitor64.ClusterItemStatus, TitleKey: "cluster.item.monitor64_status", Default: true},
	}}
}

// Register meldet Monitor64 beim Cluster an (vor peer.Run) und haengt das Modul an. nodeID liefert die Kennung dieser
// Node.
func Register(pm *peer.Manager, m *monitor64.Module, nodeID func() string) {
	pm.RegisterProvider(provider{m})
	monitor64.SetClusterOrigin(peer.ClusterOrigin)
	for _, name := range monitor64.ClusterCalls {
		pm.RegisterCall(monitor64.ClusterModuleID, name, func(ctx context.Context, from string, body []byte) (any, error) {
			return m.HandleClusterCall(ctx, from, name, json.RawMessage(body))
		})
	}
	m.SetCluster(monitor64.ClusterHooks{
		Change: func(ctx context.Context, item, id string, deleted bool) error {
			return pm.ClusterChangeErr(ctx, monitor64.ClusterModuleID, item, id, deleted)
		},
		Members: members(pm, m), // ausgesetzte bzw. mit Monitor64/Bereich aus zaehlen als nicht erreichbar
		Self:    nodeID,
		Call: func(ctx context.Context, node, name string, in, out any) error {
			return pm.Call(ctx, node, monitor64.ClusterModuleID, name, in, out)
		},
	})
}
