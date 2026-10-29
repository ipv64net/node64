// Package nodecluster verbindet nodecfg (API-Key und allgemeine Einstellungen der Node) mit dem Cluster
// (internal/peer), ohne dass nodecfg von peer abhaengt: Provider fuer das Modul "node" (Weg /peer/v2/sync).
package nodecluster

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ipv64net/node64/internal/nodecfg"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet und ClusterApply kommen aus nodecfg.Cluster.
type provider struct{ *nodecfg.Cluster }

func (p provider) ClusterModule() peer.ModuleInfo { return Module() }

// ClusterApply reicht Zeitpunkt der Aenderung und Beginn der Verbindung zum liefernden Mitglied an nodecfg weiter.
func (p provider) ClusterApply(ctx context.Context, item, id string, data json.RawMessage, deleted bool) error {
	_, at, _ := peer.ClusterOrigin(ctx)
	since, _ := peer.MemberSince(ctx)
	return p.Cluster.ClusterApply(nodecfg.WithApplyInfo(ctx, at, since), item, id, data, deleted)
}

// Module: das Modul mit seinen Bereichen (alle ohne Einstellung aus).
func Module() peer.ModuleInfo {
	mi := peer.ModuleInfo{ID: nodecfg.ModuleID, TitleKey: nodecfg.TitleKey}
	for _, it := range nodecfg.Items() {
		mi.Items = append(mi.Items, peer.ItemInfo{ID: it.ID, TitleKey: it.TitleKey, HintKey: it.HintKey})
	}
	return mi
}

// Register meldet das Modul beim Cluster an (vor peer.Run) und leitet seine Aenderungen dorthin. nodeID liefert die
// Kennung dieser Node (Urheberin der beim Start erkannten Aenderungen).
func Register(pm *peer.Manager, c *nodecfg.Cluster, nodeID func() string) {
	pm.RegisterProvider(provider{c})
	c.SetCluster(func(ctx context.Context, item, id string, deleted bool, at time.Time) {
		if !at.IsZero() {
			ctx = peer.WithClusterOrigin(ctx, nodeID(), at)
		}
		pm.ClusterChange(ctx, nodecfg.ModuleID, item, id, deleted)
	}, func(ctx context.Context) string { // Name der Urheberin fuer das Audit-Log
		id, _, ok := peer.ClusterOrigin(ctx)
		if !ok {
			return ""
		}
		list, _ := pm.Members(ctx)
		for _, x := range list {
			if x.NodeID == id {
				return x.Name
			}
		}
		return id
	})
}
