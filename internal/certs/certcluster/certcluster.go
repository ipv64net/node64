// Package certcluster verbindet die Zertifikatsverwaltung mit dem Cluster (internal/peer), ohne dass certs von peer
// abhaengt: Provider-Huelle mit den Typen des Clusters und Weiterleitung der Aenderungen.
package certcluster

import (
	"context"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet und ClusterApply kommen aus certs.Manager.
type provider struct{ *certs.Manager }

func (p provider) ClusterModule() peer.ModuleInfo { return Module() }

// Module: das Modul mit seinen Bereichen (alle ohne Einstellung aus).
func Module() peer.ModuleInfo {
	mi := peer.ModuleInfo{ID: certs.ClusterModuleID, TitleKey: certs.ClusterTitleKey}
	for _, it := range certs.ClusterItems() {
		mi.Items = append(mi.Items, peer.ItemInfo{ID: it.ID, TitleKey: it.TitleKey})
	}
	return mi
}

// Register meldet die Zertifikatsverwaltung beim Cluster an (vor peer.Run) und leitet ihre Aenderungen dorthin.
// nodeID liefert die Kennung dieser Node (zustaendig fuer die Erneuerung).
func Register(pm *peer.Manager, cm *certs.Manager, nodeID func() string) {
	pm.RegisterProvider(provider{cm})
	cm.SetCluster(nodeID, func(ctx context.Context, item, uid string, deleted bool) {
		pm.ClusterChange(ctx, certs.ClusterModuleID, item, uid, deleted)
	})
}
