// Package nfcluster verbindet die Benachrichtigungskanaele mit dem Cluster (internal/peer), ohne dass notify von peer
// abhaengt: Provider fuer den Bereich notifications/channels (Weg /peer/v2/sync). Die Zuordnung Check -> Kanal geht mit
// den Checks (healthchecks/peersync.go, Kennungen der Kanaele).
package nfcluster

import (
	"context"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
)

// provider: ClusterIDs, ClusterGet und ClusterApply kommen aus notify.Store.
type provider struct{ *notify.Store }

func (p provider) ClusterModule() peer.ModuleInfo {
	return peer.ModuleInfo{ID: "notifications", TitleKey: "cluster.mod.notifications", Items: []peer.ItemInfo{
		{ID: notify.ClusterItemChannels, TitleKey: "cluster.item.notify_channels", HintKey: "cluster.channels_hint"},
	}}
}

// Register meldet den Bereich beim Cluster an (vor peer.Run) und haengt die Kanaele an.
func Register(pm *peer.Manager, st *notify.Store) {
	pm.RegisterProvider(provider{st})
	st.SetCluster(func(ctx context.Context, uid string, deleted bool) {
		pm.ClusterChange(ctx, "notifications", notify.ClusterItemChannels, uid, deleted)
	})
}
