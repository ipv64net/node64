package m64cluster

import (
	"context"
	"slices"
	"time"

	"github.com/ipv64net/node64/internal/monitor64"
	"github.com/ipv64net/node64/internal/peer"
)

// members ist der Hook "Members" (Register): die Mitglieder fuer die Zustaendigkeit je Host.
func members(pm *peer.Manager, m *monitor64.Module) func(ctx context.Context, item string) []monitor64.ClusterPeer {
	return func(ctx context.Context, item string) []monitor64.ClusterPeer {
		list, err := pm.Members(ctx)
		if err != nil {
			return nil
		}
		return areaPeers(localAreaOn(ctx, pm, item), list, item, func(id string) bool { return m.ClusterNodeUsed(ctx, id) })
	}
}

// areaPeers: wie peer.AreaMembers, aber Mitglieder, die gerade nicht abgleichen (ausgesetzt, Monitor64 bzw. der Bereich
// dort aus), fehlen nicht, sondern zaehlen als nicht erreichbar - sofern sie fuer Monitor64 zaehlen: Bereich dort
// eingeschaltet (ausgesetzt) oder ein Host nennt sie (bevorzugt, zustaendig, Ersatz). Sonst schrumpft der Cluster: bei
// zwei Nodes gaebe es keinen mehr (Hosts der anderen ohne Uebernahme), bei drei griffe der Sonderfall zweier Nodes
// (Uebernahme ohne Mehrheit). Mitglieder ohne Monitor64, die kein Host nennt, zaehlen nicht (sonst fehlte z. B. bei
// Monitor64 auf zwei von vier Nodes immer die Mehrheit). Bereich hier aus: keine Mitglieder.
func areaPeers(localOn bool, list []peer.Member, item string, used func(id string) bool) []monitor64.ClusterPeer {
	if !localOn {
		return nil
	}
	area := monitor64.ClusterModuleID + "/" + item
	out := make([]monitor64.ClusterPeer, 0, len(list))
	for _, x := range list {
		inArea := slices.Contains(x.Sync, area)
		syncing := inArea && !x.Suspended()
		if !inArea && !used(x.NodeID) {
			continue
		}
		online := syncing && x.Online()
		out = append(out, monitor64.ClusterPeer{ID: x.NodeID, Name: x.Name, Online: online, Silent: online && time.Since(x.LastSeen) > peerSilentAfter})
	}
	return out
}

// peerSilentAfter: laenger als ein Ping-Abstand (30 s) plus Spielraum ohne Antwort.
const peerSilentAfter = 45 * time.Second

// localAreaOn: Bereich auf dieser Node eingeschaltet (Modul laeuft, abgleichen an, Bereich an; wie peer.syncOn).
func localAreaOn(ctx context.Context, pm *peer.Manager, item string) bool {
	for _, st := range pm.SyncModules(ctx) {
		if st.ID != monitor64.ClusterModuleID {
			continue
		}
		if !st.Available || !st.Enabled {
			return false
		}
		for _, it := range st.Items {
			if it.ID == item {
				return it.Enabled
			}
		}
	}
	return false
}
