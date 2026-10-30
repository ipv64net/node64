package cdn64

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Freigabe- und Sperrliste auf den CDN64-Servern: beim Abgleich schickt die Node beide Listen fuer ihren Tunnel an
// ipv64, wenn sie sich geaendert haben; die Server weisen Adressen der Sperrliste fuer alle Namen des Tunnels schon
// beim Verbindungsaufbau ab (die Freigabeliste geht vor). Dort gelten hoechstens onlineListMax Eintraege je Liste.

const (
	setOnlineLists = "cdn64.online_lists" // zuletzt geschickter Stand (Pruefsumme mit Tunnel)
	onlineListMax  = 1000
)

// onlineListsAPI: ipv64 nimmt die Listen eines Tunnels an (IPv64Online).
type onlineListsAPI interface {
	SetLists(ctx context.Context, tunnelID string, allow, deny []string) error
}

// onlineListsOf: beide Listen, gekuerzt auf das, was die Server annehmen.
func (m *Module) onlineListsOf(ctx context.Context) (allow, deny []string) {
	cut := func(key string) []string {
		l := strings.Fields(m.core.SettingOr(ctx, key, ""))
		return l[:min(len(l), onlineListMax)]
	}
	return cut(setBlockAllow), cut(setBlockDeny)
}

// onlineListsSync schickt die Listen, wenn sie sich seit dem letzten Mal geaendert haben (aus onlineSync, unter op).
func (m *Module) onlineListsSync(ctx context.Context, tunnelID string) {
	api, ok := m.online.api.(onlineListsAPI)
	if !ok || tunnelID == "" {
		return
	}
	allow, deny := m.onlineListsOf(ctx)
	h := sha256.Sum256([]byte(tunnelID + "\n" + strings.Join(allow, ",") + "\n" + strings.Join(deny, ",")))
	sum := hex.EncodeToString(h[:])
	last := m.core.SettingOr(ctx, setOnlineLists, "")
	if last == sum || (last == "" && len(allow) == 0 && len(deny) == 0) { // nie geschickt und leer: nichts zu tun
		return
	}
	if err := api.SetLists(ctx, tunnelID, allow, deny); err != nil {
		if err.Error() != m.online.lists { // gleicher Fehler nur einmal (z. B. ipv64 noch ohne diese Funktion)
			m.log.Warn("cdn64 online: block list not sent to the servers", "err", err)
		}
		m.online.lists = err.Error()
		return
	}
	m.online.lists = ""
	_ = m.core.SetSetting(ctx, setOnlineLists, sum)
	m.log.Info("cdn64 online: block list sent to the servers", "deny", len(deny), "allow", len(allow))
}
