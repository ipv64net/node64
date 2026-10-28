package peer

import (
	"context"
	"fmt"
	"net/http"
)

// Aussetzen von Mitgliedern: aendert sich etwas Grundlegendes an einer Node (Account, Schluessel bzw. Kennung,
// Bindung der Verbindung, zu alte Version), wird sie ausgesetzt. Danach gehen keine Anfragen mehr an sie (call
// liefert ErrSuspended) und von ihr wird nur noch der Ping beantwortet (fuer das Wiederaufnehmen) und die Abmeldung
// angenommen. Die uebrigen Mitglieder arbeiten weiter. Wieder aufgenommen wird nur von Hand (Resume).

// Gruende der Aussetzung (Kennungen, die Oberflaeche uebersetzt cluster.reason.<kennung>).
const (
	ReasonAccountChanged  = "account_changed"  // eigener Account passt nicht mehr zum Cluster (X→Y)
	ReasonAccountMismatch = "account_mismatch" // Account der anderen Node passt nicht (anderer als der des Clusters)
	ReasonIdentityChanged = "identity_changed" // anderer Schluessel bzw. andere Node an der Adresse
	ReasonTLSBinding      = "tls_binding"      // Verbindung nicht an die Kopplung gebunden (Proxy dazwischen)
	ReasonVersionTooOld   = "version_too_old"  // Node ohne Cluster-Protokoll

	stateSuspended = "suspended"
	stateActive    = "active"
)

// Suspended: das Mitglied ist ausgesetzt, keine Kommunikation mit ihm.
func (x Member) Suspended() bool { return x.State == stateSuspended }

// activeMembers liefert die nicht ausgesetzten Mitglieder (fuer alles, was Anfragen schickt oder Daten erwartet).
func (m *Manager) activeMembers(ctx context.Context) []Member {
	list, _ := m.Members(ctx)
	out := list[:0]
	for _, x := range list {
		if !x.Suspended() {
			out = append(out, x)
		}
	}
	return out
}

// suspend setzt ein Mitglied aus (bzw. aktualisiert den Grund) und schreibt es beim ersten Mal ins Audit-Log.
func (m *Manager) suspend(ctx context.Context, x Member, reason, detail string) {
	if x.Suspended() && x.Reason == reason {
		return
	}
	res, err := m.db.ExecContext(context.WithoutCancel(ctx), `UPDATE peer_members SET state = ?, reason = ?, last_error = ? WHERE node_id = ? AND (state != ? OR reason != ?)`,
		stateSuspended, reason, trunc(detail, 300), x.NodeID, stateSuspended, reason)
	if err != nil {
		m.d.Log.Error("cluster member not suspended", "node", x.Name, "err", err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 || x.Suspended() {
		return
	}
	m.d.Log.Warn("cluster member suspended", "node", x.Name, "reason", reason, "detail", detail)
	m.auditPeer(ctx, x.Name, "peer.suspended", x.Name, reason)
}

// compatible: zwei Accounts passen zusammen, wenn sie gleich sind oder eine Seite keinen hat (0). Ein Cluster hat nie
// zwei verschiedene Accounts (Dennis: gleicher Account oder keiner).
func compatible(a, b int64) bool { return a == 0 || b == 0 || a == b }

// ClusterAccount ist der Account des Clusters aus Sicht dieser Node: der eigene, sonst der eines aktiven Mitglieds
// (0 = noch keiner im Cluster).
func (m *Manager) ClusterAccount(ctx context.Context) int64 {
	if own := m.d.AccountID(); own != 0 {
		return own
	}
	for _, x := range m.activeMembers(ctx) {
		if x.AccountID != 0 {
			return x.AccountID
		}
	}
	return 0
}

// checkAccount gleicht den eigenen Account mit dem der Kopplung ab (self_account). Passt der neue zum Cluster (0→X mit
// X wie im Cluster oder noch keiner dort, X→0), wird er nur vermerkt; sonst (X→Y) werden alle Mitglieder ausgesetzt.
// Liefert true, wenn der eigene Account nicht (mehr) passt.
func (m *Manager) checkAccount(ctx context.Context) bool {
	own := m.d.AccountID()
	list := m.activeMembers(ctx)
	ref, changed := int64(0), false
	for _, x := range list {
		changed = changed || x.SelfAccount != own
		if ref == 0 { // bisheriger Account des Clusters: eigener bei der Kopplung, sonst der des Mitglieds
			ref = x.SelfAccount
			if ref == 0 {
				ref = x.AccountID
			}
		}
	}
	if !changed {
		return false
	}
	if compatible(own, ref) {
		if res, err := m.db.ExecContext(context.WithoutCancel(ctx), `UPDATE peer_members SET self_account = ? WHERE state != ? AND self_account != ?`,
			own, stateSuspended, own); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				m.d.Log.Info("own ipv64 account changed, cluster stays", "account", own)
			}
		}
		return false
	}
	for _, x := range list {
		if x.SelfAccount != own {
			m.suspend(ctx, x, ReasonAccountChanged, "own ipv64 account changed")
		}
	}
	return true
}

// accountChanged: der eigene Account passt nicht mehr zur Kopplung mit x (dann sind alle betroffenen Mitglieder
// ausgesetzt). Eine passende Aenderung (0→X, X→0) wird dabei nur vermerkt.
func (m *Manager) accountChanged(ctx context.Context, x Member) bool {
	if x.SelfAccount == m.d.AccountID() {
		return false
	}
	return m.checkAccount(ctx)
}

// activate setzt ein Mitglied (wieder) aktiv mit seinem Account acc (passend zum eigenen, siehe compatible).
func (m *Manager) activate(ctx context.Context, nodeID string, acc int64) {
	_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET state = ?, reason = '', account_id = ?, self_account = ?, last_error = '' WHERE node_id = ?`,
		stateActive, acc, m.d.AccountID(), nodeID)
}

// Resume nimmt ein ausgesetztes Mitglied wieder auf: prueft per Ping erneut (Schluessel, Bindung, Account). Passt
// es, ist es wieder aktiv (bei geaendertem Account mit dem neuen, wenn er jetzt zum Cluster passt);
// sonst bleibt es ausgesetzt mit dem aktuellen Grund (Fehler mit ErrSuspended). Die andere Node nimmt diese bei sich
// selbst wieder auf.
func (m *Manager) Resume(ctx context.Context, nodeID string) error {
	x, err := m.member(ctx, nodeID)
	if err != nil {
		return err
	}
	if x == nil {
		return ErrUnknownMember
	}
	if !x.Suspended() {
		return nil
	}
	var out pingInfo
	if err := m.callAny(ctx, *x, http.MethodGet, "/peer/v1/ping", nil, &out, true); err != nil {
		cur, _ := m.member(ctx, nodeID)
		if cur == nil {
			cur = x
		}
		return fmt.Errorf("%w (%s): %v", ErrSuspended, cur.Reason, err)
	}
	if out.NodeID != x.NodeID {
		m.suspend(ctx, *x, ReasonIdentityChanged, "other node at this address")
		return fmt.Errorf("%w (%s)", ErrSuspended, ReasonIdentityChanged)
	}
	if !compatible(out.AccountID, m.ClusterAccount(ctx)) {
		m.suspend(ctx, *x, ReasonAccountMismatch, "account of the other node does not match")
		return fmt.Errorf("%w (%s)", ErrSuspended, ReasonAccountMismatch)
	}
	m.activate(ctx, nodeID, out.AccountID)
	m.seen(ctx, nodeID, out, nil)
	m.d.Log.Info("cluster member resumed", "node", x.Name, "was", x.Reason)
	m.auditPeer(ctx, m.d.NodeName(), "peer.resumed", x.Name, x.Reason)
	go m.pullAll(context.Background(), nodeID)
	return nil
}
