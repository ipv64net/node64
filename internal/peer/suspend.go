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
	ReasonAccountChanged  = "account_changed"  // eigener Account geaendert (0→X, X→Y, X→0)
	ReasonAccountMismatch = "account_mismatch" // Account der anderen Node passt nicht
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

// checkAccount setzt alle Mitglieder aus, die mit einem anderen eigenen Account gekoppelt wurden.
func (m *Manager) checkAccount(ctx context.Context) {
	own := m.d.AccountID()
	for _, x := range m.activeMembers(ctx) {
		if x.SelfAccount != own {
			m.suspend(ctx, x, ReasonAccountChanged, "own ipv64 account changed")
		}
	}
}

// accountChanged: der eigene Account ist nicht mehr der der Kopplung mit x (dann sind alle betroffenen Mitglieder
// ausgesetzt).
func (m *Manager) accountChanged(ctx context.Context, x Member) bool {
	if x.SelfAccount == m.d.AccountID() {
		return false
	}
	m.checkAccount(ctx)
	return true
}

// activate setzt ein Mitglied (wieder) aktiv, gekoppelt mit dem gemeinsamen Account acc.
func (m *Manager) activate(ctx context.Context, nodeID string, acc int64) {
	_, _ = m.db.ExecContext(ctx, `UPDATE peer_members SET state = ?, reason = '', account_id = ?, self_account = ?, last_error = '' WHERE node_id = ?`,
		stateActive, acc, acc, nodeID)
}

// Resume nimmt ein ausgesetztes Mitglied wieder auf: prueft per Ping erneut (Schluessel, Bindung, Account). Passt
// es, ist es wieder aktiv (bei geaendertem Account mit dem neuen gemeinsamen, wenn beide Seiten jetzt gleich sind);
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
	own := m.d.AccountID()
	if out.NodeID != x.NodeID {
		m.suspend(ctx, *x, ReasonIdentityChanged, "other node at this address")
		return fmt.Errorf("%w (%s)", ErrSuspended, ReasonIdentityChanged)
	}
	if out.AccountID != own {
		m.suspend(ctx, *x, ReasonAccountMismatch, "account of the other node does not match")
		return fmt.Errorf("%w (%s)", ErrSuspended, ReasonAccountMismatch)
	}
	m.activate(ctx, nodeID, own)
	m.seen(ctx, nodeID, out, nil)
	m.d.Log.Info("cluster member resumed", "node", x.Name, "was", x.Reason)
	m.auditPeer(ctx, m.d.NodeName(), "peer.resumed", x.Name, x.Reason)
	go m.pullAll(context.Background(), nodeID)
	return nil
}
