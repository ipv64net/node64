package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// Gemeinsamer Cluster-Schluessel (Plan "Ein gemeinsamer Cluster-Schluessel"): Mit dem Bereich Monitor64 haben alle
// Nodes denselben privaten Schluessel (Eintrag "key:cluster", Klartext ueber die Cluster-Verbindung, gespeichert mit
// dem Schluessel der Node wie das ACME-Konto). Ein Agent wird einmal installiert und jede Node darf ihn abfragen.
//
//   - Gibt es im Cluster noch keinen, bringt ihn die Node mit der kleinsten Kennung ein (nach clusterKeyWait; eine
//     gerade beigetretene Node wartet laenger, sie soll den des Clusters uebernehmen).
//   - Uebernimmt eine Node einen anderen Schluessel (Beitritt) bzw. wird er gewechselt, behaelt sie den alten (bis zu
//     maxOldKeys) und bietet ihn den Agents und SSH-Hosts weiter an, bis ihre Agents per Anfrage "keys" auf den neuen
//     umgestellt sind (m64_keypending). Danach ist der alte weg. Agents, die gerade nicht erreichbar sind, stehen als
//     "Schluessel veraltet" in der Liste; SSH-Hosts ohne Agent kann die Node nicht selbst umstellen (neue Zeile fuer
//     authorized_keys, nach dem Eintragen bestaetigen).
//   - Umgestellt werden die Hosts, fuer die diese Node zustaendig oder bevorzugt ist (die erreicht sie).
//
// Achtung: "keys" setzt die ganze Schluesselliste des Agents; Schluessel anderer Nodes ausserhalb des Clusters fallen
// dabei weg.

const (
	setKeyCluster = "monitor64.key_cluster" // Zeitpunkt (RFC 3339) des Cluster-Schluessels; leer = eigener Schluessel
	setOldKeys    = "monitor64.old_keys"    // JSON-Liste alter privater Schluessel (je verschluesselt)
	setKeyJoined  = "monitor64.key_joined"  // "1": diese Node ist beigetreten (bringt keinen Schluessel ein)
	maxOldKeys    = 3
)

var (
	clusterKeyWait = 2 * time.Minute  // so lange nach dem Start warten, bevor eine Node ihren Schluessel einbringt
	keyRetryEvery  = 5 * time.Minute  // nicht erreichbare Agents erneut umstellen
	keySwitchLimit = 30 * time.Second // je Agent
)

// keyEntry ist der Eintrag "key:cluster".
type keyEntry struct {
	PEM string    `json:"pem"`
	At  time.Time `json:"at"`
}

// nodeSigners: aktueller Schluessel und die alten (werden nach ihm angeboten).
func (m *Module) nodeSigners(ctx context.Context) (ssh.Signer, []ssh.Signer, error) {
	s, err := m.nodeSigner(ctx)
	if err != nil {
		return nil, nil, err
	}
	var extra []ssh.Signer
	for _, enc := range m.oldKeys(ctx) {
		pem, err := m.box.Decrypt(enc)
		if err != nil {
			continue
		}
		if o, err := transport.ParseKey([]byte(pem)); err == nil && transport.Fingerprint(o.PublicKey()) != transport.Fingerprint(s.PublicKey()) {
			extra = append(extra, o)
		}
	}
	return s, extra, nil
}

func (m *Module) oldKeys(ctx context.Context) []string {
	var l []string
	_ = json.Unmarshal([]byte(m.st.SettingOr(ctx, setOldKeys, "[]")), &l)
	return l
}

func (m *Module) keyGet(ctx context.Context) (json.RawMessage, bool, error) {
	at := m.st.SettingOr(ctx, setKeyCluster, "")
	if at == "" {
		return nil, false, nil
	}
	enc, ok, err := m.st.Setting(ctx, setNodeKey)
	if err != nil || !ok {
		return nil, false, err
	}
	pem, err := m.box.Decrypt(enc)
	if err != nil {
		return nil, false, err // hier nicht lesbar: die anderen holen ihn spaeter erneut
	}
	t, _ := time.Parse(time.RFC3339Nano, at)
	b, err := json.Marshal(keyEntry{PEM: pem, At: t})
	return b, err == nil, err
}

func (m *Module) keyApply(ctx context.Context, data json.RawMessage, deleted bool) error {
	if deleted {
		return nil // der Schluessel bleibt (sonst waeren alle Agents ausgesperrt)
	}
	var in keyEntry
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	signer, err := transport.ParseKey([]byte(in.PEM))
	if err != nil {
		return err
	}
	if in.At.IsZero() {
		in.At = time.Now()
	}
	return m.useKey(ctx, in.PEM, signer, in.At, false)
}

// useKey macht einen Schluessel zum aktuellen (Cluster-Schluessel); announce: an den Cluster melden (eigener Wechsel).
func (m *Module) useKey(ctx context.Context, pem string, signer ssh.Signer, at time.Time, announce bool) error {
	cur, err := m.nodeSigner(ctx)
	if err != nil {
		return err
	}
	changed := transport.Fingerprint(cur.PublicKey()) != transport.Fingerprint(signer.PublicKey())
	nodeKeyMu.Lock()
	if changed {
		old := m.oldKeys(ctx)
		if enc := m.st.SettingOr(ctx, setNodeKey, ""); enc != "" {
			old = append([]string{enc}, old...)
		}
		if len(old) > maxOldKeys {
			old = old[:maxOldKeys]
		}
		b, _ := json.Marshal(old)
		if err := m.st.SetSetting(ctx, setOldKeys, string(b)); err != nil {
			nodeKeyMu.Unlock()
			return err
		}
		if err := m.st.SetSetting(ctx, setNodeKey, m.box.Encrypt(pem)); err != nil {
			nodeKeyMu.Unlock()
			return err
		}
	}
	err = m.st.SetSetting(ctx, setKeyCluster, at.UTC().Format(time.RFC3339Nano))
	nodeKeyMu.Unlock()
	if err != nil {
		return err
	}
	if announce {
		m.clusterChange(ctx, ClusterItemConfig, "key:cluster", false)
	}
	if !changed {
		return nil
	}
	m.log.Info("monitor64: node key changed (cluster key)", "fingerprint", transport.Fingerprint(signer.PublicKey()))
	m.queueKeySwitch(ctx, transport.Fingerprint(signer.PublicKey()))
	m.cl.bg.Go(func() { m.reloadAllHosts(context.WithoutCancel(ctx)) }) // Sammler mit neuem (und altem) Schluessel; nicht unter der Sperre des Abgleichs
	return nil
}

func (m *Module) reloadAllHosts(ctx context.Context) {
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return
	}
	for _, h := range hosts {
		m.ReloadHost(ctx, h.UID)
	}
}

// queueKeySwitch merkt die Agents und SSH-Hosts (Schluessel-Anmeldung), die auf fp umzustellen sind.
func (m *Module) queueKeySwitch(ctx context.Context, fp string) {
	self := m.clusterSelf()
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return
	}
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return
	}
	mine := map[string]bool{}
	for _, h := range hosts {
		mine[h.UID] = ownerOf(h, self) == self || preferredOf(h, self) == self
	}
	db := m.st.Writer()
	_, _ = db.ExecContext(ctx, `DELETE FROM m64_keypending WHERE target_fp != ?`, fp)
	for _, a := range accs {
		if !mine[a.HostUID] || !a.Enabled || (a.Type != "agent" && a.Type != "ssh") || a.Type == "ssh" && a.Secret != "" {
			continue // SSH mit Passwort braucht keinen Schluessel
		}
		_, _ = db.ExecContext(ctx, `INSERT INTO m64_keypending (access_uid, host_uid, type, target_fp, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (access_uid) DO UPDATE SET target_fp = excluded.target_fp, tries = 0, last_try = '', error = ''`, a.UID, a.HostUID, a.Type, fp, tsNow())
	}
}

// keyPending ist ein noch nicht umgestellter Zugang.
type keyPending struct {
	AccessUID string    `json:"access_uid"`
	HostUID   string    `json:"host_uid"`
	HostName  string    `json:"host_name,omitempty"`
	Type      string    `json:"type"`
	Tries     int       `json:"tries"`
	LastTry   time.Time `json:"last_try,omitzero"`
	Error     string    `json:"error,omitempty"`
	Manual    bool      `json:"manual"` // SSH: Zeile von Hand eintragen, dann bestaetigen
}

func (m *Module) keyPendingList(ctx context.Context) []keyPending {
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT k.access_uid, k.host_uid, COALESCE(h.name, ''), k.type, k.tries, k.last_try, k.error
		FROM m64_keypending k LEFT JOIN m64_hosts h ON h.uid = k.host_uid ORDER BY h.name, k.access_uid`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []keyPending{}
	for rows.Next() {
		var p keyPending
		var last string
		if rows.Scan(&p.AccessUID, &p.HostUID, &p.HostName, &p.Type, &p.Tries, &last, &p.Error) == nil {
			p.LastTry, p.Manual = parseTS(last), p.Type == "ssh"
			out = append(out, p)
		}
	}
	return out
}

// clusterKeys: Schluessel einbringen (keiner im Cluster), Agents umstellen, alte Schluessel abraeumen.
func (m *Module) clusterKeys(ctx context.Context, s *clusterSnap) {
	if m.scheduler() == nil {
		return
	}
	if s.Active && m.st.SettingOr(ctx, setKeyCluster, "") == "" {
		wait := clusterKeyWait
		if m.st.SettingOr(ctx, setKeyJoined, "") == "1" {
			wait *= 5
		}
		smallest := true
		for id, p := range s.Peers {
			if p.Online && id < s.Self {
				smallest = false
			}
		}
		if smallest && m.cl.clock().Sub(m.cl.started) >= wait {
			if signer, err := m.nodeSigner(ctx); err == nil {
				enc := m.st.SettingOr(ctx, setNodeKey, "")
				if pem, err := m.box.Decrypt(enc); err == nil {
					_ = m.useKey(ctx, pem, signer, time.Now(), true)
				}
			}
		}
	}
	m.switchAgents(ctx, false)
}

// switchAgents stellt die Agents der Liste auf den aktuellen Schluessel um (now: ohne Wartezeit).
func (m *Module) switchAgents(ctx context.Context, now bool) {
	signer, err := m.nodeSigner(ctx)
	if err != nil {
		return
	}
	line := transport.AuthorizedKeyLine(signer.PublicKey(), "node64@"+m.st.SettingOr(ctx, "node.name", "node"))
	fp := transport.Fingerprint(signer.PublicKey())
	list := m.keyPendingList(ctx)
	open := 0
	for _, p := range list {
		if p.Type != "agent" {
			open++
			continue
		}
		if !now && !p.LastTry.IsZero() && time.Since(p.LastTry) < keyRetryEvery {
			open++
			continue
		}
		err := m.switchAgent(ctx, p, line)
		if err == nil {
			_, _ = m.st.Writer().ExecContext(ctx, `DELETE FROM m64_keypending WHERE access_uid = ? AND target_fp = ?`, p.AccessUID, fp)
			m.log.Info("monitor64: agent switched to the current node key", "host", p.HostName)
			continue
		}
		open++
		_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_keypending SET tries = tries + 1, last_try = ?, error = ? WHERE access_uid = ?`,
			tsNow(), shortErr(err), p.AccessUID)
	}
	if open == 0 && len(m.oldKeys(ctx)) > 0 { // alles umgestellt: alte Schluessel weg
		m.retireOldKeys(ctx)
	}
}

var errNoAgent = errors.New("monitor64: agent access not loaded")

func (m *Module) switchAgent(ctx context.Context, p keyPending, line string) error {
	m.rtMu.Lock()
	rt := m.rts[p.HostUID]
	m.rtMu.Unlock()
	if rt == nil {
		return errNoAgent
	}
	rt.mu.Lock()
	var ac *agentCollector
	for _, a := range rt.accs {
		if a.row.UID == p.AccessUID {
			ac, _ = a.col.(*agentCollector)
		}
	}
	rt.mu.Unlock()
	if ac == nil {
		return errNoAgent
	}
	c, err := ac.ref.agent(ac.cfg)
	if err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, keySwitchLimit)
	defer cancel()
	_, err = c.SetKeys(cctx, []string{line})
	return err
}

// retireOldKeys verwirft die alten Schluessel (alle umgestellt bzw. von Hand).
func (m *Module) retireOldKeys(ctx context.Context) {
	nodeKeyMu.Lock()
	err := m.st.SetSetting(ctx, setOldKeys, "[]")
	nodeKeyMu.Unlock()
	if err != nil {
		return
	}
	m.log.Info("monitor64: old node keys removed")
	m.cl.bg.Go(func() { m.reloadAllHosts(context.WithoutCancel(ctx)) })
}

// RotateKey erzeugt einen neuen Schluessel fuer den Cluster (Knopf "Schluessel wechseln").
func (m *Module) RotateKey(ctx context.Context) error {
	pem, signer, err := transport.GenerateKey("node64@" + m.st.SettingOr(ctx, "node.name", "node"))
	if err != nil {
		return err
	}
	return m.useKey(ctx, string(pem), signer, time.Now(), true)
}

// ClusterJoined: diese Node ist einem Cluster beigetreten (peer.Joiner) - sie uebernimmt den Schluessel des Clusters,
// statt ihren einzubringen.
func (m *Module) ClusterJoined(ctx context.Context) []string {
	if m.st.SettingOr(ctx, setKeyCluster, "") == "" {
		_ = m.st.SetSetting(ctx, setKeyJoined, "1")
	}
	return nil
}

// keyInfo ist der Stand der Schluessel fuer die Oberflaeche.
type keyInfo struct {
	Fingerprint   string       `json:"fingerprint"`
	AuthorizedKey string       `json:"authorized_key"` // Zeile fuer authorized_keys bzw. den Installationsbefehl
	Cluster       bool         `json:"cluster"`        // gemeinsamer Cluster-Schluessel
	At            time.Time    `json:"at,omitzero"`
	OldKeys       []string     `json:"old_keys"` // Fingerabdruecke der alten, noch angebotenen Schluessel
	Pending       []keyPending `json:"pending"`
}

func (m *Module) keyInfo(ctx context.Context) (keyInfo, error) {
	s, extra, err := m.nodeSigners(ctx)
	if err != nil {
		return keyInfo{}, err
	}
	at := m.st.SettingOr(ctx, setKeyCluster, "")
	t, _ := time.Parse(time.RFC3339Nano, at)
	out := keyInfo{Fingerprint: transport.Fingerprint(s.PublicKey()), Cluster: at != "", At: t, OldKeys: []string{},
		AuthorizedKey: strings.TrimSpace(transport.AuthorizedKeyLine(s.PublicKey(), "node64@"+m.st.SettingOr(ctx, "node.name", "node"))),
		Pending:       m.keyPendingList(ctx)}
	for _, o := range extra {
		out.OldKeys = append(out.OldKeys, transport.Fingerprint(o.PublicKey()))
	}
	return out, nil
}
