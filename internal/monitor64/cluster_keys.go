package monitor64

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
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
//     maxOldKeys) und bietet ihn den Agents und SSH-Hosts weiter an, bis alle auf den neuen umgestellt sind
//     (m64_keypending). Agents, die gerade nicht erreichbar sind, stehen als "Schluessel veraltet" in der Liste;
//     SSH-Hosts ohne Agent kann die Node nicht selbst umstellen (neue Zeile fuer authorized_keys, nach dem Eintragen
//     bestaetigen).
//   - Per Anfrage "keys" umgestellt werden die Agents der Hosts, fuer die diese Node zustaendig oder bevorzugt ist (die
//     erreicht sie). Jede Umstellung bzw. Bestaetigung meldet die Node im Cluster (Eintrag "key:cluster", Liste "done"
//     je Schluessel; die Nodes fuehren die Listen zusammen). Die Umstellung laeuft im Hintergrund (startKeySwitch),
//     nie zweimal zugleich.
//
// Regel fuer das Verwerfen der alten Schluessel (lieber zu lange behalten als einen Agent aussperren) - erst wenn
//  1. der Schluessel seit Beginn des Laufs derselbe ist (ein Wechsel mitten im Lauf verwirft nichts; Pruefung unter
//     nodeKeyMu),
//  2. jeder Zugang, der den Schluessel der Node braucht (Agent, SSH ohne Passwort), auf jedem Host - auch deaktivierte
//     Zugaenge, auch Hosts anderer Nodes und solche, fuer die diese Node nur Ersatz ist - clusterweit als umgestellt
//     bzw. bestaetigt gilt; die offene Liste wird dafuer frisch aus allen Zugaengen gebildet (neue Zugaenge seit dem
//     Wechsel kommen dazu, geloeschte fallen weg),
//  3. also nichts mehr offen ist.
//
// Sonst bleiben sie; der Knopf "Alte Schluessel verwerfen" ist der bewusste Schritt daran vorbei.
//
// Achtung: "keys" setzt die ganze Schluesselliste des Agents; Schluessel anderer Nodes ausserhalb des Clusters fallen
// dabei weg.

const (
	setKeyCluster = "monitor64.key_cluster" // Zeitpunkt (RFC 3339) des Cluster-Schluessels; leer = eigener Schluessel
	setOldKeys    = "monitor64.old_keys"    // JSON-Liste alter privater Schluessel (je verschluesselt)
	setKeyJoined  = "monitor64.key_joined"  // "1": diese Node ist beigetreten (bringt keinen Schluessel ein)
	setKeyDone    = "monitor64.key_done"    // JSON keyDoneSet: clusterweit umgestellte bzw. bestaetigte Zugaenge
	maxOldKeys    = 3
	maxKeyDone    = 50000
)

var (
	clusterKeyWait = 2 * time.Minute  // so lange nach dem Start warten, bevor eine Node ihren Schluessel einbringt
	keyRetryEvery  = 5 * time.Minute  // nicht erreichbare Agents erneut umstellen
	keySwitchLimit = 30 * time.Second // je Agent
)

// keyEntry ist der Eintrag "key:cluster".
type keyEntry struct {
	PEM  string    `json:"pem"`
	At   time.Time `json:"at"`
	Done []string  `json:"done,omitempty"` // Zugaenge, die auf diesen Schluessel umgestellt bzw. bestaetigt sind
}

// keyDoneSet: Zugaenge, die clusterweit auf den Schluessel FP umgestellt bzw. bestaetigt sind.
type keyDoneSet struct {
	FP   string   `json:"fp"`
	UIDs []string `json:"uids"`
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
	signer, err := transport.ParseKey([]byte(pem))
	if err != nil {
		return nil, false, err
	}
	t, _ := time.Parse(time.RFC3339Nano, at)
	e := keyEntry{PEM: pem, At: t}
	if d := m.keyDone(ctx); d.FP == transport.Fingerprint(signer.PublicKey()) {
		e.Done = d.UIDs
	}
	b, err := json.Marshal(e)
	return b, err == nil, err
}

// keyApply uebernimmt den Schluessel des Clusters. Es gilt der juengere Schluessel (sein Zeitpunkt, nicht der der
// Meldung: auch Nodes, die nur ihre Umstellungen melden, schicken den Eintrag); bei gleichem Schluessel werden die
// Listen der umgestellten Zugaenge zusammengefuehrt. Hat diese Node den juengeren Schluessel bzw. mehr umgestellte
// Zugaenge, meldet sie ihren Stand neu (die eingehende Fassung ist damit ueberholt).
func (m *Module) keyApply(ctx context.Context, data json.RawMessage, deleted bool) error {
	if deleted {
		return nil // der Schluessel bleibt (sonst waeren alle Agents ausgesperrt)
	}
	var in keyEntry
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if len(in.Done) > maxKeyDone {
		return errClItem
	}
	signer, err := transport.ParseKey([]byte(in.PEM))
	if err != nil {
		return err
	}
	if in.At.IsZero() {
		in.At = time.Now()
	}
	fp := transport.Fingerprint(signer.PublicKey())
	if cur, err := m.nodeSigner(ctx); err == nil && transport.Fingerprint(cur.PublicKey()) != fp {
		if at := m.st.SettingOr(ctx, setKeyCluster, ""); at != "" {
			own, _ := time.Parse(time.RFC3339Nano, at)
			if own.After(in.At) || own.Equal(in.At) && transport.Fingerprint(cur.PublicKey()) > fp {
				m.clusterChange(context.Background(), ClusterItemConfig, "key:cluster", false) // der eigene ist juenger
				return supersededErr{"newer cluster key"}
			}
		}
	}
	if err := m.useKey(ctx, in.PEM, signer, in.At, false); err != nil {
		return err
	}
	var done []string
	for _, u := range in.Done {
		if reUID.MatchString(u) {
			done = append(done, u)
		}
	}
	if m.mergeKeyDone(ctx, fp, done) {
		m.clusterChange(context.Background(), ClusterItemConfig, "key:cluster", false) // hier sind mehr umgestellt
		return supersededErr{"more switched accesses"}
	}
	return nil
}

func (m *Module) keyDone(ctx context.Context) keyDoneSet {
	var d keyDoneSet
	_ = json.Unmarshal([]byte(m.st.SettingOr(ctx, setKeyDone, "")), &d)
	return d
}

func (m *Module) saveKeyDone(ctx context.Context, d keyDoneSet) error {
	if len(d.UIDs) > maxKeyDone {
		d.UIDs = d.UIDs[len(d.UIDs)-maxKeyDone:]
	}
	b, _ := json.Marshal(d)
	return m.st.SetSetting(ctx, setKeyDone, string(b))
}

// mergeKeyDone nimmt clusterweit gemeldete Umstellungen fuer fp auf (offene Eintraege dazu fallen weg); more: hier
// sind Zugaenge umgestellt, die in uids fehlen.
func (m *Module) mergeKeyDone(ctx context.Context, fp string, uids []string) (more bool) {
	m.cl.kdMu.Lock()
	defer m.cl.kdMu.Unlock()
	d := m.keyDone(ctx)
	if d.FP != fp {
		d = keyDoneSet{FP: fp}
	}
	have := map[string]bool{}
	for _, u := range d.UIDs {
		have[u] = true
	}
	in := map[string]bool{}
	var added []string
	for _, u := range uids {
		in[u] = true
		if !have[u] {
			have[u] = true
			added = append(added, u)
		}
	}
	for _, u := range d.UIDs {
		if !in[u] {
			more = true
			break
		}
	}
	if len(added) == 0 {
		return more
	}
	d.UIDs = append(d.UIDs, added...)
	if m.saveKeyDone(ctx, d) != nil {
		return more
	}
	for _, u := range added {
		_, _ = m.st.Writer().ExecContext(ctx, `DELETE FROM m64_keypending WHERE access_uid = ? AND target_fp = ?`, u, fp)
	}
	return more
}

// markKeyDone: Zugaenge hier umgestellt bzw. bestaetigt (Schluessel fp) - merken und im Cluster melden. Ist fp nicht
// mehr der aktuelle Schluessel, zaehlt es nicht.
func (m *Module) markKeyDone(ctx context.Context, fp string, uids ...string) {
	if len(uids) == 0 || m.currentKeyFP(ctx) != fp {
		return
	}
	m.cl.kdMu.Lock()
	d := m.keyDone(ctx)
	if d.FP != fp {
		d = keyDoneSet{FP: fp}
	}
	for _, u := range uids {
		if !slices.Contains(d.UIDs, u) {
			d.UIDs = append(d.UIDs, u)
		}
	}
	err := m.saveKeyDone(ctx, d)
	m.cl.kdMu.Unlock()
	if err == nil && m.st.SettingOr(ctx, setKeyCluster, "") != "" {
		m.clusterChange(context.Background(), ClusterItemConfig, "key:cluster", false)
	}
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

// needsNodeKey: der Zugang meldet sich mit dem Schluessel der Node an (Agent, SSH ohne Passwort).
func needsNodeKey(a *Access) bool {
	return a.Type == "agent" || a.Type == "ssh" && a.Secret == ""
}

// queueKeySwitch merkt die Agents und SSH-Hosts (Schluessel-Anmeldung), die auf fp umzustellen sind.
func (m *Module) queueKeySwitch(ctx context.Context, fp string) {
	if err := m.refreshKeyPending(ctx, fp); err != nil {
		m.log.Warn("monitor64: key switch list", "err", err)
	}
}

// refreshKeyPending gleicht die offenen Umstellungen mit allen Zugaengen ab, die den Schluessel der Node brauchen:
// alle Hosts (auch die anderer Nodes und solche, fuer die diese Node nur Ersatz ist), auch deaktivierte Zugaenge.
// Offen bleibt, was nicht clusterweit als auf fp umgestellt gilt; geloeschte Zugaenge fallen weg.
func (m *Module) refreshKeyPending(ctx context.Context, fp string) error {
	m.cl.kdMu.Lock()
	d := m.keyDone(ctx)
	if d.FP != fp {
		d = keyDoneSet{FP: fp, UIDs: []string{}}
		if err := m.saveKeyDone(ctx, d); err != nil {
			m.cl.kdMu.Unlock()
			return err
		}
	}
	m.cl.kdMu.Unlock()
	done := map[string]bool{}
	for _, u := range d.UIDs {
		done[u] = true
	}
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return err
	}
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, h := range hosts {
		known[h.UID] = true
	}
	db := m.st.Writer()
	need := map[string]bool{}
	for _, a := range accs {
		if !known[a.HostUID] || !needsNodeKey(a) || done[a.UID] {
			continue
		}
		need[a.UID] = true
		if _, err := db.ExecContext(ctx, `INSERT INTO m64_keypending (access_uid, host_uid, type, target_fp, created_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT (access_uid) DO UPDATE SET host_uid = excluded.host_uid, type = excluded.type, target_fp = excluded.target_fp,
			tries = 0, last_try = '', error = '' WHERE m64_keypending.target_fp != excluded.target_fp OR m64_keypending.type != excluded.type`,
			a.UID, a.HostUID, a.Type, fp, tsNow()); err != nil {
			return err
		}
	}
	rows, err := db.QueryContext(ctx, `SELECT access_uid FROM m64_keypending`)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && !need[u] {
			gone = append(gone, u)
		}
	}
	rows.Close()
	for _, u := range gone {
		_, _ = db.ExecContext(ctx, `DELETE FROM m64_keypending WHERE access_uid = ?`, u)
	}
	return nil
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
	targetFP  string
}

func (m *Module) keyPendingList(ctx context.Context) []keyPending {
	rows, err := m.st.Reader().QueryContext(ctx, `SELECT k.access_uid, k.host_uid, COALESCE(h.name, ''), k.type, k.tries, k.last_try, k.error, k.target_fp
		FROM m64_keypending k LEFT JOIN m64_hosts h ON h.uid = k.host_uid ORDER BY h.name, k.access_uid`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []keyPending{}
	for rows.Next() {
		var p keyPending
		var last string
		if rows.Scan(&p.AccessUID, &p.HostUID, &p.HostName, &p.Type, &p.Tries, &last, &p.Error, &p.targetFP) == nil {
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
	m.startKeySwitch(ctx, false) // je Agent bis keySwitchLimit: nicht im Ablauf des Clusters
}

// startKeySwitch stellt die Agents im Hintergrund um (now: ohne Wartezeit). Laeuft schon ein Lauf, folgt ihm genau
// einer (mit now, wenn einer der Wuensche es wollte) - nie zwei zugleich, kein Stau.
func (m *Module) startKeySwitch(ctx context.Context, now bool) {
	m.cl.ksMu.Lock()
	if m.cl.ksRun {
		m.cl.ksAgain, m.cl.ksNow = true, m.cl.ksNow || now
		m.cl.ksMu.Unlock()
		return
	}
	m.cl.ksRun = true
	m.cl.ksMu.Unlock()
	m.cl.bg.Go(func() {
		for {
			m.switchAgents(ctx, now)
			m.cl.ksMu.Lock()
			if !m.cl.ksAgain || ctx.Err() != nil {
				m.cl.ksRun, m.cl.ksAgain, m.cl.ksNow = false, false, false
				m.cl.ksMu.Unlock()
				return
			}
			now = m.cl.ksNow
			m.cl.ksAgain, m.cl.ksNow = false, false
			m.cl.ksMu.Unlock()
		}
	})
}

// keySwitchRunning: ein Lauf im Hintergrund ist unterwegs (die Oberflaeche fragt dann erneut).
func (m *Module) keySwitchRunning() bool {
	m.cl.ksMu.Lock()
	defer m.cl.ksMu.Unlock()
	return m.cl.ksRun
}

// switchAgents stellt die Agents der Liste auf den aktuellen Schluessel um (now: ohne Wartezeit) und verwirft danach
// die alten Schluessel, wenn nichts mehr offen ist (Regel oben).
func (m *Module) switchAgents(ctx context.Context, now bool) {
	m.cl.ksLock.Lock()
	defer m.cl.ksLock.Unlock()
	signer, err := m.nodeSigner(ctx)
	if err != nil {
		return
	}
	line := transport.AuthorizedKeyLine(signer.PublicKey(), "node64@"+m.st.SettingOr(ctx, "node.name", "node"))
	fp := transport.Fingerprint(signer.PublicKey())
	if len(m.oldKeys(ctx)) > 0 { // nur waehrend eines Wechsels (sonst stellte die Node Agents ohne Anlass um)
		_ = m.refreshKeyPending(ctx, fp)
	}
	hosts, err := m.store.Hosts(ctx)
	if err != nil {
		return
	}
	accs, err := m.store.Accesses(ctx, "")
	if err != nil {
		return
	}
	hostOf := map[string]*Host{}
	for _, h := range hosts {
		hostOf[h.UID] = h
	}
	accOf := map[string]*Access{}
	for _, a := range accs {
		accOf[a.UID] = a
	}
	self := m.clusterSelf()
	var switched []string
	for _, p := range m.keyPendingList(ctx) {
		if ctx.Err() != nil {
			return
		}
		h, a := hostOf[p.HostUID], accOf[p.AccessUID]
		if p.Type != "agent" || h == nil || a == nil || !a.Enabled {
			continue // SSH: von Hand; deaktiviert: wartet (der alte Schluessel bleibt)
		}
		if ownerOf(h, self) != self && preferredOf(h, self) != self {
			continue // stellt die zustaendige bzw. bevorzugte Node um und meldet es im Cluster
		}
		if !now && !p.LastTry.IsZero() && time.Since(p.LastTry) < keyRetryEvery {
			continue
		}
		err := m.switchAgent(ctx, p, line)
		if err == nil {
			_, _ = m.st.Writer().ExecContext(ctx, `DELETE FROM m64_keypending WHERE access_uid = ? AND target_fp = ?`, p.AccessUID, p.targetFP)
			m.log.Info("monitor64: agent switched to the current node key", "host", p.HostName)
			if p.targetFP == fp {
				switched = append(switched, p.AccessUID)
			}
			continue
		}
		_, _ = m.st.Writer().ExecContext(ctx, `UPDATE m64_keypending SET tries = tries + 1, last_try = ?, error = ? WHERE access_uid = ?`,
			tsNow(), shortErr(err), p.AccessUID)
	}
	m.markKeyDone(ctx, fp, switched...)
	m.maybeRetireOldKeys(ctx, fp)
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

// maybeRetireOldKeys verwirft die alten Schluessel nach der Regel oben (fp: Schluessel zu Beginn des Laufs).
func (m *Module) maybeRetireOldKeys(ctx context.Context, fp string) {
	nodeKeyMu.Lock() // kein Schluesselwechsel dazwischen (useKey)
	if len(m.oldKeys(ctx)) == 0 || m.currentKeyFP(ctx) != fp || m.refreshKeyPending(ctx, fp) != nil {
		nodeKeyMu.Unlock()
		return
	}
	var open int
	if err := m.st.Reader().QueryRowContext(ctx, `SELECT COUNT(*) FROM m64_keypending`).Scan(&open); err != nil || open > 0 {
		nodeKeyMu.Unlock()
		return
	}
	err := m.st.SetSetting(ctx, setOldKeys, "[]")
	nodeKeyMu.Unlock()
	if err != nil {
		return
	}
	m.log.Info("monitor64: old node keys removed (all accesses switched)")
	m.cl.bg.Go(func() { m.reloadAllHosts(context.WithoutCancel(ctx)) })
}

// currentKeyFP: Fingerabdruck des gespeicherten Schluessels (ohne nodeKeyMu; "" = keiner bzw. nicht lesbar).
func (m *Module) currentKeyFP(ctx context.Context) string {
	pem, err := m.box.Decrypt(m.st.SettingOr(ctx, setNodeKey, ""))
	if err != nil {
		return ""
	}
	s, err := transport.ParseKey([]byte(pem))
	if err != nil {
		return ""
	}
	return transport.Fingerprint(s.PublicKey())
}

// retireOldKeys verwirft die alten Schluessel sofort (Knopf; nicht umgestellte Agents sind dann ausgesperrt).
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

// importKey uebernimmt den Schluessel aus einem Konfig-Import wie einen Wechsel (der bisherige bleibt unter den alten,
// die Agents werden umgestellt, der Cluster bekommt ihn mit Zeitpunkt jetzt). Ohne bisherigen Schluessel: einfach
// speichern.
func (m *Module) importKey(ctx context.Context, pem string) error {
	signer, err := transport.ParseKey([]byte(pem))
	if err != nil {
		return err
	}
	if m.st.SettingOr(ctx, setNodeKey, "") == "" {
		nodeKeyMu.Lock()
		defer nodeKeyMu.Unlock()
		return m.st.SetSetting(ctx, setNodeKey, m.box.Encrypt(pem))
	}
	if m.currentKeyFP(ctx) == transport.Fingerprint(signer.PublicKey()) {
		return nil
	}
	return m.useKey(ctx, pem, signer, time.Now(), true)
}

// ClusterJoined: diese Node ist einem Cluster beigetreten (peer.Joiner) - sie uebernimmt den Schluessel des Clusters,
// statt ihren einzubringen. Den Eintrag eines Cluster-Schluessels aus einem frueheren Cluster verwirft sie (sonst
// gewaenne sein juengerer Stand und der ganze Cluster wechselte auf ihn): ihr Stand im Protokoll wird zum Vermerk, den
// peer gleich wieder herausnimmt (forget). Der Schluessel selbst bleibt aktuell, bis der des Clusters kommt, und dann
// unter den alten (ihre Agents werden umgestellt).
func (m *Module) ClusterJoined(ctx context.Context) []string {
	_ = m.st.SetSetting(ctx, setKeyJoined, "1")
	if m.st.SettingOr(ctx, setKeyCluster, "") == "" {
		return nil
	}
	_ = m.st.SetSetting(ctx, setKeyCluster, "")
	_ = m.st.SetSetting(ctx, setKeyDone, "")
	m.clusterChange(ctx, ClusterItemConfig, "key:cluster", true)
	return []string{ClusterItemConfig + "/key:cluster"}
}

// keyInfo ist der Stand der Schluessel fuer die Oberflaeche.
type keyInfo struct {
	Fingerprint   string       `json:"fingerprint"`
	AuthorizedKey string       `json:"authorized_key"` // Zeile fuer authorized_keys bzw. den Installationsbefehl
	Cluster       bool         `json:"cluster"`        // gemeinsamer Cluster-Schluessel
	At            time.Time    `json:"at,omitzero"`
	OldKeys       []string     `json:"old_keys"` // Fingerabdruecke der alten, noch angebotenen Schluessel
	Pending       []keyPending `json:"pending"`
	Running       bool         `json:"running"` // Umstellung laeuft gerade im Hintergrund (Stand erneut abfragen)
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
		Pending:       m.keyPendingList(ctx), Running: m.keySwitchRunning()}
	for _, o := range extra {
		out.OldKeys = append(out.OldKeys, transport.Fingerprint(o.PublicKey()))
	}
	return out, nil
}
