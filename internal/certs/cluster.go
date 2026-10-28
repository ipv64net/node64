package certs

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/fnv"
	"maps"
	"net/url"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/store"
)

// Cluster: Abgleich der Zertifikatsverwaltung zwischen Nodes. Die Verwaltung ist ein Provider fuer den Cluster
// (internal/peer, verbunden ueber certs/certcluster, damit certs nicht von peer abhaengt). Je Bereich: Zertifikate
// mit Schluessel, ACME-Stellen mit EAB samt dem ACME-Konto der Node, DNS-Zugaenge und eigene CAs. Geheimes geht
// entschluesselt ueber die Leitung (HTTPS, an die Kopplung gebunden) und wird hier mit dem eigenen Schluessel neu
// verschluesselt. Eintraege heissen ueberall gleich (uid); Verweise eines Zertifikats laufen ueber die uid des Ziels.
// Fehlt das Ziel hier (Bereich aus), kommt das Zertifikat trotzdem, der Verweis bleibt leer und es wird hier nicht
// erneuert.
//
// Erneuerung: es erneuert die Node, die das Zertifikat zuletzt ausgestellt hat (renewer, '' = diese Node). Eine
// andere Node uebernimmt erst, wenn das Zertifikat ein Drittel der Erneuerungsfrist vor Ablauf noch immer nicht
// erneuert ist (Let's Encrypt: 10 statt 30 Tage) - dann hat die zustaendige Node es offensichtlich nicht geschafft,
// gleich ob sie aus ist, nicht erreichbar oder ihr etwas fehlt. Dazu braucht es keinen Blick auf den Cluster. Damit
// nicht alle gleichzeitig uebernehmen, ist die Schwelle je Node um bis zu 1/30 der Frist versetzt. Wer ausstellt,
// wird zustaendig; die Aenderung verteilt sich.

// Kennungen fuer den Cluster.
const (
	ClusterModuleID = "certs"
	ClusterTitleKey = "cluster.mod.certs"

	ItemCertificates = "certificates"
	ItemACME         = "acme"
	ItemDNSAccounts  = "dns_accounts"
	ItemCAs          = "cas"

	clusterAccount = "account" // ACME-Konto der Node (Schluessel, Mail, Nutzungsbedingungen) im Bereich acme
)

// ClusterItem ist ein abgleichbarer Bereich.
type ClusterItem struct{ ID, TitleKey string }

// ClusterItems: Bereiche der Zertifikatsverwaltung (alle ohne Einstellung aus).
func ClusterItems() []ClusterItem {
	return []ClusterItem{
		{ItemCertificates, "cluster.item.certificates"},
		{ItemACME, "cluster.item.acme"},
		{ItemDNSAccounts, "cluster.item.dns_accounts"},
		{ItemCAs, "cluster.item.cas"},
	}
}

var itemTables = map[string]string{ItemCertificates: "certs", ItemACME: "cert_acme_cas", ItemDNSAccounts: "cert_dns_accounts", ItemCAs: "cert_cas"}

// ErrClusterItem: Bereich gibt es nicht.
var ErrClusterItem = errors.New("unknown cluster item")

// ClusterHook meldet eine Aenderung an den Cluster (peer.Manager.ClusterChange fuer das Modul certs).
type ClusterHook func(ctx context.Context, item, uid string, deleted bool)

// SetCluster verbindet die Verwaltung mit dem Cluster: self liefert die Kennung dieser Node, hook nimmt Aenderungen
// entgegen (auch bei Uebernahmen; die Herkunft steht dann in ctx und wertet der Cluster aus).
func (m *Manager) SetCluster(self func() string, hook ClusterHook) {
	m.mu.Lock()
	m.clSelf, m.clHook = self, hook
	m.mu.Unlock()
}

func (m *Manager) selfID() string {
	m.mu.Lock()
	f := m.clSelf
	m.mu.Unlock()
	if f == nil {
		return ""
	}
	return f()
}

func (m *Manager) hook() ClusterHook {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.clHook
}

// changedUID meldet eine Aenderung an den Cluster (ohne Cluster: nichts).
func (m *Manager) changedUID(ctx context.Context, item, uid string, deleted bool) {
	if h := m.hook(); h != nil && uid != "" {
		h(ctx, item, uid, deleted)
	}
}

// changed meldet einen geschriebenen Eintrag (lokale ID). Zertifikate, die ein Modul fuer sich haelt (EnsureIssued,
// z. B. DNS64 mit den IPs dieser Node), bleiben auf der Node.
func (m *Manager) changed(ctx context.Context, item string, id int64) {
	if m.hook() == nil {
		return
	}
	if item == ItemCertificates && m.ownedIDs(ctx)[id] {
		return
	}
	m.changedUID(ctx, item, m.uidOf(ctx, itemTables[item], id), false)
}

// deleting liefert vor dem Loeschen die uid fuer die Meldung danach ("" = nicht melden).
func (m *Manager) deleting(ctx context.Context, item string, id int64) string {
	if m.hook() == nil || (item == ItemCertificates && m.ownedIDs(ctx)[id]) {
		return ""
	}
	return m.uidOf(ctx, itemTables[item], id)
}

func (m *Manager) uidOf(ctx context.Context, table string, id int64) string {
	var uid string
	if id != 0 {
		_ = m.r.QueryRowContext(ctx, `SELECT uid FROM `+table+` WHERE id = ?`, id).Scan(&uid)
	}
	return uid
}

func (m *Manager) idOfDirectory(ctx context.Context, dir string) int64 {
	var id int64
	_ = m.r.QueryRowContext(ctx, `SELECT id FROM cert_acme_cas WHERE directory = ?`, dir).Scan(&id)
	return id
}

func (m *Manager) idOf(ctx context.Context, table, uid string) int64 {
	var id int64
	if uid != "" {
		_ = m.r.QueryRowContext(ctx, `SELECT id FROM `+table+` WHERE uid = ?`, uid).Scan(&id)
	}
	return id
}

// CertUID: stabile Kennung eines Zertifikats ("" = unbekannt), fuer Module, die Zertifikate ueber den Cluster
// verweisen.
func (m *Manager) CertUID(ctx context.Context, id int64) string { return m.uidOf(ctx, "certs", id) }

// CertIDByUID: lokale ID zur Kennung (0 = hier nicht vorhanden).
func (m *Manager) CertIDByUID(ctx context.Context, uid string) int64 {
	return m.idOf(ctx, "certs", uid)
}

// ownedIDs: Zertifikate, die ein Modul fuer sich haelt (EnsureIssued).
func (m *Manager) ownedIDs(ctx context.Context) map[int64]bool {
	out := map[int64]bool{}
	rows, err := m.r.QueryContext(ctx, `SELECT value FROM settings WHERE key LIKE 'certs.owned.%'`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		var id int64
		if rows.Scan(&v) == nil {
			if _, err := fmt.Sscan(v, &id); err == nil {
				out[id] = true
			}
		}
	}
	return out
}

// ---------------------------------------------------------------- Erneuerung im Cluster

// renewHere: erneuert diese Node das Zertifikat (sonst die zustaendige andere Node)?
func (m *Manager) renewHere(ctx context.Context, c *Cert) bool {
	if c.RefMissing {
		return false // ACME-Stelle, DNS-Zugang oder CA fehlt hier
	}
	if c.RenewedBy == "" {
		return true
	}
	if !c.hasCert { // die zustaendige Node holt es gerade
		return false
	}
	return time.Until(c.NotAfter) < takeoverBefore(c, m.selfID()) && m.canIssue(ctx, c)
}

// takeoverBefore: ab wann vor Ablauf eine andere Node die Erneuerung uebernimmt (ein Drittel der Frist, je Node
// um bis zu 1/30 der Frist frueher oder spaeter, damit nicht alle zugleich bestellen).
func takeoverBefore(c *Cert, self string) time.Duration {
	before := renewBefore
	if c.Source == SourceCA || c.Source == SourceSelf {
		before = caRenewBefore(c.Days)
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(self))
	return before/3 - time.Duration(float64(before/30)*float64(h.Sum32()%1000)/1000)
}

// canIssue: hat diese Node alles fuer eine Ausstellung (sonst stuende nur ein Fehler bei allen)?
func (m *Manager) canIssue(ctx context.Context, c *Cert) bool {
	switch c.Source {
	case SourceSelf:
		return true
	case SourceCA:
		return c.CAID != 0
	case SourceIPv64, SourceAlias:
		if !m.DNSReady(ctx) {
			return false
		}
	case SourceHTTP:
		if m.d.HTTP == nil {
			return false
		}
	case SourceDNS:
		if c.DNSAccount == 0 {
			return false
		}
	default:
		return false
	}
	return c.ACMECA != 0 || m.Account(ctx).TOSAccepted
}

// ---------------------------------------------------------------- Provider

// ClusterIDs: alle Eintraege eines Bereichs.
func (m *Manager) ClusterIDs(ctx context.Context, item string) ([]string, error) {
	table, ok := itemTables[item]
	if !ok {
		return nil, ErrClusterItem
	}
	var owned map[int64]bool
	if item == ItemCertificates {
		owned = m.ownedIDs(ctx)
	}
	rows, err := m.r.QueryContext(ctx, `SELECT id, uid FROM `+table+` WHERE uid != '' ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id int64
		var uid string
		if err := rows.Scan(&id, &uid); err != nil {
			return nil, err
		}
		if !owned[id] {
			out = append(out, uid)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if item == ItemACME && m.d.Store.SettingOr(ctx, setKey, "") != "" {
		out = append(out, clusterAccount)
	}
	return out, nil
}

// Daten je Bereich (Geheimes entschluesselt).
type clusterCert struct {
	Names       []string `json:"names"`
	Source      string   `json:"source"`
	AliasZone   string   `json:"alias_zone,omitempty"`
	AliasPrefix string   `json:"alias_prefix,omitempty"`
	DNSAccount  string   `json:"dns_account,omitempty"` // uid
	CA          string   `json:"ca,omitempty"`          // uid
	ACMECA      string   `json:"acme_ca,omitempty"`     // uid, leer = Let's Encrypt
	Days        int      `json:"days,omitempty"`
	KeyType     string   `json:"key_type,omitempty"`
	Staging     bool     `json:"staging"`
	AutoRenew   bool     `json:"auto_renew"`
	CertPEM     string   `json:"cert_pem,omitempty"`
	KeyPEM      string   `json:"key_pem,omitempty"`
	NotBefore   string   `json:"not_before,omitempty"`
	NotAfter    string   `json:"not_after,omitempty"`
	Issuer      string   `json:"issuer,omitempty"`
	Status      string   `json:"status"`
	LastError   string   `json:"last_error,omitempty"`
	LastAttempt string   `json:"last_attempt,omitempty"`
	RenewedBy   string   `json:"renewed_by"` // Node, die erneuert
	CreatedAt   string   `json:"created_at"`
}

type clusterACME struct {
	Name      string `json:"name"`
	Directory string `json:"directory"`
	EABKID    string `json:"eab_kid,omitempty"`
	EABHMAC   string `json:"eab_hmac,omitempty"`
	RootPEM   string `json:"root_pem,omitempty"`
	CreatedAt string `json:"created_at"`
}

type clusterDNS struct {
	Name      string `json:"name"`
	Provider  string `json:"provider"`
	Config    string `json:"config"` // Felder als JSON
	CreatedAt string `json:"created_at"`
}

type clusterCA struct {
	Name      string `json:"name"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	Imported  bool   `json:"imported"`
	CreatedAt string `json:"created_at"`
}

// ClusterGet: aktueller Stand eines Eintrags.
func (m *Manager) ClusterGet(ctx context.Context, item, uid string) (json.RawMessage, bool, error) {
	var v any
	var err error
	switch item {
	case ItemCertificates:
		c, e := m.clusterGetCert(ctx, uid)
		if c == nil && e == nil {
			return nil, false, nil // haelt ein Modul fuer sich
		}
		v, err = c, e
	case ItemACME:
		v, err = m.clusterGetACME(ctx, uid)
	case ItemDNSAccounts:
		var d clusterDNS
		var sealed string
		err = m.r.QueryRowContext(ctx, `SELECT name, provider, config, created_at FROM cert_dns_accounts WHERE uid = ?`, uid).Scan(&d.Name, &d.Provider, &sealed, &d.CreatedAt)
		if err == nil && sealed != "" {
			d.Config, err = m.d.Box.Decrypt(sealed)
		}
		v = &d
	case ItemCAs:
		var c clusterCA
		var sealed string
		err = m.r.QueryRowContext(ctx, `SELECT name, cert_pem, key_pem, imported, created_at FROM cert_cas WHERE uid = ?`, uid).Scan(&c.Name, &c.CertPEM, &sealed, &c.Imported, &c.CreatedAt)
		if err == nil {
			c.KeyPEM, err = m.d.Box.Decrypt(sealed)
		}
		v = &c
	default:
		return nil, false, ErrClusterItem
	}
	if errors.Is(err, sql.ErrNoRows) || (err == nil && v == nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	b, err := json.Marshal(v)
	return b, err == nil, err
}

func (m *Manager) clusterGetCert(ctx context.Context, uid string) (*clusterCert, error) {
	var c clusterCert
	var id, dns, ca, acmeCA int64
	var names, refDNS, refCA, refACME, sealed, renewer string
	err := m.r.QueryRowContext(ctx, `SELECT id, names, source, alias_zone, alias_prefix, dns_account, ca_id, acme_ca, ref_dns_account, ref_ca, ref_acme_ca, days,
		key_type, staging, auto_renew, cert_pem, key_pem, not_before, not_after, issuer, status, last_error, last_attempt, renewer, created_at FROM certs WHERE uid = ?`, uid).Scan(
		&id, &names, &c.Source, &c.AliasZone, &c.AliasPrefix, &dns, &ca, &acmeCA, &refDNS, &refCA, &refACME, &c.Days, &c.KeyType, &c.Staging, &c.AutoRenew,
		&c.CertPEM, &sealed, &c.NotBefore, &c.NotAfter, &c.Issuer, &c.Status, &c.LastError, &c.LastAttempt, &renewer, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	c.LastError = notify.RedactSecrets(c.LastError)
	if m.ownedIDs(ctx)[id] {
		return nil, nil
	}
	c.Names = strings.Split(names, ",")
	if sealed != "" {
		if c.KeyPEM, err = m.d.Box.Decrypt(sealed); err != nil {
			return nil, err
		}
	}
	ref := func(table string, id int64, stored string) string {
		if u := m.uidOf(ctx, table, id); u != "" {
			return u
		}
		return stored // Ziel fehlt hier: Verweis der anderen Node weitergeben
	}
	c.DNSAccount, c.CA, c.ACMECA = ref("cert_dns_accounts", dns, refDNS), ref("cert_cas", ca, refCA), ref("cert_acme_cas", acmeCA, refACME)
	c.RenewedBy = renewer
	if c.RenewedBy == "" {
		c.RenewedBy = m.selfID()
	}
	if c.RenewedBy == "" {
		c.RenewedBy = "unknown" // nie leer: leer hiesse beim Empfaenger "diese Node"
	}
	return &c, nil
}

func (m *Manager) clusterGetACME(ctx context.Context, uid string) (any, error) {
	if uid == clusterAccount {
		a, _, err := m.ownAccount(ctx)
		if a == nil || err != nil {
			return nil, err
		}
		return a, nil
	}
	var a clusterACME
	var sealed string
	err := m.r.QueryRowContext(ctx, `SELECT name, directory, eab_kid, eab_hmac, root_pem, created_at FROM cert_acme_cas WHERE uid = ?`, uid).Scan(
		&a.Name, &a.Directory, &a.EABKID, &sealed, &a.RootPEM, &a.CreatedAt)
	if err == nil && sealed != "" {
		a.EABHMAC, err = m.d.Box.Decrypt(sealed)
	}
	return &a, err
}

// ClusterApply uebernimmt einen Eintrag einer anderen Node (deleted: loeschen).
func (m *Manager) ClusterApply(ctx context.Context, item, uid string, data json.RawMessage, deleted bool) error {
	if uid == "" || len(uid) > 64 {
		return invalid("uid", "invalid")
	}
	switch item {
	case ItemCertificates:
		if deleted {
			return m.clusterDeleteCert(ctx, uid)
		}
		return m.clusterApplyCert(ctx, uid, data)
	case ItemACME:
		if uid == clusterAccount {
			if deleted {
				return nil // das Konto bleibt
			}
			return m.clusterApplyAccount(ctx, data)
		}
		if deleted {
			return m.clusterDeleteRef(ctx, item, uid, "acme_ca", "ref_acme_ca")
		}
		return m.clusterApplyACME(ctx, uid, data)
	case ItemDNSAccounts:
		if deleted {
			return m.clusterDeleteRef(ctx, item, uid, "dns_account", "ref_dns_account")
		}
		return m.clusterApplyDNS(ctx, uid, data)
	case ItemCAs:
		if deleted {
			return m.clusterDeleteRef(ctx, item, uid, "ca_id", "ref_ca")
		}
		return m.clusterApplyCA(ctx, uid, data)
	}
	return ErrClusterItem
}

// match sucht den Eintrag zur uid, sonst einen genau gleichen Eintrag unter anderer uid: query liefert id, uid
// der Kandidaten, same prueft jeden (nur genau Gleiches wird zusammengefuehrt, Aehnliches mit gleichem Namen bleibt
// getrennt). Damit beide Seiten dieselbe uid bekommen, gilt die kleinere: ist die fremde kleiner, uebernimmt der
// Eintrag hier sie (Zertifikate, die darauf verweisen, gehen neu hinaus), sonst bleibt alles und keep ist true mit der
// id des Eintrags hier (die andere Node uebernimmt unsere uid, sobald sie sie bekommt).
func (m *Manager) match(ctx context.Context, table, uid, refCol, query string, same func(id int64) bool, args ...any) (id int64, keep bool, err error) {
	if id = m.idOf(ctx, table, uid); id != 0 || query == "" {
		return id, false, nil
	}
	rows, err := m.r.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, false, err
	}
	type cand struct {
		id  int64
		uid string
	}
	var list []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.uid); err != nil {
			rows.Close()
			return 0, false, err
		}
		list = append(list, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, false, err
	}
	var local string
	for _, c := range list { // mehrere gleiche hier: die kleinste uid (auf allen Nodes dieselbe Wahl)
		if c.uid != "" && (local == "" || c.uid < local) && same(c.id) {
			id, local = c.id, c.uid
		}
	}
	if id == 0 {
		return 0, false, nil
	}
	if uid >= local {
		m.addAlias(ctx, table, uid, local)
		return id, true, nil
	}
	if _, err := m.w.ExecContext(ctx, `UPDATE `+table+` SET uid = ? WHERE id = ?`, uid, id); err != nil {
		return 0, false, err
	}
	m.addAlias(ctx, table, local, uid)
	if refCol != "" {
		m.refsChanged(ctx, refCol, id)
	}
	return id, false, nil
}

const setAlias = "certs.cluster_alias" // zusammengefuehrte uids je Tabelle: {"tabelle": {"alt": "neu"}}

// addAlias merkt sich eine zusammengefuehrte uid: Verweise anderer Nodes auf die alte (z. B. von einer dritten Node,
// die noch nicht umgestellt hat) zeigen so auf den verbliebenen Eintrag. Loeschen geht nie ueber einen Alias.
func (m *Manager) addAlias(ctx context.Context, table, old, cur string) {
	m.aliasMu.Lock()
	defer m.aliasMu.Unlock()
	al := map[string]map[string]string{}
	_ = json.Unmarshal([]byte(m.d.Store.SettingOr(ctx, setAlias, "{}")), &al)
	if al[table] == nil {
		al[table] = map[string]string{}
	}
	if al[table][old] == cur {
		return
	}
	al[table][old] = cur
	if b, err := json.Marshal(al); err == nil {
		_ = m.d.Store.SetSetting(ctx, setAlias, string(b))
	}
}

// refID: lokale ID des Verweisziels, auch ueber eine zusammengefuehrte uid (0 = hier nicht vorhanden).
func (m *Manager) refID(ctx context.Context, table, uid string) int64 {
	if id := m.idOf(ctx, table, uid); id != 0 || uid == "" {
		return id
	}
	al := map[string]map[string]string{}
	_ = json.Unmarshal([]byte(m.d.Store.SettingOr(ctx, setAlias, "{}")), &al)
	for i := 0; i < 5 && al[table][uid] != ""; i++ { // auch mehrfach zusammengefuehrt
		uid = al[table][uid]
		if id := m.idOf(ctx, table, uid); id != 0 {
			return id
		}
	}
	return 0
}

// leafFingerprint: SHA-256 des ersten Zertifikats im PEM ("" = keins).
func leafFingerprint(certPEM string) string {
	rest := []byte(certPEM)
	for {
		var b *pem.Block
		if b, rest = pem.Decode(rest); b == nil {
			return ""
		}
		if b.Type == "CERTIFICATE" {
			sum := sha256.Sum256(b.Bytes)
			return hex.EncodeToString(sum[:])
		}
	}
}

// sameCertKey: der Eintrag (certs oder cert_cas) hat dasselbe Zertifikat (Fingerabdruck) und denselben privaten
// Schluessel.
func (m *Manager) sameCertKey(ctx context.Context, table string, id int64, fp string, key crypto.PrivateKey) bool {
	var certPEM, sealed string
	if m.r.QueryRowContext(ctx, `SELECT cert_pem, key_pem FROM `+table+` WHERE id = ?`, id).Scan(&certPEM, &sealed) != nil || sealed == "" || fp == "" || leafFingerprint(certPEM) != fp {
		return false
	}
	raw, err := m.d.Box.Decrypt(sealed)
	if err != nil {
		return false
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(raw))
	if err != nil {
		return false
	}
	k, ok := pair.PrivateKey.(interface{ Equal(crypto.PrivateKey) bool })
	return ok && k.Equal(key)
}

// refsChanged meldet die Zertifikate, die auf einen Eintrag verweisen (dessen uid sich geaendert hat).
func (m *Manager) refsChanged(ctx context.Context, col string, id int64) {
	if m.hook() == nil {
		return
	}
	rows, err := m.r.QueryContext(ctx, `SELECT id FROM certs WHERE `+col+` = ?`, id)
	if err != nil {
		return
	}
	var ids []int64
	for rows.Next() {
		var c int64
		if rows.Scan(&c) == nil {
			ids = append(ids, c)
		}
	}
	rows.Close()
	for _, c := range ids {
		m.changed(ctx, ItemCertificates, c)
	}
}

func (m *Manager) clusterApplyCert(ctx context.Context, uid string, data json.RawMessage) error {
	var in clusterCert
	if err := json.Unmarshal(data, &in); err != nil {
		return invalid("data", "%v", err)
	}
	switch in.Source {
	case SourceIPv64, SourceAlias, SourceHTTP, SourceDNS, SourceUpload, SourceCA, SourceSelf:
	default:
		return invalid("source", "unknown source %q", in.Source)
	}
	if len(in.Names) == 0 || len(in.Names) > maxNames {
		return invalid("names", "1 to %d names", maxNames)
	}
	var fp string
	var key crypto.PrivateKey
	if in.CertPEM != "" {
		pair, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
		if err != nil {
			return invalid("cert", "certificate and key do not fit: %v", err)
		}
		fp, key = leafFingerprint(in.CertPEM), pair.PrivateKey
	}
	query := ""
	if fp != "" { // gleich = dasselbe Zertifikat mit demselben Schluessel (nicht nur dieselben Namen)
		query = `SELECT id, uid FROM certs WHERE cert_pem != ''`
	}
	owned := m.ownedIDs(ctx)
	id, keep, err := m.match(ctx, "certs", uid, "", query, func(id int64) bool { return !owned[id] && m.sameCertKey(ctx, "certs", id, fp, key) })
	if err != nil || keep {
		return err
	}
	if id != 0 && m.ownedIDs(ctx)[id] {
		return nil
	}
	renewer := in.RenewedBy
	if renewer == m.selfID() {
		renewer = ""
	} else if renewer == "" {
		renewer = "unknown"
	}
	dns, ca, acmeCA := m.refID(ctx, "cert_dns_accounts", in.DNSAccount), m.refID(ctx, "cert_cas", in.CA), m.refID(ctx, "cert_acme_cas", in.ACMECA)
	sealed := ""
	if in.KeyPEM != "" {
		sealed = m.d.Box.Encrypt(in.KeyPEM)
	}
	now := store.Now()
	if in.CreatedAt == "" {
		in.CreatedAt = now
	}
	var prev string
	newCert := true
	if id != 0 {
		_ = m.r.QueryRowContext(ctx, `SELECT cert_pem FROM certs WHERE id = ?`, id).Scan(&prev)
		newCert = prev != in.CertPEM
		_, err = m.w.ExecContext(ctx, `UPDATE certs SET names = ?, source = ?, alias_zone = ?, alias_prefix = ?, dns_account = ?, ca_id = ?, acme_ca = ?, ref_dns_account = ?,
			ref_ca = ?, ref_acme_ca = ?, days = ?, key_type = ?, staging = ?, auto_renew = ?, cert_pem = ?, key_pem = ?, not_before = ?, not_after = ?, issuer = ?,
			status = ?, last_error = ?, last_attempt = ?, renewer = ?, warned = CASE WHEN cert_pem = ? THEN warned ELSE '' END, updated_at = ? WHERE id = ?`,
			strings.Join(in.Names, ","), in.Source, in.AliasZone, in.AliasPrefix, dns, ca, acmeCA, in.DNSAccount, in.CA, in.ACMECA, in.Days, in.KeyType, in.Staging,
			in.AutoRenew, in.CertPEM, sealed, in.NotBefore, in.NotAfter, in.Issuer, in.Status, notify.RedactSecrets(in.LastError), in.LastAttempt, renewer, in.CertPEM, now, id)
	} else {
		var res sql.Result
		res, err = m.w.ExecContext(ctx, `INSERT INTO certs (uid, names, source, alias_zone, alias_prefix, dns_account, ca_id, acme_ca, ref_dns_account, ref_ca, ref_acme_ca,
			days, key_type, staging, auto_renew, cert_pem, key_pem, not_before, not_after, issuer, status, last_error, last_attempt, renewer, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, uid, strings.Join(in.Names, ","), in.Source, in.AliasZone, in.AliasPrefix,
			dns, ca, acmeCA, in.DNSAccount, in.CA, in.ACMECA, in.Days, in.KeyType, in.Staging, in.AutoRenew, in.CertPEM, sealed, in.NotBefore, in.NotAfter, in.Issuer,
			in.Status, notify.RedactSecrets(in.LastError), in.LastAttempt, renewer, in.CreatedAt, now)
		if err == nil {
			id, _ = res.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	if err := m.reload(ctx); err != nil {
		return err
	}
	m.refreshHold(ctx)
	if newCert && in.CertPEM != "" {
		m.issued(id)
	}
	m.changedUID(ctx, ItemCertificates, uid, false)
	return nil
}

func (m *Manager) clusterDeleteCert(ctx context.Context, uid string) error {
	id := m.idOf(ctx, "certs", uid)
	if id == 0 || m.ownedIDs(ctx)[id] {
		return nil
	}
	if used := m.usedBy(ctx)[id]; len(used) > 0 {
		m.log.Warn("certificate deleted by another cluster node is in use here", "cert", id, "used_by", strings.Join(used, ","))
	}
	if _, err := m.w.ExecContext(ctx, `DELETE FROM certs WHERE id = ?`, id); err != nil {
		return err
	}
	m.unload(id)
	m.refreshHold(ctx)
	m.changedUID(ctx, ItemCertificates, uid, true)
	return nil
}

// clusterDeleteRef loescht einen Eintrag, auf den Zertifikate verweisen koennen: deren Verweis wird leer (mit der
// uid in ref_*), damit sie hier nicht mehr erneuert werden.
func (m *Manager) clusterDeleteRef(ctx context.Context, item, uid, col, refCol string) error {
	table := itemTables[item]
	id := m.idOf(ctx, table, uid)
	if id == 0 {
		return nil
	}
	var dir string
	if item == ItemACME {
		_ = m.r.QueryRowContext(ctx, `SELECT directory FROM cert_acme_cas WHERE id = ?`, id).Scan(&dir)
	}
	if _, err := m.w.ExecContext(ctx, `UPDATE certs SET `+col+` = 0, `+refCol+` = ? WHERE `+col+` = ?`, uid, id); err != nil {
		return err
	}
	if _, err := m.w.ExecContext(ctx, `DELETE FROM `+table+` WHERE id = ?`, id); err != nil {
		return err
	}
	if dir != "" {
		m.mu.Lock()
		delete(m.reg, dir)
		m.mu.Unlock()
	}
	m.changedUID(ctx, item, uid, true)
	return nil
}

// resolveRefs: Zertifikate, die auf die uid warten, zeigen jetzt auf den Eintrag.
func (m *Manager) resolveRefs(ctx context.Context, col, refCol, uid string, id int64) error {
	_, err := m.w.ExecContext(ctx, `UPDATE certs SET `+col+` = ? WHERE `+col+` = 0 AND `+refCol+` = ?`, id, uid)
	return err
}

func (m *Manager) clusterApplyACME(ctx context.Context, uid string, data json.RawMessage) error {
	var in clusterACME
	if err := json.Unmarshal(data, &in); err != nil {
		return invalid("data", "%v", err)
	}
	u, err := url.Parse(in.Directory)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || strings.TrimSpace(in.Name) == "" {
		return invalid("directory", "invalid")
	}
	// gleich = dasselbe Verzeichnis mit demselben EAB (oder beide ohne)
	id, keep, err := m.match(ctx, "cert_acme_cas", uid, "acme_ca", `SELECT id, uid FROM cert_acme_cas WHERE directory = ?`, func(id int64) bool {
		var kid, sealed, hmac string
		if m.r.QueryRowContext(ctx, `SELECT eab_kid, eab_hmac FROM cert_acme_cas WHERE id = ?`, id).Scan(&kid, &sealed) != nil || kid != in.EABKID {
			return false
		}
		if sealed != "" {
			var err error
			if hmac, err = m.d.Box.Decrypt(sealed); err != nil {
				return false
			}
		}
		return hmac == in.EABHMAC
	}, in.Directory)
	if err != nil {
		return err
	}
	if keep {
		return m.resolveRefs(ctx, "acme_ca", "ref_acme_ca", uid, id)
	}
	if id == 0 && m.idOfDirectory(ctx, in.Directory) != 0 {
		// dasselbe Verzeichnis mit anderem EAB: nicht zusammenfuehren (das Verzeichnis gibt es je Node nur einmal),
		// Zertifikate mit dieser Stelle erneuert hier keiner
		return invalid("directory", "this CA exists here with a different EAB, not merged")
	}
	sealed := ""
	if in.EABHMAC != "" {
		sealed = m.d.Box.Encrypt(in.EABHMAC)
	}
	if in.CreatedAt == "" {
		in.CreatedAt = store.Now()
	}
	var old string
	if id != 0 {
		_ = m.r.QueryRowContext(ctx, `SELECT directory FROM cert_acme_cas WHERE id = ?`, id).Scan(&old)
		_, err = m.w.ExecContext(ctx, `UPDATE cert_acme_cas SET name = ?, directory = ?, eab_kid = ?, eab_hmac = ?, root_pem = ? WHERE id = ?`,
			in.Name, in.Directory, in.EABKID, sealed, in.RootPEM, id)
	} else {
		var res sql.Result
		res, err = m.w.ExecContext(ctx, `INSERT INTO cert_acme_cas (uid, name, directory, eab_kid, eab_hmac, root_pem, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			uid, in.Name, in.Directory, in.EABKID, sealed, in.RootPEM, in.CreatedAt)
		if err == nil {
			id, _ = res.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.reg, old)
	delete(m.reg, in.Directory)
	m.mu.Unlock()
	if err := m.resolveRefs(ctx, "acme_ca", "ref_acme_ca", uid, id); err != nil {
		return err
	}
	m.changedUID(ctx, ItemACME, uid, false)
	return nil
}

func (m *Manager) clusterApplyDNS(ctx context.Context, uid string, data json.RawMessage) error {
	var in clusterDNS
	if err := json.Unmarshal(data, &in); err != nil {
		return invalid("data", "%v", err)
	}
	if _, ok := providers[in.Provider]; !ok || strings.TrimSpace(in.Name) == "" {
		return invalid("provider", "unknown provider %q", in.Provider)
	}
	var vals map[string]string
	if in.Config != "" {
		if err := json.Unmarshal([]byte(in.Config), &vals); err != nil {
			return invalid("config", "%v", err)
		}
	}
	// gleich = derselbe Anbieter mit denselben Zugangsdaten (der Name zaehlt nicht)
	id, keep, err := m.match(ctx, "cert_dns_accounts", uid, "dns_account", `SELECT id, uid FROM cert_dns_accounts WHERE provider = ?`, func(id int64) bool {
		var sealed string
		if m.r.QueryRowContext(ctx, `SELECT config FROM cert_dns_accounts WHERE id = ?`, id).Scan(&sealed) != nil {
			return false
		}
		var local map[string]string
		if sealed != "" {
			raw, err := m.d.Box.Decrypt(sealed)
			if err != nil || json.Unmarshal([]byte(raw), &local) != nil {
				return false
			}
		}
		return maps.Equal(local, vals)
	}, in.Provider)
	if err != nil {
		return err
	}
	if keep {
		return m.resolveRefs(ctx, "dns_account", "ref_dns_account", uid, id)
	}
	sealed := ""
	if in.Config != "" {
		sealed = m.d.Box.Encrypt(in.Config)
	}
	now := store.Now()
	if in.CreatedAt == "" {
		in.CreatedAt = now
	}
	if id != 0 {
		_, err = m.w.ExecContext(ctx, `UPDATE cert_dns_accounts SET name = ?, provider = ?, config = ?, updated_at = ? WHERE id = ?`, in.Name, in.Provider, sealed, now, id)
	} else {
		var res sql.Result
		res, err = m.w.ExecContext(ctx, `INSERT INTO cert_dns_accounts (uid, name, provider, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
			uid, in.Name, in.Provider, sealed, in.CreatedAt, now)
		if err == nil {
			id, _ = res.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	if err := m.resolveRefs(ctx, "dns_account", "ref_dns_account", uid, id); err != nil {
		return err
	}
	m.changedUID(ctx, ItemDNSAccounts, uid, false)
	return nil
}

func (m *Manager) clusterApplyCA(ctx context.Context, uid string, data json.RawMessage) error {
	var in clusterCA
	if err := json.Unmarshal(data, &in); err != nil {
		return invalid("data", "%v", err)
	}
	if strings.TrimSpace(in.Name) == "" {
		return invalid("name", "required")
	}
	pair, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
	if err != nil {
		return invalid("cert", "CA certificate and key do not fit: %v", err)
	}
	// gleich = dasselbe CA-Zertifikat mit demselben Schluessel
	fp := leafFingerprint(in.CertPEM)
	id, keep, err := m.match(ctx, "cert_cas", uid, "ca_id", `SELECT id, uid FROM cert_cas`, func(id int64) bool { return m.sameCertKey(ctx, "cert_cas", id, fp, pair.PrivateKey) })
	if err != nil {
		return err
	}
	if keep {
		return m.resolveRefs(ctx, "ca_id", "ref_ca", uid, id)
	}
	if in.CreatedAt == "" {
		in.CreatedAt = store.Now()
	}
	sealed := m.d.Box.Encrypt(in.KeyPEM)
	if id != 0 {
		_, err = m.w.ExecContext(ctx, `UPDATE cert_cas SET name = ?, cert_pem = ?, key_pem = ?, imported = ? WHERE id = ?`, in.Name, in.CertPEM, sealed, in.Imported, id)
	} else {
		var res sql.Result
		res, err = m.w.ExecContext(ctx, `INSERT INTO cert_cas (uid, name, cert_pem, key_pem, imported, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
			uid, in.Name, in.CertPEM, sealed, in.Imported, in.CreatedAt)
		if err == nil {
			id, _ = res.LastInsertId()
		}
	}
	if err != nil {
		return err
	}
	if err := m.resolveRefs(ctx, "ca_id", "ref_ca", uid, id); err != nil {
		return err
	}
	m.changedUID(ctx, ItemCAs, uid, false)
	return nil
}
