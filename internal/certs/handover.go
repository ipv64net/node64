package certs

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Uebernahme fuer Module, die bisher eigene Zertifikate hatten (DNS64): eine vorhandene CA einmal uebernehmen,
// ein vorhandenes Let's-Encrypt-Zertifikat samt Schluessel uebernehmen (ab dann erneuert die Zentrale) und ein
// Server-Zertifikat der eigenen CA fuer ein Modul halten, das neu ausgestellt wird, wenn sich Namen aendern.

// EnsureCA uebernimmt eine CA; ist sie (gleicher Fingerabdruck) schon da, kommt die vorhandene zurueck.
func (m *Manager) EnsureCA(ctx context.Context, name, certPEM, keyPEM string) (*CA, error) {
	if b, _ := pem.Decode([]byte(certPEM)); b != nil {
		if id, ok := m.findByFingerprint(ctx, `SELECT id, cert_pem FROM cert_cas`, sha256.Sum256(b.Bytes)); ok {
			return m.GetCA(ctx, id)
		}
	}
	return m.ImportCA(ctx, name, certPEM, keyPEM)
}

// findByFingerprint sucht einen Eintrag, dessen erstes Zertifikat (cert_pem) den Fingerabdruck hat, ohne
// Schluessel zu entschluesseln. query liefert id und cert_pem.
func (m *Manager) findByFingerprint(ctx context.Context, query string, sum [32]byte) (int64, bool) {
	rows, err := m.r.QueryContext(ctx, query)
	if err != nil {
		return 0, false
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var p string
		if rows.Scan(&id, &p) != nil {
			continue
		}
		if b, _ := pem.Decode([]byte(p)); b != nil && sha256.Sum256(b.Bytes) == sum {
			return id, true
		}
	}
	return 0, false
}

// ImportRequest: vorhandenes Zertifikat, das die Zentrale ab jetzt erneuert.
type ImportRequest struct {
	Names       []string // leer = alle Namen des Zertifikats
	Source      string   // ipv64, alias, dns, http
	AliasZone   string   // alias: ipv64-Domain fuer den TXT-Record (Pflicht)
	AliasPrefix string   // alias: Praefix darunter
	DNSAccount  int64    // dns: DNS-Zugang (Pflicht)
	Staging     bool
	CertPEM     string // mit Kette
	KeyPEM      string
}

// ImportIssued legt ein vorhandenes Zertifikat als erneuerbares Zertifikat an (Status gueltig, automatisch
// erneuern an). Gibt es schon eins mit demselben Fingerabdruck, kommt dieses zurueck.
func (m *Manager) ImportIssued(ctx context.Context, req ImportRequest) (*Cert, error) {
	crt, err := tls.X509KeyPair([]byte(req.CertPEM), []byte(req.KeyPEM))
	if err != nil {
		return nil, invalid("cert", "certificate and key do not fit: %v", err)
	}
	leaf := crt.Leaf
	if time.Now().After(leaf.NotAfter) {
		return nil, invalid("cert", "certificate expired on %s", leaf.NotAfter.UTC().Format(time.DateOnly))
	}
	switch req.Source {
	case SourceIPv64, SourceHTTP:
		req.AliasZone, req.AliasPrefix, req.DNSAccount = "", "", 0
	case SourceAlias: // ohne Ziel-Domain liesse sich das Zertifikat nie erneuern
		req.AliasZone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(req.AliasZone)), ".")
		req.AliasPrefix = strings.Trim(strings.ToLower(strings.TrimSpace(req.AliasPrefix)), ".")
		if req.AliasZone == "" {
			return nil, invalid("alias_zone", "required")
		}
		req.DNSAccount = 0
	case SourceDNS:
		if _, _, err := m.dnsAccountRaw(ctx, req.DNSAccount); err != nil {
			return nil, invalid("dns_account", "unknown dns account")
		}
		req.AliasZone, req.AliasPrefix = "", ""
	default:
		return nil, invalid("source", "renewable source expected")
	}
	have := certNames(leaf)
	names := req.Names
	if len(names) == 0 {
		names = have
	}
	if names, err = normNames(names); err != nil {
		return nil, err
	}
	for _, n := range names {
		if !slices.Contains(have, n) {
			return nil, invalid("names", "%s is not in the certificate", n)
		}
	}
	if id, ok := m.findByFingerprint(ctx, `SELECT id, cert_pem FROM certs WHERE cert_pem != ''`, sha256.Sum256(crt.Certificate[0])); ok {
		return m.Get(ctx, id)
	}
	var chain []byte
	for _, der := range crt.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	keyOut, err := marshalKey(crt.PrivateKey)
	if err != nil {
		return nil, invalid("key", "%v", err)
	}
	now := store.Now()
	res, err := m.w.ExecContext(ctx, `INSERT INTO certs (names, source, alias_zone, alias_prefix, dns_account, staging, auto_renew, cert_pem, key_pem, not_before,
		not_after, issuer, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`, strings.Join(names, ","), req.Source, req.AliasZone,
		req.AliasPrefix, req.DNSAccount, req.Staging, string(chain), m.d.Box.Encrypt(keyOut), store.FormatTime(leaf.NotBefore), store.FormatTime(leaf.NotAfter),
		issuerName(leaf), StatusValid, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := m.reload(ctx); err != nil {
		return nil, err
	}
	m.refreshHold(ctx)
	return m.Get(ctx, id)
}

func ownedKey(owner string) string { return "certs.owned." + owner }

// EnsureIssued haelt fuer einen Abnehmer (z. B. "dns64") ein Zertifikat der eigenen CA mit genau diesen Namen und
// IPs: fehlt es, wird es angelegt; aendern sich die Namen, wird es neu ausgestellt. Ausgestellt wird sofort (ohne
// ACME), damit der Abnehmer es gleich benutzen kann. Erneuert wird wie jedes Zertifikat.
func (m *Manager) EnsureIssued(ctx context.Context, owner string, caID int64, names []string, days int) (*Cert, error) {
	names, err := normNamesIP(names, true)
	if err != nil {
		return nil, err
	}
	ca, err := m.loadCA(ctx, caID, false)
	if err != nil {
		return nil, invalid("ca_id", "unknown CA")
	}
	if err := ca.permits(names); err != nil {
		return nil, invalid("names", "%v", err)
	}
	if days <= 0 {
		days = defaultCADays
	}
	if days > maxCADays {
		days = maxCADays
	}
	if v := m.d.Store.SettingOr(ctx, ownedKey(owner), ""); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			if c, err := m.Get(ctx, id); err == nil && c.Source == SourceCA {
				if c.CAID == caID && coversNames(c.Names, names) && c.Status == StatusValid && time.Until(c.NotAfter) > caRenewBefore(days) {
					return c, nil
				}
				if _, err := m.w.ExecContext(ctx, `UPDATE certs SET ca_id = ?, days = ?, updated_at = ? WHERE id = ?`, caID, days, store.Now(), id); err != nil {
					return nil, err
				}
				// die Namen gehen mit der Ausstellung in die Datenbank (storeIssued), damit Eintrag und Zertifikat nie
				// auseinanderlaufen; laeuft gerade eine Erneuerung, kurz warten und dann mit den neuen Namen ausstellen
				c, err := m.issueNow(ctx, id, names)
				for i := 0; i < 100 && errors.Is(err, ErrBusy); i++ {
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(100 * time.Millisecond):
					}
					c, err = m.issueNow(ctx, id, names)
				}
				return c, err
			}
		}
	}
	now := store.Now()
	res, err := m.w.ExecContext(ctx, `INSERT INTO certs (names, source, ca_id, days, auto_renew, status, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?, ?)`,
		strings.Join(names, ","), SourceCA, caID, days, StatusPending, now, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	if err := m.d.Store.SetSetting(ctx, ownedKey(owner), strconv.FormatInt(id, 10)); err != nil {
		return nil, err
	}
	m.refreshHold(ctx)
	return m.issueNow(ctx, id, nil)
}

// issueNow stellt ein Zertifikat der eigenen CA sofort aus (statt im Hintergrund), mit names statt der
// gespeicherten Namen (nil = gespeicherte). Ohne die ACME-Sperre: ein laufender Abruf bei Let's Encrypt haelt den
// Abnehmer nicht auf. Gegen einen gleichzeitigen Lauf fuer dasselbe Zertifikat schuetzt der Eintrag in steps; Close
// wartet ueber bg auf das Ende.
func (m *Manager) issueNow(ctx context.Context, id int64, names []string) (*Cert, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if names != nil {
		c.Names = names
	}
	m.mu.Lock()
	if m.base.Err() != nil {
		m.mu.Unlock()
		return nil, errors.New("certificate manager stopped")
	}
	if m.steps[id] != "" {
		m.mu.Unlock()
		return nil, ErrBusy
	}
	m.steps[id] = "certificate"
	m.bg.Add(1)
	m.mu.Unlock()
	err = m.issueFromCA(ctx, c)
	m.mu.Lock()
	delete(m.steps, id)
	m.mu.Unlock()
	m.bg.Done()
	if err != nil {
		now := store.Now()
		_, _ = m.w.ExecContext(ctx, `UPDATE certs SET status = ?, last_error = ?, last_attempt = ?, updated_at = ? WHERE id = ?`, StatusError, err.Error(), now, now, id)
		return nil, err
	}
	return m.Get(ctx, id)
}

// Owned liefert das Zertifikat, das EnsureIssued fuer einen Abnehmer haelt (ErrNotFound = keins).
func (m *Manager) Owned(ctx context.Context, owner string) (*Cert, error) {
	id, err := strconv.ParseInt(m.d.Store.SettingOr(ctx, ownedKey(owner), ""), 10, 64)
	if err != nil {
		return nil, ErrNotFound
	}
	c, err := m.Get(ctx, id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = m.d.Store.SetSetting(ctx, ownedKey(owner), "")
		}
		return nil, err
	}
	return c, nil
}

// coversNames: alle gewuenschten Namen enthalten und genau dieselben IPs (eine IP, die die Node nicht mehr hat,
// fuehrt zu einem neuen Zertifikat).
func coversNames(have, want []string) bool {
	ips := func(list []string) []string {
		var out []string
		for _, n := range list {
			if ip := net.ParseIP(n); ip != nil {
				out = append(out, ip.String())
			}
		}
		slices.Sort(out)
		return out
	}
	if !slices.Equal(ips(have), ips(want)) {
		return false
	}
	for _, n := range want {
		if net.ParseIP(n) == nil && !slices.Contains(have, n) {
			return false
		}
	}
	return true
}
