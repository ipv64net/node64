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
		sum := sha256.Sum256(b.Bytes)
		list, err := m.CAs(ctx)
		if err != nil {
			return nil, err
		}
		for _, ca := range list {
			if sha256.Sum256(ca.cert.Raw) == sum {
				return ca, nil
			}
		}
	}
	return m.ImportCA(ctx, name, certPEM, keyPEM)
}

// ImportRequest: vorhandenes Zertifikat, das die Zentrale ab jetzt erneuert.
type ImportRequest struct {
	Names   []string // leer = alle Namen des Zertifikats
	Source  string   // ipv64, alias, dns, http
	Staging bool
	CertPEM string // mit Kette
	KeyPEM  string
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
	case SourceIPv64, SourceAlias, SourceDNS, SourceHTTP:
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
	sum := sha256.Sum256(crt.Certificate[0])
	if list, err := m.List(ctx); err == nil {
		for _, c := range list {
			if b, err := m.Bundle(ctx, c.ID); err == nil && sha256.Sum256(b.Leaf.Raw) == sum {
				return c, nil
			}
		}
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
	res, err := m.w.ExecContext(ctx, `INSERT INTO certs (names, source, staging, auto_renew, cert_pem, key_pem, not_before, not_after, issuer, status, created_at, updated_at)
		VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`, strings.Join(names, ","), req.Source, req.Staging, string(chain), m.d.Box.Encrypt(keyOut),
		store.FormatTime(leaf.NotBefore), store.FormatTime(leaf.NotAfter), issuerName(leaf), StatusValid, now, now)
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
	ca, err := m.loadCA(ctx, caID)
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
				if c.CAID == caID && coversNames(c.Names, names) && c.Status == StatusValid && time.Until(c.NotAfter) > renewBefore {
					return c, nil
				}
				if _, err := m.w.ExecContext(ctx, `UPDATE certs SET names = ?, ca_id = ?, days = ?, updated_at = ? WHERE id = ?`,
					strings.Join(names, ","), caID, days, store.Now(), id); err != nil {
					return nil, err
				}
				return m.issueNow(ctx, id)
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
	return m.issueNow(ctx, id)
}

// issueNow stellt ein Zertifikat der eigenen CA sofort aus (statt im Hintergrund).
func (m *Manager) issueNow(ctx context.Context, id int64) (*Cert, error) {
	c, err := m.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	m.acme.Lock()
	err = m.issueFromCA(ctx, c)
	m.acme.Unlock()
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
