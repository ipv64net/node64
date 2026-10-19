package certs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"

	"github.com/ipv64net/node64/internal/store"
)

// DNSAccount ist ein Zugang zu einem DNS-Anbieter (ohne die geheimen Werte).
type DNSAccount struct {
	ID           int64             `json:"id"`
	Name         string            `json:"name"`
	Provider     string            `json:"provider"`
	ProviderName string            `json:"provider_name"`
	Values       map[string]string `json:"values"` // nur nicht geheime Felder; geheime als "set"
	UsedBy       []string          `json:"used_by,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

const dnsCols = `id, name, provider, config, created_at, updated_at`

// dnsAccountRaw liest einen Zugang mit allen Werten (entschluesselt).
func (m *Manager) dnsAccountRaw(ctx context.Context, id int64) (*DNSAccount, map[string]string, error) {
	var a DNSAccount
	var cfg, ca, ua string
	err := m.r.QueryRowContext(ctx, `SELECT `+dnsCols+` FROM cert_dns_accounts WHERE id = ?`, id).Scan(&a.ID, &a.Name, &a.Provider, &cfg, &ca, &ua)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	}
	if err != nil {
		return nil, nil, err
	}
	a.CreatedAt, a.UpdatedAt = store.ParseTime(ca), store.ParseTime(ua)
	vals := map[string]string{}
	if cfg != "" {
		plain, err := m.d.Box.Decrypt(cfg)
		if err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal([]byte(plain), &vals)
	}
	return &a, vals, nil
}

// public: Werte fuer die Anzeige (geheime nur als "gesetzt").
func publicValues(provider string, vals map[string]string) map[string]string {
	out := map[string]string{}
	for _, f := range providers[provider].Fields {
		if v := vals[f.Key]; v != "" {
			if f.Secret {
				out[f.Key] = "set"
			} else {
				out[f.Key] = v
			}
		}
	}
	return out
}

// DNSAccounts liefert alle Zugaenge mit den Zertifikaten, die sie benutzen.
func (m *Manager) DNSAccounts(ctx context.Context) ([]*DNSAccount, error) {
	rows, err := m.r.QueryContext(ctx, `SELECT id FROM cert_dns_accounts ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	used := map[int64][]string{}
	if list, err := m.List(ctx); err == nil {
		for _, c := range list {
			if c.Source == SourceDNS && c.DNSAccount > 0 {
				used[c.DNSAccount] = append(used[c.DNSAccount], c.Title())
			}
		}
	}
	out := make([]*DNSAccount, 0, len(ids))
	for _, id := range ids {
		a, vals, err := m.dnsAccountRaw(ctx, id)
		if err != nil {
			return nil, err
		}
		a.ProviderName = providers[a.Provider].Name
		a.Values = publicValues(a.Provider, vals)
		a.UsedBy = used[id]
		out = append(out, a)
	}
	return out, nil
}

// DNSAccount liefert einen Zugang (ohne geheime Werte).
func (m *Manager) DNSAccount(ctx context.Context, id int64) (*DNSAccount, error) {
	a, vals, err := m.dnsAccountRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	a.ProviderName = providers[a.Provider].Name
	a.Values = publicValues(a.Provider, vals)
	return a, nil
}

// SaveDNSAccount legt an (ID 0) oder aendert. Leere geheime Felder behalten beim Aendern ihren Wert.
func (m *Manager) SaveDNSAccount(ctx context.Context, a *DNSAccount, values map[string]string) error {
	a.Name = strings.TrimSpace(a.Name)
	if a.Name == "" || len(a.Name) > 100 {
		return invalid("name", "1-100 characters")
	}
	if a.ID > 0 {
		old, oldVals, err := m.dnsAccountRaw(ctx, a.ID)
		if err != nil {
			return err
		}
		if a.Provider == "" {
			a.Provider = old.Provider
		}
		if a.Provider == old.Provider {
			merged := map[string]string{}
			for k, v := range oldVals {
				merged[k] = v
			}
			for k, v := range values {
				if strings.TrimSpace(v) != "" {
					merged[k] = v
				}
			}
			values = merged
		}
	}
	vals, err := checkValues(a.Provider, values)
	if err != nil {
		return err
	}
	if _, err := buildProvider(a.Provider, vals); err != nil { // Grundpruefung des Anbieters (Pflichtwerte, Format)
		return invalid("fields", "%v", err)
	}
	raw, _ := json.Marshal(vals)
	sealed := m.d.Box.Encrypt(string(raw))
	now := store.Now()
	if a.ID == 0 {
		res, err := m.w.ExecContext(ctx, `INSERT INTO cert_dns_accounts (name, provider, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			a.Name, a.Provider, sealed, now, now)
		if err != nil {
			return err
		}
		a.ID, _ = res.LastInsertId()
		m.changed(ctx, ItemDNSAccounts, a.ID)
		return nil
	}
	_, err = m.w.ExecContext(ctx, `UPDATE cert_dns_accounts SET name = ?, provider = ?, config = ?, updated_at = ? WHERE id = ?`, a.Name, a.Provider, sealed, now, a.ID)
	if err == nil {
		m.changed(ctx, ItemDNSAccounts, a.ID)
	}
	return err
}

// DeleteDNSAccount entfernt einen Zugang, der von keinem Zertifikat mehr benutzt wird.
func (m *Manager) DeleteDNSAccount(ctx context.Context, id int64) error {
	var n int
	if err := m.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM certs WHERE source = ? AND dns_account = ?`, SourceDNS, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	uid := m.deleting(ctx, ItemDNSAccounts, id)
	res, err := m.w.ExecContext(ctx, `DELETE FROM cert_dns_accounts WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if k, _ := res.RowsAffected(); k == 0 {
		return ErrNotFound
	}
	m.changedUID(ctx, ItemDNSAccounts, uid, true)
	return nil
}

// dnsProvider baut den Anbieter eines Zugangs (Tests ersetzen ihn ueber m.provider).
func (m *Manager) dnsProvider(ctx context.Context, id int64) (challenge.Provider, error) {
	a, vals, err := m.dnsAccountRaw(ctx, id)
	if err != nil {
		return nil, err
	}
	if m.provider != nil {
		return m.provider(a.Provider, vals)
	}
	return buildProvider(a.Provider, vals)
}
