package certs

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"slices"
	"strings"
)

// Sicherung der Zertifikatsverwaltung fuer das Backup des Kerns (verschluesseltes Archiv): Zertifikate mit
// Schluessel, DNS-Zugaenge, eigene CAs und weitere ACME-Stellen. Geheimes steht entschluesselt im Paket - es darf
// nur in das verschluesselte Archiv. Der Import verschluesselt mit dem Schluessel dieser Node, erkennt Vorhandenes
// und schreibt die Verweise zwischen den Tabellen um (Zertifikat -> DNS-Zugang, CA, ACME-Stelle).

// BackupVersion: Format von Backup.
const BackupVersion = 1

// Backup ist der Inhalt aller Tabellen der Zertifikatsverwaltung (Zeilen als Spalte -> Wert).
type Backup struct {
	Version int                         `json:"version"`
	Tables  map[string][]map[string]any `json:"tables"`
}

// ImportResult: was beim Import angelegt bzw. als vorhanden erkannt wurde, und die neuen Kennungen der Zertifikate
// (alte ID -> neue ID, fuer Module mit festen Zertifikaten).
type ImportResult struct {
	Added   map[string]int  `json:"added"`
	Skipped map[string]int  `json:"skipped"`
	CertIDs map[int64]int64 `json:"-"`
}

// Reihenfolge: erst, worauf Zertifikate verweisen.
var backupTables = []struct {
	name    string
	secrets []string // mit Box verschluesselte Spalten
}{
	{"cert_acme_cas", []string{"eab_hmac"}},
	{"cert_dns_accounts", []string{"config"}},
	{"cert_cas", []string{"key_pem"}},
	{"certs", []string{"key_pem"}},
}

// ExportAll liefert alle Tabellen mit entschluesselten Geheimnissen.
func (m *Manager) ExportAll(ctx context.Context) (*Backup, error) {
	b := &Backup{Version: BackupVersion, Tables: map[string][]map[string]any{}}
	for _, t := range backupTables {
		rows, err := m.r.QueryContext(ctx, `SELECT * FROM `+t.name+` ORDER BY id`)
		if err != nil {
			return nil, err
		}
		cols, _ := rows.Columns()
		var list []map[string]any
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return nil, err
			}
			row := map[string]any{}
			for i, c := range cols {
				v := vals[i]
				if bs, ok := v.([]byte); ok {
					v = string(bs)
				}
				if s, ok := v.(string); ok && s != "" && slices.Contains(t.secrets, c) {
					plain, err := m.d.Box.Decrypt(s)
					if err != nil {
						rows.Close()
						return nil, fmt.Errorf("%s.%s: %w", t.name, c, err)
					}
					v = plain
				}
				row[c] = v
			}
			list = append(list, row)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
		b.Tables[t.name] = list
	}
	return b, nil
}

// ImportAll uebernimmt eine Sicherung. Vorhandenes bleibt (ACME-Stelle nach Verzeichnis, DNS-Zugang nach Name und
// Anbieter, CA nach Zertifikat, Zertifikat nach Zertifikat bzw. - noch nicht ausgestellt - nach Namen und Quelle).
func (m *Manager) ImportAll(ctx context.Context, b *Backup) (*ImportResult, error) {
	if b == nil || b.Version != BackupVersion {
		return nil, invalid("version", "unsupported certificate backup")
	}
	res := &ImportResult{Added: map[string]int{}, Skipped: map[string]int{}, CertIDs: map[int64]int64{}}
	ids := map[string]map[int64]int64{} // Tabelle -> alte ID -> neue ID
	type added struct {
		item string
		id   int64
	}
	var news []added // fuer den Cluster
	for _, t := range backupTables {
		cols, err := m.tableColumns(ctx, t.name)
		if err != nil {
			return res, err
		}
		ids[t.name] = map[int64]int64{}
		for _, row := range b.Tables[t.name] {
			old := asInt(row["id"])
			// Verweise der Zertifikate umschreiben (0 = keiner)
			if t.name == "certs" {
				for col, ref := range map[string]string{"dns_account": "cert_dns_accounts", "ca_id": "cert_cas", "acme_ca": "cert_acme_cas"} {
					if v := asInt(row[col]); v != 0 {
						row[col] = ids[ref][v] // unbekannt -> 0
					}
				}
			}
			if id, ok, err := m.existingRow(ctx, t.name, row); err != nil {
				return res, err
			} else if ok {
				ids[t.name][old] = id
				res.Skipped[t.name]++
				continue
			}
			var names []string
			var args []any
			for _, c := range cols {
				v, ok := row[c]
				if c == "id" || !ok {
					continue
				}
				if s, isStr := v.(string); isStr && s != "" && slices.Contains(t.secrets, c) {
					v = m.d.Box.Encrypt(s)
				}
				if f, isNum := v.(float64); isNum && f == math.Trunc(f) { // JSON-Zahlen
					v = int64(f)
				}
				names = append(names, c)
				args = append(args, v)
			}
			if len(names) == 0 {
				continue
			}
			r, err := m.w.ExecContext(ctx, `INSERT INTO `+t.name+` (`+strings.Join(names, ", ")+`) VALUES (?`+strings.Repeat(", ?", len(names)-1)+`)`, args...)
			if err != nil {
				return res, fmt.Errorf("%s: %w", t.name, err)
			}
			id, _ := r.LastInsertId()
			ids[t.name][old] = id
			res.Added[t.name]++
			for item, table := range itemTables {
				if table == t.name {
					news = append(news, added{item, id})
				}
			}
		}
	}
	res.CertIDs = ids["certs"]
	if err := m.reload(ctx); err != nil {
		return res, err
	}
	m.refreshHold(ctx) // Erneuerung auch auf Nodes, die vor dem Import keine Zertifikate hatten
	for _, n := range news {
		m.changed(ctx, n.item, n.id)
	}
	return res, nil
}

// existingRow: gibt es den Eintrag hier schon (dann dessen ID)?
func (m *Manager) existingRow(ctx context.Context, table string, row map[string]any) (int64, bool, error) {
	s := func(k string) string { v, _ := row[k].(string); return v }
	if id := m.idOf(ctx, table, s("uid")); id != 0 { // gleiche Kennung (Cluster, fruehere Sicherung)
		return id, true, nil
	}
	var q string
	var args []any
	switch table {
	case "cert_acme_cas":
		q, args = `SELECT id FROM cert_acme_cas WHERE directory = ?`, []any{s("directory")}
	case "cert_dns_accounts":
		q, args = `SELECT id FROM cert_dns_accounts WHERE name = ? AND provider = ?`, []any{s("name"), s("provider")}
	case "cert_cas":
		q, args = `SELECT id FROM cert_cas WHERE cert_pem = ?`, []any{s("cert_pem")}
	case "certs":
		if s("cert_pem") != "" {
			q, args = `SELECT id FROM certs WHERE cert_pem = ?`, []any{s("cert_pem")}
		} else {
			q, args = `SELECT id FROM certs WHERE cert_pem = '' AND names = ? AND source = ?`, []any{s("names"), s("source")}
		}
	default:
		return 0, false, nil
	}
	var id int64
	err := m.r.QueryRowContext(ctx, q, args...).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	return id, err == nil, err
}

// tableColumns: Spalten der Tabelle hier (nur diese werden geschrieben - Spalten aus der Datei sind kein SQL).
func (m *Manager) tableColumns(ctx context.Context, table string) ([]string, error) {
	rows, err := m.r.QueryContext(ctx, `SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func asInt(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	case int:
		return int64(x)
	}
	return 0
}
