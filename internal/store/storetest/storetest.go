// Package storetest hilft Tests, die ueber alle Tabellen der Node gehen (Backup, Wiederherstellung, Zuruecksetzen).
// Die Tabellen kommen aus sqlite_master, damit neue Module und Migrationen ohne Aenderung am Test erfasst werden;
// nur ein neuer Scope muss in Scopes eingetragen werden (wie in cmd/node64).
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/cdn64"
	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/dns64"
	"github.com/ipv64net/node64/internal/dyndns"
	"github.com/ipv64net/node64/internal/healthchecks"
	"github.com/ipv64net/node64/internal/honeypot"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// Scopes liefert die Migrationen aller Scopes der Node (Kern, feste Teile und Module).
func Scopes(t testing.TB) map[string][]store.Migration {
	t.Helper()
	out := map[string][]store.Migration{}
	for name, f := range map[string]func() ([]store.Migration, error){"core": store.CoreMigrations, "notify": notify.Migrations,
		"certs": certs.Migrations, "peer": peer.Migrations} {
		ms, err := f()
		if err != nil {
			t.Fatal(err)
		}
		out[name] = ms
	}
	out[healthchecks.Name] = (&healthchecks.Module{}).Migrations()
	out[dyndns.Name] = (&dyndns.Module{}).Migrations()
	out[dns64.Name] = (&dns64.Module{}).Migrations()
	out[cdn64.Name] = (&cdn64.Module{}).Migrations()
	out[honeypot.Name] = honeypot.Migrations()
	return out
}

// MigrateAll legt alle Tabellen aller Scopes an (Kern zuerst).
func MigrateAll(t testing.TB, st *store.Store) {
	t.Helper()
	scopes := Scopes(t)
	names := []string{"core"}
	for n := range scopes {
		if n != "core" {
			names = append(names, n)
		}
	}
	sort.Strings(names[1:])
	for _, n := range names {
		if err := st.Migrate(context.Background(), n, scopes[n]); err != nil {
			t.Fatalf("migrate %s: %v", n, err)
		}
	}
}

// Tables liefert alle Tabellen der Datenbank ausser den internen (sqlite_*) und schema_migrations.
func Tables(t testing.TB, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name != 'schema_migrations' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// FillAll schreibt in jede Tabelle eine Zeile (Werte nach Spaltentyp, Fremdschluessel aus).
func FillAll(t testing.TB, st *store.Store) {
	t.Helper()
	w := st.Writer() // genau eine Verbindung: das PRAGMA gilt fuer alle folgenden Anweisungen
	if _, err := w.Exec(`PRAGMA foreign_keys = OFF`); err != nil {
		t.Fatal(err)
	}
	defer w.Exec(`PRAGMA foreign_keys = ON`) //nolint:errcheck
	for i, tbl := range Tables(t, st.Reader()) {
		rows, err := w.Query(`SELECT name, type FROM pragma_table_info(?)`, tbl)
		if err != nil {
			t.Fatal(err)
		}
		var cols, marks []string
		var args []any
		for rows.Next() {
			var name, typ string
			if err := rows.Scan(&name, &typ); err != nil {
				t.Fatal(err)
			}
			typ = strings.ToUpper(typ)
			var v any = fmt.Sprintf("x%d", i)
			switch {
			case strings.Contains(typ, "INT"):
				v = int64(i + 1)
			case strings.Contains(typ, "REAL"), strings.Contains(typ, "FLOA"), strings.Contains(typ, "DOUB"):
				v = float64(i) + 0.5
			case strings.Contains(typ, "BLOB"):
				v = []byte{byte(i), 1, 2}
			}
			cols, marks, args = append(cols, `"`+name+`"`), append(marks, "?"), append(args, v)
		}
		rows.Close()
		if _, err := w.Exec(`INSERT INTO "`+tbl+`" (`+strings.Join(cols, ", ")+`) VALUES (`+strings.Join(marks, ", ")+`)`, args...); err != nil {
			t.Fatalf("fill %s: %v", tbl, err)
		}
	}
}

// Counts liefert die Zeilenzahl je Tabelle.
func Counts(t testing.TB, db *sql.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, tbl := range Tables(t, db) {
		var n int64
		if err := db.QueryRow(`SELECT count(*) FROM "` + tbl + `"`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		out[tbl] = n
	}
	return out
}

// Snapshot liefert den Inhalt jeder Tabelle als sortierten Text (zum Vergleichen zweier Datenbanken).
func Snapshot(t testing.TB, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, tbl := range Tables(t, db) {
		rows, err := db.Query(`SELECT * FROM "` + tbl + `"`)
		if err != nil {
			t.Fatal(err)
		}
		cols, _ := rows.Columns()
		var lines []string
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, fmt.Sprintf("%v", vals))
		}
		rows.Close()
		sort.Strings(lines)
		out[tbl] = strings.Join(lines, "\n")
	}
	return out
}
