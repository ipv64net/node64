package tsdb

import (
	"context"
	"errors"
	"strings"
)

// RenameSeriesPrefix haengt alle Reihen, deren Schluessel mit from beginnt, an das Praefix to (Rest bleibt), samt
// Punkten im Speicher und gesicherten Bloecken (Dienst an einen anderen Host uebergeben). Reihen, deren neuer
// Schluessel schon belegt ist, bleiben unveraendert. Scheitert die Datenbank, bleibt alles beim Alten. Liefert die
// Zahl der umbenannten Reihen.
func (db *DB) RenameSeriesPrefix(ctx context.Context, from, to string) (int, error) {
	if from == "" || to == "" || from == to || strings.HasPrefix(to, from) || strings.HasPrefix(from, to) {
		return 0, errors.New("tsdb: ungueltiges Praefix")
	}
	if db.closed.Load() {
		return 0, ErrClosed
	}
	db.wmu.Lock() // kein Flush, Purge oder Loeschen dazwischen (die Kennungen der Reihen bleiben fest)
	defer db.wmu.Unlock()
	db.mu.Lock()
	defer db.mu.Unlock()
	type move struct {
		s       *series
		old, nk string
	}
	var list []move
	for key, s := range db.series {
		if !strings.HasPrefix(key, from) {
			continue
		}
		nk := to + key[len(from):]
		if _, taken := db.series[nk]; taken {
			continue
		}
		list = append(list, move{s: s, old: key, nk: nk})
	}
	if len(list) == 0 {
		return 0, nil
	}
	tx, err := db.sql.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	for _, m := range list {
		if m.s.id == 0 { // noch nicht gesichert: der naechste Flush legt sie unter dem neuen Schluessel an
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE series SET key = ? WHERE id = ?`, m.nk, m.s.id); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	for _, m := range list {
		m.s.mu.Lock()
		m.s.key = m.nk
		m.s.mu.Unlock()
		delete(db.series, m.old)
		db.series[m.nk] = m.s
	}
	return len(list), nil
}
