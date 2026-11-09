package monitor64

import (
	"context"
	"log/slog"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/tsdb"
)

// Series ist der Verlaufsspeicher, wie das Modul ihn nutzt (Umsetzung: Paket tsdb, Datei monitor64.db).
// Im Cluster beantwortet spaeter auch eine andere Node Abfragen (Plan "Cluster"); daher nur Werte rein/raus.
type Series interface {
	Append(key string, t time.Time, v float64)
	Flush(ctx context.Context) error
	Purge(ctx context.Context, now time.Time) (int64, error)
	Size() int64
	Close() error
}

// openSeries oeffnet den Verlauf mit der Standard-Aufbewahrung (48 h / 30 Tage / 1 Jahr, Einstellung folgt);
// gesichert wird alle 5 Minuten durch housekeeping des Moduls.
func openSeries(path string, log *slog.Logger) (*tsdb.DB, error) {
	opt := tsdb.DefaultOptions()
	opt.FlushInterval = -1
	opt.Logger = log
	return tsdb.Open(path, opt)
}
