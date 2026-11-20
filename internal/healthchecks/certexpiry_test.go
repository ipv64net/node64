package healthchecks

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/checks"
	"github.com/ipv64net/node64/internal/scheduler"
	"github.com/ipv64net/node64/internal/store"
)

// Zertifikats-Ablauf je HTTP(S)-Check aus der neuesten Messung mit Zertifikat (#197: frueher eine Abfrage ueber alle
// Messungen der letzten 3 Tage, ~13 s bei grossen Datenbanken). Messungen ohne Zertifikat dazwischen, andere
// Check-Typen und Messungen aelter als 3 Tage zaehlen nicht; das Ergebnis gilt certCacheTTL.
func TestCertExpiries(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	core, err := store.Open(context.Background(), filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), log)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { core.Close() })
	cm, _ := store.CoreMigrations()
	if err := core.Migrate(context.Background(), "core", cm); err != nil {
		t.Fatal(err)
	}
	if err := core.Migrate(context.Background(), Name, New(core, log, nil, nil, "test").Migrations()); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	st := NewStore(core)
	add := func(typ checks.Type) *Check {
		c := &Check{Token: NewToken(), Type: typ, Name: string(typ), Target: "https://x/", Params: json.RawMessage("{}"), Interval: time.Minute,
			RetryInterval: 20 * time.Second, ConnectTimeout: time.Second, TotalTimeout: 2 * time.Second, Stabilize: 1, IPMode: checks.IPAuto}
		if err := st.Insert(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	httpC, oldC, pingC := add(checks.TypeHTTP), add(checks.TypeHTTP), add(checks.TypeTCP)
	now := time.Now().UTC()
	save := func(c *Check, at time.Time, notAfter string, msg string) {
		m := scheduler.Measurement{Token: c.Token, Time: at, Status: checks.Up, Message: msg}
		if notAfter != "" {
			m.Details = map[string]any{"cert_not_after": notAfter}
		}
		if err := st.SaveMeasurement(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	save(httpC, now.Add(-2*time.Hour), "2027-01-01T00:00:00Z", "")
	save(httpC, now.Add(-time.Hour), "2027-02-01T00:00:00Z", "") // neueste mit Zertifikat
	for i := 0; i < 10; i++ {                                    // danach Messungen ohne Zertifikat (z. B. Zeitueberschreitung)
		save(httpC, now.Add(-time.Duration(50-i)*time.Minute), "", "timeout")
	}
	save(oldC, now.Add(-4*24*time.Hour), "2027-03-01T00:00:00Z", "") // aelter als 3 Tage
	save(pingC, now.Add(-time.Hour), "2027-04-01T00:00:00Z", "")     // kein HTTP-Check
	// abgelaufenes oder nicht erreichbares Ziel: viele Messungen ohne Zertifikat nach der letzten mit - das letzte
	// bekannte Ablaufdatum bleibt (frueher nach 50 Messungen weg)
	gone := add(checks.TypeJSON)
	save(gone, now.Add(-30*time.Hour), "2027-05-01T00:00:00Z", "")
	for i := 0; i < 80; i++ {
		save(gone, now.Add(-time.Duration(80-i)*10*time.Minute), "", "certificate has expired")
	}
	got := st.CertExpiries(ctx)
	if len(got) != 2 || !got[httpC.Token].Equal(time.Date(2027, 2, 1, 0, 0, 0, 0, time.UTC)) ||
		!got[gone.Token].Equal(time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cert expiries: %v", got)
	}
	if exp, ok := st.CertExpiry(ctx, gone.Token); !ok || !exp.Equal(time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("cert expiry: %v %v", exp, ok)
	}
	if _, ok := st.CertExpiry(ctx, oldC.Token); ok {
		t.Fatal("older than 3 days")
	}
	// zwischengespeichert: eine neue Messung zeigt sich erst nach certCacheTTL
	save(oldC, now, "2027-06-01T00:00:00Z", "")
	if _, ok := st.CertExpiries(ctx)[oldC.Token]; ok {
		t.Fatal("not cached")
	}
	st.certMu.Lock()
	st.certAt = time.Now().Add(-certCacheTTL)
	st.certMu.Unlock()
	if got := st.CertExpiries(ctx); !got[oldC.Token].Equal(time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("after ttl: %v", got)
	}
}
