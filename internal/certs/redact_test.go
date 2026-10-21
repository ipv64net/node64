package certs

import (
	"context"
	"strings"
	"testing"
)

// Fehlertexte von DNS-Providern koennen Zugangsdaten enthalten (z. B. DuckDNS-URL mit token=); auch aeltere,
// ungeschwaerzt gespeicherte Eintraege duerfen ueber API und Oberflaeche nicht im Klartext erscheinen.
func TestLastErrorRedacted(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	if _, err := e.st.Writer().ExecContext(ctx, `INSERT INTO certs (names, source, status, last_error, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"x.example.org", "acme", StatusError, `duckdns: Get "https://www.duckdns.org/update?domains=x&token=0f1e2d3c-aaaa-bbbb-cccc-123456789abc": EOF`,
		"2026-10-21T00:00:00.000Z", "2026-10-21T00:00:00.000Z"); err != nil {
		t.Fatal(err)
	}
	list, err := e.m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range list {
		if strings.Contains(c.LastError, "duckdns") {
			found = true
			if strings.Contains(c.LastError, "0f1e2d3c") || strings.Contains(c.LastError, "token=") {
				t.Fatalf("not redacted: %s", c.LastError)
			}
		}
	}
	if !found {
		t.Fatal("cert not listed")
	}
}
