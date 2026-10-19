package main

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
	"github.com/ipv64net/node64/internal/web"
)

func TestResetPassword(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NODE64_DATA_DIR", dir)
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	core, err := store.CoreMigrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx, "core", core); err != nil {
		t.Fatal(err)
	}
	hash, _ := web.HashPassword("altes-passwort-123")
	u, err := st.CreateUser(ctx, "admin", hash, "de", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserTOTP(ctx, u.ID, "SECRET", "x"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := st.CreateSession(ctx, &store.Session{ID: "s1", UserID: u.ID, CSRF: "c", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	st.Close()

	// zu kurz: abgelehnt, nichts geaendert
	if code := resetPassword([]string{"-password", "kurz"}); code == 0 {
		t.Fatal("kurzes Passwort angenommen")
	}
	// unbekannter Benutzer
	if code := resetPassword([]string{"-user", "nobody"}); code == 0 {
		t.Fatal("unbekannter Benutzer angenommen")
	}
	if code := resetPassword([]string{"-password", "neues-passwort-456", "-disable-2fa"}); code != 0 {
		t.Fatalf("reset-password: exit %d", code)
	}

	st, err = store.Open(ctx, filepath.Join(dir, "node64.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.UserByName(ctx, "admin")
	if err != nil || got == nil {
		t.Fatal("Benutzer weg", err)
	}
	if !web.VerifyPassword(got.PasswordHash, "neues-passwort-456") {
		t.Error("neues Passwort passt nicht")
	}
	if web.VerifyPassword(got.PasswordHash, "altes-passwort-123") {
		t.Error("altes Passwort gilt noch")
	}
	if got.TOTPSecret != "" {
		t.Error("2FA nicht abgeschaltet")
	}
	if s, _ := st.SessionByID(ctx, "s1"); s != nil {
		t.Error("Sitzung nicht beendet")
	}
}

func TestRandomPassword(t *testing.T) {
	p, err := randomPassword(20)
	if err != nil || len(p) != 20 {
		t.Fatalf("%q %v", p, err)
	}
	q, _ := randomPassword(20)
	if p == q {
		t.Error("zweimal dasselbe Passwort")
	}
}
