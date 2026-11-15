package environment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(ctx, filepath.Join(dir, "n.db"), filepath.Join(dir, "backups"), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	core, _ := store.CoreMigrations()
	if err := st.Migrate(ctx, "core", core); err != nil {
		t.Fatal(err)
	}
	ms, err := Migrations()
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Migrate(ctx, Name, ms); err != nil {
		t.Fatal(err)
	}
	return st
}

type fakeCluster struct {
	members []peer.Member
	areas   map[string]bool // "modul/bereich" an mit allen Mitgliedern
}

func (f *fakeCluster) deps(st *store.Store, now *time.Time) Deps {
	return Deps{Store: st,
		Members: func(context.Context) ([]peer.Member, error) { return f.members, nil },
		AreaOn: func(_ context.Context, module, item string) []peer.Member {
			if !f.areas[module+"/"+item] {
				return nil
			}
			var out []peer.Member
			for _, x := range f.members {
				if !x.Suspended() {
					out = append(out, x)
				}
			}
			return out
		},
		Now: func() time.Time { return *now }}
}

func ticketFor(t *testing.T, s *Service, from string, req TicketRequest) (string, error) {
	t.Helper()
	b, _ := json.Marshal(req)
	out, err := s.HandleTicket(context.Background(), from, b)
	if err != nil {
		return "", err
	}
	return out.(TicketResponse).Ticket, nil
}

// Ticket: nur fuer aktive Mitglieder mit Benutzer-Abgleich und bekannte, nicht gesperrte Benutzer; die Rolle ist das
// Minimum; einmal einloesbar, nach 60 s ungueltig.
func TestTicket(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)
	fc := &fakeCluster{members: []peer.Member{{NodeID: "node-a", Name: "Node A", URL: "https://a:8443"}}, areas: map[string]bool{}}
	s := New(fc.deps(st, &now))
	u, err := st.CreateUserWith(ctx, store.NewUser{Username: "dennis", PasswordHash: "x", Lang: "de", Timezone: "UTC"})
	if err != nil {
		t.Fatal(err)
	}
	req := TicketRequest{UID: u.UID, Role: store.RoleAdmin, Back: "https://a:8443/environment"}

	if _, err := ticketFor(t, s, "node-a", req); !errors.Is(err, ErrNoUserSync) {
		t.Fatalf("user sync off: %v", err)
	}
	fc.areas["users/accounts"] = true
	// Schalter environment/login hier aus: kein Ticket, auch wenn die anfragende Node ihn fuer an haelt
	if _, err := ticketFor(t, s, "node-a", req); !errors.Is(err, ErrLoginOff) {
		t.Fatalf("login area off here: %v", err)
	}
	fc.areas[ModuleID+"/"+ItemLogin] = true
	if _, err := ticketFor(t, s, "node-x", req); !errors.Is(err, ErrMember) {
		t.Fatalf("unknown member: %v", err)
	}
	if _, err := ticketFor(t, s, "node-a", TicketRequest{UID: "0123456789abcdef", Role: store.RoleAdmin}); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown uid: %v", err)
	}
	if _, err := ticketFor(t, s, "node-a", TicketRequest{UID: "../x", Role: store.RoleAdmin}); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("invalid uid: %v", err)
	}

	tok, err := ticketFor(t, s, "node-a", req)
	if err != nil || len(tok) < 40 {
		t.Fatalf("ticket %q: %v", tok, err)
	}
	got, ok := s.Redeem(tok)
	if !ok || got.UID != u.UID || got.Role != store.RoleAdmin || got.FromName != "Node A" || got.FromNode != "node-a" || got.Back != req.Back {
		t.Fatalf("redeem: %+v %v", got, ok)
	}
	if !got.Trusted {
		t.Fatal("back at the member address should be trusted")
	}
	if _, ok := s.Redeem(tok); ok {
		t.Fatal("ticket used twice")
	}
	// Rueckweg aus einem frei gewaehlten Host-Header: nicht vertrauenswuerdig (B laesst bestaetigen); mit Pfad,
	// Abfrage oder Zugangsdaten gar kein Rueckweg
	for back, want := range map[string]string{"https://evil.example/environment": "https://evil.example/environment",
		"https://a:8443/x": "", "https://u:p@a:8443/environment": "", "https://a:8443/environment?x=1": "", "javascript:alert(1)": ""} {
		tok, err := ticketFor(t, s, "node-a", TicketRequest{UID: u.UID, Role: store.RoleAdmin, Back: back})
		if err != nil {
			t.Fatal(err)
		}
		got, _ := s.Redeem(tok)
		if got.Back != want || got.Trusted {
			t.Fatalf("back %q: %+v", back, got)
		}
	}
	if _, ok := s.Redeem(""); ok {
		t.Fatal("empty ticket accepted")
	}

	// Rolle begrenzt: von A nur lesen, bzw. hier nur lesen; unbekannte Rolle zaehlt als nur lesen
	for _, c := range []struct{ from, here, want string }{
		{store.RoleRead, store.RoleAdmin, store.RoleRead}, {store.RoleAdmin, store.RoleRead, store.RoleRead},
		{"superuser", store.RoleAdmin, store.RoleRead}, {store.RoleAdmin, store.RoleAdmin, store.RoleAdmin}} {
		if err := st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: c.here}); err != nil {
			t.Fatal(err)
		}
		tok, err := ticketFor(t, s, "node-a", TicketRequest{UID: u.UID, Role: c.from})
		if err != nil {
			t.Fatal(err)
		}
		if got, _ := s.Redeem(tok); got == nil || got.Role != c.want {
			t.Fatalf("role from %s here %s: %+v", c.from, c.here, got)
		}
	}

	// abgelaufen
	tok, _ = ticketFor(t, s, "node-a", req)
	now = now.Add(TicketTTL)
	if _, ok := s.Redeem(tok); ok {
		t.Fatal("expired ticket accepted")
	}

	// gesperrt, ausgesetzt
	_ = st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin, Disabled: true})
	if _, err := ticketFor(t, s, "node-a", req); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked user: %v", err)
	}
	_ = st.UpdateUserAdmin(ctx, u.ID, store.UserAdmin{Role: store.RoleAdmin})
	fc.members[0].State = "suspended"
	if _, err := ticketFor(t, s, "node-a", req); !errors.Is(err, ErrMember) {
		t.Fatalf("suspended member: %v", err)
	}
	// abgelehnte Anfragen im Audit-Log
	entries, _ := st.AuditList(ctx, 50, 0)
	n := 0
	for _, e := range entries {
		if e.Action == "environment.ticket_denied" {
			n++
		}
	}
	if n < 5 {
		t.Fatalf("denied tickets in audit: %d", n)
	}
}

// Liste: Anmeldung mit eigenem Benutzer nur mit Benutzer-Abgleich und environment/login, nie fuer ausgesetzte.
func TestNodes(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	now := time.Now()
	fc := &fakeCluster{members: []peer.Member{{NodeID: "node-b", Name: "Node B", URL: "https://b:8443/", Version: "1.6.0"}}, areas: map[string]bool{"users/accounts": true}}
	s := New(fc.deps(st, &now))
	list := s.Nodes(ctx)
	if len(list) != 1 || list[0].URL != "https://b:8443" || list[0].Login || list[0].Version != "1.6.0" {
		t.Fatalf("nodes: %+v", list)
	}
	fc.areas[ModuleID+"/"+ItemLogin] = true
	if n := s.Member(ctx, "node-b"); n == nil || !n.Login {
		t.Fatalf("login with user: %+v", n)
	}
	fc.members[0].State = "suspended"
	if n := s.Member(ctx, "node-b"); n == nil || n.Login || !n.Suspended {
		t.Fatalf("suspended: %+v", n)
	}
	if s.Member(ctx, "node-x") != nil {
		t.Fatal("unknown member found")
	}
}

// Sitzungen: Herkunft gespeichert, unbekannte Rolle wird „nur lesen“, Zeilen beendeter Sitzungen werden aufgeraeumt.
func TestSessionOrigin(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	s := New(Deps{Store: st})
	u, _ := st.CreateUser(ctx, "dennis", "x", "de", "UTC")
	now := time.Now()
	for _, id := range []string{"s1", "s2"} {
		if err := st.CreateSession(ctx, &store.Session{ID: id, UserID: u.ID, CSRF: "c", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if o, err := s.SessionOrigin(ctx, "s1"); o != nil || err != nil {
		t.Fatalf("normal session: %+v %v", o, err)
	}
	if err := s.SaveSession(ctx, "s1", Origin{MaxRole: "root", FromNode: "node-a", FromName: "Node A", Back: "https://a/environment"}); err != nil {
		t.Fatal(err)
	}
	o, err := s.SessionOrigin(ctx, "s1")
	if err != nil || o == nil || o.MaxRole != store.RoleRead || o.FromName != "Node A" || o.Back != "https://a/environment" {
		t.Fatalf("origin: %+v %v", o, err)
	}
	_ = st.DeleteSession(ctx, "s1")
	_ = s.SaveSession(ctx, "s2", Origin{MaxRole: store.RoleAdmin, FromNode: "node-a"})
	var n int
	_ = st.Reader().QueryRow(`SELECT COUNT(*) FROM env_sessions`).Scan(&n)
	if n != 1 {
		t.Fatalf("rows after cleanup: %d", n)
	}
	if o, _ := s.SessionOrigin(ctx, "s2"); o == nil || o.MaxRole != store.RoleAdmin {
		t.Fatalf("admin origin: %+v", o)
	}
}

func TestMinRole(t *testing.T) {
	if MinRole(store.RoleAdmin, store.RoleAdmin) != store.RoleAdmin || MinRole(store.RoleAdmin, store.RoleRead) != store.RoleRead ||
		MinRole("", store.RoleAdmin) != store.RoleRead {
		t.Fatal("MinRole")
	}
}
