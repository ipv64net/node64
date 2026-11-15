package web

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/ldapauth/ldaptest"
	"github.com/ipv64net/node64/internal/store"
)

// Befunde aus dem Code-Review der Benutzerverwaltung (AD/LDAP, SSO, Anmeldung).

type countWatcher struct{ n atomic.Int32 }

func (c *countWatcher) LoginFailed(netip.Addr, int, bool) { c.n.Add(1) }

// Befund 5: nur falsches Passwort und unbekannter Name zaehlen als Fehlversuch; Verzeichnis-Fehler und Ablehnungen
// mit richtigem Passwort nicht.
func TestLDAPOnlyRealFailuresCount(t *testing.T) {
	e := newLDAPEnv(t)
	w := &countWatcher{}
	e.a.s.SetLoginWatcher(w)
	if resp := e.login(t, "mmuster", "falsch"); resp.StatusCode != http.StatusUnauthorized || w.n.Load() != 1 {
		t.Fatalf("wrong password: %d, count %d", resp.StatusCode, w.n.Load())
	}
	if resp := e.login(t, "niemand", "egal"); resp.StatusCode != http.StatusUnauthorized || w.n.Load() != 2 {
		t.Fatalf("unknown user: %d, count %d", resp.StatusCode, w.n.Load())
	}
	e.unthrottle()
	if resp := e.login(t, "bert", "ad-passwort-2"); resp.StatusCode != http.StatusUnauthorized || w.n.Load() != 2 {
		t.Fatalf("no group must not count: %d, count %d", resp.StatusCode, w.n.Load())
	}
	// Verzeichnis nicht erreichbar: kein Fehlversuch, eigene Meldung, Versuch zurueck
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := "ldap://" + ln.Addr().String()
	ln.Close()
	cfg := authcfg.LoadLDAP(context.Background(), e.a.store)
	cfg.URLs = []string{dead}
	cfg.TimeoutSec = 1
	_ = authcfg.SaveLDAP(context.Background(), e.a.store, cfg)
	for range 8 { // mehr als die Bremse erlaubt: der Versuch kommt jedes Mal zurueck
		if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("unreachable: %d", resp.StatusCode)
		}
	}
	if w.n.Load() != 2 {
		t.Fatalf("directory errors must not count: %d", w.n.Load())
	}
	if e.lastAudit(t, "login.ldap_error") == nil {
		t.Fatal("audit login.ldap_error")
	}
}

// Befund 6: fehlgeschlagene Anmeldungen antworten gleich spaet, egal ob der Name lokal, im Verzeichnis oder unbekannt ist.
func TestLoginFailTimingFloor(t *testing.T) {
	e := newLDAPEnv(t)
	loginFailFloor = 300 * time.Millisecond
	t.Cleanup(func() { loginFailFloor = 0 })
	for _, c := range [][2]string{{"admin", "falsch"}, {"niemand", "falsch"}, {"mmuster", "falsch"}} {
		e.unthrottle()
		start := time.Now()
		if resp := e.login(t, c[0], c[1]); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s: %d", c[0], resp.StatusCode)
		}
		if d := time.Since(start); d < 300*time.Millisecond {
			t.Fatalf("%s answered after %v (floor 300ms)", c[0], d)
		}
	}
}

// Befund 3: das gespeicherte Bind-Passwort geht nur an denselben Server mit demselben Konto und denselben
// TLS-Einstellungen; sonst muss es neu eingegeben werden.
func TestLDAPStoredBindPasswordOnlyForSameTarget(t *testing.T) {
	e := newLDAPEnv(t)
	a, ctx := e.a, context.Background()
	u, _ := a.store.UserByName(ctx, "admin")
	key, _, _ := a.store.NewAPIKey(ctx, u.ID, "script")
	stored := authcfg.LoadLDAP(ctx, a.store).BindPasswordEnc
	base := func() map[string]any {
		return map[string]any{"enabled": true, "urls": []string{e.dir.URL("ldap")}, "allow_plain": true, "profile": "ad", "bind_dn": ldaptest.Service,
			"bind_password": "", "base_dn": "dc=example,dc=org", "nested": true}
	}
	if code, out := apiCall(t, a, key, "PUT", "/api/auth/ldap", base()); code != 200 {
		t.Fatalf("same target: %d %v", code, out)
	}
	if authcfg.LoadLDAP(ctx, a.store).BindPasswordEnc != stored {
		t.Fatal("same target must keep the stored password")
	}
	other := ldaptest.New(t, false) // fremder Server
	for name, change := range map[string]func(m map[string]any){
		"url":     func(m map[string]any) { m["urls"] = []string{other.URL("ldap")} },
		"bind_dn": func(m map[string]any) { m["bind_dn"] = "CN=Anderer,DC=example,DC=org" },
		"tls":     func(m map[string]any) { m["skip_verify"] = true },
	} {
		in := base()
		change(in)
		if code, out := apiCall(t, a, key, "PUT", "/api/auth/ldap", in); code != http.StatusUnprocessableEntity || out.(map[string]any)["field"] != "bind_password" {
			t.Fatalf("%s changed, save: %d %v", name, code, out)
		}
		if code, out := apiCall(t, a, key, "POST", "/api/auth/ldap/test", map[string]any{"username": "x", "config": in}); code != http.StatusUnprocessableEntity {
			t.Fatalf("%s changed, test: %d %v", name, code, out)
		}
	}
	if binds, _, _ := other.Stats(); len(binds) != 0 {
		t.Fatalf("stored password sent to another server: %v", binds)
	}
	if authcfg.LoadLDAP(ctx, a.store).BindPasswordEnc != stored {
		t.Fatal("refused save changed the stored password")
	}
}

// Befund 2: Rollen aus LDAP-Gruppen werden nachgeprueft – abgelehnte Anmeldung, Passkey-Anmeldung (ldapRecheck) und
// regelmaessiger Abgleich (ldapSyncGroups) nehmen die Gruppen weg.
func TestLDAPGroupsRevoked(t *testing.T) {
	e := newLDAPEnv(t)
	ctx := context.Background()
	e.dir.Set(tAdminsDN, "member", tMaxDN, "CN=Jemand,DC=example,DC=org")
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	e.logout(t)
	max, _ := e.a.store.UserByName(ctx, "mmuster")
	if e.a.store.EffectiveRole(ctx, max) != store.RoleAdmin {
		t.Fatal("admin via group expected")
	}
	// regelmaessiger Abgleich: aus der Admin-Gruppe entfernt -> nur noch lesen (z. B. fuer API-Keys)
	e.dir.Set(tAdminsDN, "member", "CN=Jemand,DC=example,DC=org")
	e.a.s.ldapSyncGroups(ctx)
	max, _ = e.a.store.UserByName(ctx, "mmuster")
	if e.a.store.EffectiveRole(ctx, max) != store.RoleRead || len(max.ExtGroupUIDs) != 1 {
		t.Fatalf("sync must drop the admin group: %+v", max.ExtGroupUIDs)
	}
	// Passkey-Anmeldung: im Verzeichnis deaktiviert -> abgelehnt, Gruppen weg
	e.dir.Set(tMaxDN, "userAccountControl", "514")
	if ok, reason := e.a.s.ldapRecheck(ctx, max); ok || reason == "" {
		t.Fatal("disabled account must be refused on passkey login")
	}
	if max, _ = e.a.store.UserByName(ctx, "mmuster"); len(max.ExtGroupUIDs) != 0 {
		t.Fatalf("groups must be gone: %v", max.ExtGroupUIDs)
	}
	// wieder aktiv: Passkey-Anmeldung uebernimmt die Gruppen
	e.dir.Set(tMaxDN, "userAccountControl", "512")
	if ok, _ := e.a.s.ldapRecheck(ctx, max); !ok {
		t.Fatal("active account must pass the recheck")
	}
	// abgelehnte Passwort-Anmeldung (deaktiviert) nimmt die Gruppen weg
	e.dir.Set(tMaxDN, "userAccountControl", "514")
	e.unthrottle()
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("disabled login: %d", resp.StatusCode)
	}
	if max, _ = e.a.store.UserByName(ctx, "mmuster"); len(max.ExtGroupUIDs) != 0 {
		t.Fatalf("denied login must clear the groups: %v", max.ExtGroupUIDs)
	}
	// keine passende Gruppe mehr: Anmeldung abgelehnt, Gruppen weg
	e.dir.Set(tMaxDN, "userAccountControl", "512")
	e.dir.Set(tMaxDN, "memberOf", tOtherDN)
	e.dir.Set(tStaffDN, "member", "CN=Kollege,OU=Users,DC=example,DC=org")
	_ = e.a.store.SetUserExtGroups(ctx, max.ID, []string{e.read.UID})
	if resp := e.login(t, "mmuster", "ad-passwort-1"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no group login: %d", resp.StatusCode)
	}
	if max, _ = e.a.store.UserByName(ctx, "mmuster"); len(max.ExtGroupUIDs) != 0 {
		t.Fatalf("no group must clear the groups: %v", max.ExtGroupUIDs)
	}
	// Verzeichnis nicht erreichbar: Passkey-Anmeldung geht, Stand bleibt (laeuft nach store.ExtMaxAgeLDAP ab)
	_ = e.a.store.SetUserExtGroups(ctx, max.ID, []string{e.read.UID})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	cfg := authcfg.LoadLDAP(ctx, e.a.store)
	cfg.URLs, cfg.TimeoutSec = []string{"ldap://" + ln.Addr().String()}, 1
	ln.Close()
	_ = authcfg.SaveLDAP(ctx, e.a.store, cfg)
	if ok, _ := e.a.s.ldapRecheck(ctx, max); !ok {
		t.Fatal("unreachable directory must not lock out")
	}
	e.a.s.ldapSyncGroups(ctx)
	if max, _ = e.a.store.UserByName(ctx, "mmuster"); len(max.ExtGroupUIDs) != 1 {
		t.Fatal("failed sync must keep the last state")
	}
}
