package ldapauth

import (
	"context"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/ldapauth/ldaptest"
)

const (
	adBase   = "dc=example,dc=org"
	maxDN    = "CN=Max Muster,OU=Users,DC=example,DC=org"
	guidRaw  = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
	guidHex  = "0102030405060708090a0b0c0d0e0f10"
	adminsDN = "CN=Node64 Admins,OU=Groups,DC=example,DC=org"
	staffDN  = "CN=Staff,OU=Groups,DC=example,DC=org"
	allDN    = "CN=Alle,OU=Groups,DC=example,DC=org"
)

// adDirectory: AD-artiges Verzeichnis; Max ist direkt in Staff (memberOf) und ueber Staff verschachtelt in Alle.
func adDirectory(t *testing.T, ldaps bool) *ldaptest.Server {
	f := ldaptest.New(t, ldaps)
	f.Add(maxDN, map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"MMuster"}, "userPrincipalName": {"max@example.org"},
		"displayName": {"Max Muster"}, "mail": {"max@example.org"}, "memberOf": {staffDN}, "objectGUID": {guidRaw},
		"userAccountControl": {"512"}, "userPassword": {"richtig-geheim"}})
	f.Add("CN=Gesperrt,OU=Users,DC=example,DC=org", map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"gesperrt"},
		"userAccountControl": {"514"}, "userPassword": {"richtig-geheim"}, "objectGUID": {"\xff\xff"}})
	f.Add(staffDN, map[string][]string{"objectClass": {"group"}, "member": {maxDN}})
	f.Add(allDN, map[string][]string{"objectClass": {"group"}, "member": {staffDN}})
	f.Add(adminsDN, map[string][]string{"objectClass": {"group"}, "member": {"CN=Jemand,DC=example,DC=org"}})
	return f
}

func adConfig(f *ldaptest.Server, urls ...string) authcfg.LDAPConfig {
	if len(urls) == 0 {
		urls = []string{f.URL("ldap")}
	}
	return authcfg.LDAPConfig{Enabled: true, URLs: urls, StartTLS: true, Profile: authcfg.ProfileAD, BindDN: ldaptest.Service,
		BaseDN: adBase, Nested: true, TimeoutSec: 5}
}

func ctxCA(t *testing.T, f *ldaptest.Server) context.Context { return WithRootCAs(t.Context(), f.Pool) }

func TestAuthenticateAD(t *testing.T) {
	f := adDirectory(t, false)
	id, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "MMuster", "richtig-geheim")
	if err != nil {
		t.Fatal(err)
	}
	if id.StableKey != guidHex || id.Username != "mmuster" || id.DisplayName != "Max Muster" || id.Email != "max@example.org" || id.DN != maxDN {
		t.Fatalf("identity: %+v", id)
	}
	if len(id.GroupDNs) != 2 || !slices.Contains(id.GroupDNs, staffDN) || !slices.Contains(id.GroupDNs, allDN) {
		t.Fatalf("groups (memberOf + nested): %v", id.GroupDNs)
	}
	// auch per userPrincipalName; Benutzername bleibt sAMAccountName
	if id, err = Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "max@example.org", "richtig-geheim"); err != nil || id.Username != "mmuster" {
		t.Fatalf("upn: %v %+v", err, id)
	}
	// ohne Verschachtelung nur memberOf
	cfg := adConfig(f)
	cfg.Nested = false
	if id, err = Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "mmuster", "richtig-geheim"); err != nil || len(id.GroupDNs) != 1 || id.GroupDNs[0] != staffDN {
		t.Fatalf("memberOf only: %v %+v", err, id)
	}
	if GUIDString(guidHex) != "04030201-0605-0807-090a-0b0c0d0e0f10" {
		t.Fatal(GUIDString(guidHex))
	}
}

func TestAuthenticateWrongAndEmptyPassword(t *testing.T) {
	f := adDirectory(t, false)
	if _, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "mmuster", "falsch"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	_, _, conns := f.Stats()
	// leeres Passwort: nie ans Verzeichnis (unauthenticated bind wuerde dort gelingen)
	for _, pw := range []string{""} {
		if _, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "mmuster", pw); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("empty password: %v", err)
		}
	}
	if _, empty, c := f.Stats(); empty != 0 || c != conns {
		t.Fatalf("empty password reached the server: empty binds %d, conns %d->%d", empty, conns, c)
	}
	// falsches Bind-Passwort des Dienstkontos: Fehler ohne das Passwort im Text
	_, err := Authenticate(ctxCA(t, f), adConfig(f), "dienst-geheim", "mmuster", "richtig-geheim")
	if err == nil || strings.Contains(err.Error(), "dienst-geheim") || strings.Contains(err.Error(), "richtig-geheim") {
		t.Fatalf("service bind: %v", err)
	}
	if _, err := Authenticate(ctxCA(t, f), adConfig(f), "", "mmuster", "richtig-geheim"); !errors.Is(err, ErrConfig) {
		t.Fatalf("missing bind password: %v", err)
	}
}

func TestAuthenticateFilterInjection(t *testing.T) {
	f := adDirectory(t, false)
	f.Add("CN=Zweiter,OU=Users,DC=example,DC=org", map[string][]string{"objectClass": {"user"}, "sAMAccountName": {"zweiter"}, "userPassword": {"richtig-geheim"}})
	for _, name := range []string{"*", "mmuster)(sAMAccountName=*", "*)(|(objectClass=*", `mm\2a`, "mmuster\x00"} {
		_, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, name, "richtig-geheim")
		if !errors.Is(err, ErrUnknownUser) && !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	for _, s := range f.Searches() { // ein "*" kommt als Wert an, nie als Praesenzfilter; die Struktur bleibt
		if strings.Contains(s, "=*)") || !strings.HasPrefix(s, `(&(objectClass="user")(|(sAMAccountName=`) {
			t.Errorf("filter structure changed: %s", s)
		}
	}
	// Ein Filter, der mehrere Eintraege findet, meldet sich nicht still mit dem ersten an
	cfg := adConfig(f)
	cfg.UserFilter = "(objectClass=user)"
	if _, err := Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "egal", "richtig-geheim"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("ambiguous: %v", err)
	}
}

func TestAuthenticateDisabledAD(t *testing.T) {
	f := adDirectory(t, false)
	if _, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "gesperrt", "richtig-geheim"); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	if _, err := Authenticate(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "unbekannt", "x"); !errors.Is(err, ErrUnknownUser) {
		t.Fatalf("unknown: %v", err)
	}
}

func TestAuthenticateLDAPGroups(t *testing.T) {
	f := ldaptest.New(t, true) // ldaps
	f.Add("uid=anna,ou=people,dc=example,dc=org", map[string][]string{"objectClass": {"person"}, "uid": {"Anna"}, "cn": {"Anna A"},
		"entryUUID": {"6F1E0D1C-0000-4000-8000-000000000001"}, "userPassword": {"anna-pw-123"}})
	f.Add("uid=bert,ou=people,dc=example,dc=org", map[string][]string{"objectClass": {"person"}, "uid": {"bert"},
		"memberOf": {"cn=direkt,ou=groups,dc=example,dc=org"}, "userPassword": {"bert-pw-123"}})
	f.Add("cn=admins,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"groupOfNames"}, "member": {"uid=anna,ou=people,dc=example,dc=org"}})
	f.Add("cn=uniq,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"groupOfUniqueNames"}, "uniqueMember": {"UID=Anna,OU=People,DC=Example,DC=Org"}})
	f.Add("cn=posix,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"posixGroup"}, "memberUid": {"anna"}})
	f.Add("cn=fremd,ou=groups,dc=example,dc=org", map[string][]string{"objectClass": {"groupOfNames"}, "member": {"uid=bert,ou=people,dc=example,dc=org"}})
	cfg := authcfg.LDAPConfig{Enabled: true, URLs: []string{f.URL("ldaps")}, Profile: authcfg.ProfileLDAP, BindDN: ldaptest.Service, BaseDN: adBase}
	id, err := Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "anna", "anna-pw-123")
	if err != nil {
		t.Fatal(err)
	}
	if id.StableKey != "6f1e0d1c-0000-4000-8000-000000000001" || id.Username != "anna" || id.DisplayName != "Anna A" {
		t.Fatalf("identity: %+v", id)
	}
	if len(id.GroupDNs) != 3 {
		t.Fatalf("group search (member, uniqueMember, memberUid): %v", id.GroupDNs)
	}
	// memberOf vorhanden: keine Gruppensuche
	id, err = Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "bert", "bert-pw-123")
	if err != nil || len(id.GroupDNs) != 1 || id.GroupDNs[0] != "cn=direkt,ou=groups,dc=example,dc=org" {
		t.Fatalf("memberOf: %v %+v", err, id)
	}
	if id.StableKey != "uid=bert,ou=people,dc=example,dc=org" {
		t.Fatalf("stable key falls back to the dn: %q", id.StableKey)
	}
}

func TestConnectTLSAndURLs(t *testing.T) {
	f := adDirectory(t, true)
	// Zertifikat unbekannt: abgelehnt; mit eigener CA oder (nur mit Schalter) ohne Pruefung: geht
	cfg := adConfig(f, f.URL("ldaps"))
	if _, err := Test(t.Context(), cfg, ldaptest.ServicePassword, ""); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("unknown certificate must fail: %v", err)
	}
	if r, err := Test(ctxCA(t, f), cfg, ldaptest.ServicePassword, ""); err != nil || !r.TLS || r.URL != f.URL("ldaps") {
		t.Fatalf("own CA: %v %+v", err, r)
	}
	cfg.SkipVerify = true
	if _, err := Test(t.Context(), cfg, ldaptest.ServicePassword, ""); err != nil {
		t.Fatalf("skip verify: %v", err)
	}

	// mehrere Server: der erste ist tot
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadURL := "ldaps://" + dead.Addr().String()
	_ = dead.Close()
	cfg = adConfig(f, deadURL, f.URL("ldaps"))
	id, err := Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "mmuster", "richtig-geheim")
	if err != nil || id.Username != "mmuster" {
		t.Fatalf("failover: %v", err)
	}
	cfg = adConfig(f, deadURL)
	if _, err := Authenticate(ctxCA(t, f), cfg, ldaptest.ServicePassword, "mmuster", "richtig-geheim"); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("all dead: %v", err)
	}

	// Klartext nur mit Schalter
	p := adDirectory(t, false)
	cfg = adConfig(p)
	cfg.StartTLS = false
	if _, err := Test(ctxCA(t, p), cfg, ldaptest.ServicePassword, ""); err == nil || !strings.Contains(err.Error(), "StartTLS") {
		t.Fatalf("plain without switch: %v", err)
	}
	cfg.AllowPlain = true
	if r, err := Test(ctxCA(t, p), cfg, ldaptest.ServicePassword, ""); err != nil || r.TLS {
		t.Fatalf("plain allowed: %v %+v", err, r)
	}
	cfg.StartTLS = true
	if r, err := Test(ctxCA(t, p), cfg, ldaptest.ServicePassword, ""); err != nil || !r.TLS {
		t.Fatalf("starttls: %v %+v", err, r)
	}
}

func TestProbe(t *testing.T) {
	f := adDirectory(t, false)
	r, err := Test(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "mmuster")
	if err != nil || !r.Found || r.DN != maxDN || len(r.Groups) != 2 || r.StableKey != guidHex || r.Disabled {
		t.Fatalf("probe: %v %+v", err, r)
	}
	if r, err = Test(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "gesperrt"); err != nil || !r.Found || !r.Disabled {
		t.Fatalf("probe disabled: %v %+v", err, r)
	}
	if r, err = Test(ctxCA(t, f), adConfig(f), ldaptest.ServicePassword, "niemand"); err != nil || r.Found {
		t.Fatalf("probe unknown: %v %+v", err, r)
	}
	binds, _, _ := f.Stats()
	for _, b := range binds {
		if b != ldaptest.Service {
			t.Fatalf("test must only bind the service account, got %q", b)
		}
	}
}

func TestMatchGroup(t *testing.T) {
	for _, tc := range []struct {
		m, dn string
		ok    bool
	}{
		{"CN=Node64 Admins,OU=Groups,DC=example,DC=org", "cn=node64 admins, ou=groups, dc=example, dc=org", true},
		{"cn=node64 admins,ou=groups,dc=example,dc=org", "CN=Node64 Admins,OU=Other,DC=example,DC=org", false},
		{"node64 admins", adminsDN, true},
		{"admins", adminsDN, false},
		{"", adminsDN, false},
		{`cn=a\,b,dc=x`, `CN=A\,B,DC=X`, true},
		{`cn=a\,b,dc=x`, `cn=a,cn=b,dc=x`, false},
	} {
		if MatchGroup(tc.m, tc.dn) != tc.ok {
			t.Errorf("MatchGroup(%q, %q) != %v", tc.m, tc.dn, tc.ok)
		}
	}
}

func TestCheckURL(t *testing.T) {
	cfg := authcfg.LDAPConfig{}
	for raw, ok := range map[string]bool{"ldaps://dc1.example.org": true, "ldaps://dc1:636": true, "ldap://dc1": false, "http://dc1": false,
		"ldaps://": false, "ldaps://dc1/dc=x": false, "ldaps://u:p@dc1": false, "ldaps://dc1:99999": false} {
		if (CheckURL(cfg, raw) == nil) != ok {
			t.Errorf("CheckURL(%q) ok=%v", raw, !ok)
		}
	}
	cfg.StartTLS = true
	if CheckURL(cfg, "ldap://dc1:389") != nil {
		t.Error("ldap:// with StartTLS")
	}
}
