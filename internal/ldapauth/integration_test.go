//go:build integration

// Integrationstest gegen echte Verzeichnisse (Samba-AD-DC und OpenLDAP), nur mit Build-Tag integration und gesetzter
// Umgebung (sonst uebersprungen):
//
//	LDAPIT_CA         Pfad zur CA der Testserver (PEM)
//	LDAPIT_SVCPW      Passwort der Dienstkonten (AD svc-node64, LDAP cn=svc)
//	LDAPIT_USERPW     Passwort der Testbenutzer
//	LDAPIT_ANNA_GUID  objectGUID von anna, wie samba-tool sie anzeigt
//
// Erwartete Verzeichnisse: AD n64test.lan auf dc1.n64test.lan (anna, jürgen, "Schmidt, Eva" in Inner ⊂ Middle ⊂ Outer;
// anna zusaetzlich in "Node64 Admins"; gesperrt deaktiviert), OpenLDAP auf ldap1.n64test.lan mit dc=mo,dc=lan
// (memberof-Overlay) und dc=plain,dc=lan (ohne memberOf), je bob und jürgen in groupOfNames staff, bob zusaetzlich in
// groupOfUniqueNames admins und posixGroup posix. Aufbau der Umgebung: testdata/integration/README.md.
package ldapauth

import (
	"crypto/x509"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/authcfg"
)

const (
	itAD    = "dc1.n64test.lan"
	itLDAP  = "ldap1.n64test.lan"
	itBase  = "DC=n64test,DC=lan"
	itInner = "CN=Inner,CN=Users,DC=n64test,DC=lan"
	itMid   = "CN=Middle,CN=Users,DC=n64test,DC=lan"
	itOuter = "CN=Outer,CN=Users,DC=n64test,DC=lan"
	itAdmin = "CN=Node64 Admins,CN=Users,DC=n64test,DC=lan"
)

var reUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type itEnv struct {
	pool          *x509.CertPool
	svcPW, userPW string
	annaGUID      string
}

func itSetup(t *testing.T) itEnv {
	t.Helper()
	caFile := os.Getenv("LDAPIT_CA")
	if caFile == "" {
		t.Skip("LDAPIT_CA not set")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA in " + caFile)
	}
	return itEnv{pool: pool, svcPW: os.Getenv("LDAPIT_SVCPW"), userPW: os.Getenv("LDAPIT_USERPW"), annaGUID: os.Getenv("LDAPIT_ANNA_GUID")}
}

func itADConfig(url string) authcfg.LDAPConfig {
	return authcfg.LDAPConfig{Enabled: true, URLs: []string{url}, StartTLS: strings.HasPrefix(url, "ldap://"), Profile: authcfg.ProfileAD,
		BindDN: "svc-node64@n64test.lan", BaseDN: itBase, Nested: true, TimeoutSec: 10}
}

func itLDAPConfig(url, base string) authcfg.LDAPConfig {
	return authcfg.LDAPConfig{Enabled: true, URLs: []string{url}, StartTLS: strings.HasPrefix(url, "ldap://"), Profile: authcfg.ProfileLDAP,
		BindDN: "cn=svc," + base, BaseDN: base, TimeoutSec: 10}
}

func hasGroups(got []string, want ...string) bool {
	for _, w := range want {
		if !slices.ContainsFunc(got, func(g string) bool { return NormalizeDN(g) == NormalizeDN(w) }) {
			return false
		}
	}
	return true
}

func TestIntegrationAD(t *testing.T) {
	env := itSetup(t)
	ctx := WithRootCAs(t.Context(), env.pool)
	for _, url := range []string{"ldaps://" + itAD, "ldap://" + itAD} {
		t.Run(url, func(t *testing.T) {
			cfg := itADConfig(url)
			res, err := Test(ctx, cfg, env.svcPW, "anna")
			if err != nil {
				t.Fatal(err)
			}
			if !res.TLS || !res.Found || res.Username != "anna" || res.Email != "anna@n64test.lan" || res.Disabled {
				t.Fatalf("test result: %+v", res)
			}
			if len(res.Groups) != 4 || !hasGroups(res.Groups, itInner, itMid, itOuter, itAdmin) {
				t.Fatalf("groups (nested): %v", res.Groups)
			}
			if env.annaGUID != "" && GUIDString(res.StableKey) != strings.ToLower(env.annaGUID) {
				t.Fatalf("objectGUID %s (%s), samba-tool shows %s", res.StableKey, GUIDString(res.StableKey), env.annaGUID)
			}
			t.Logf("tls=%v key=%s (%s) groups=%v", res.TLS, res.StableKey, GUIDString(res.StableKey), res.Groups)
			// Zuordnung wie in der Oberflaeche: nur der Name bzw. DN in anderer Schreibweise
			if !slices.ContainsFunc(res.Groups, func(g string) bool { return MatchGroup("node64 admins", g) }) ||
				!slices.ContainsFunc(res.Groups, func(g string) bool { return MatchGroup("cn=outer, cn=users, dc=n64test, dc=lan", g) }) {
				t.Fatalf("MatchGroup: %v", res.Groups)
			}
			// sAMAccountName, UPN und andere Schreibweise ergeben denselben Benutzer
			for _, name := range []string{"anna", "anna@n64test.lan", "ANNA", "Anna@N64TEST.lan"} {
				id, err := Authenticate(ctx, cfg, env.svcPW, name, env.userPW)
				if err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				if id.Username != "anna" || id.StableKey != res.StableKey || id.DisplayName != "Anna Alt" || !hasGroups(id.GroupDNs, itOuter) {
					t.Fatalf("%s: %+v", name, id)
				}
			}
			if _, err := Authenticate(ctx, cfg, env.svcPW, "anna", env.userPW+"x"); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
			if _, err := Authenticate(ctx, cfg, env.svcPW, "anna", ""); !errors.Is(err, ErrInvalidCredentials) {
				t.Fatalf("empty password: %v", err)
			}
			if _, err := Authenticate(ctx, cfg, env.svcPW, "niemand", env.userPW); !errors.Is(err, ErrUnknownUser) {
				t.Fatalf("unknown user: %v", err)
			}
		})
	}
}

func TestIntegrationADSpecial(t *testing.T) {
	env := itSetup(t)
	ctx := WithRootCAs(t.Context(), env.pool)
	cfg := itADConfig("ldaps://" + itAD)

	// deaktiviert (userAccountControl 514): Test zeigt es, Anmeldung abgelehnt
	if res, err := Test(ctx, cfg, env.svcPW, "gesperrt"); err != nil || !res.Found || !res.Disabled {
		t.Fatalf("disabled probe: %+v %v", res, err)
	}
	if _, err := Authenticate(ctx, cfg, env.svcPW, "gesperrt", env.userPW); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled login: %v", err)
	}

	// Umlaut in Name und DN, beide Schreibweisen
	for _, name := range []string{"jürgen", "Jürgen", "JÜRGEN"} {
		id, err := Authenticate(ctx, cfg, env.svcPW, name, env.userPW)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if id.Username != "jürgen" || id.DisplayName != "Jürgen Müller" || !strings.Contains(id.DN, "Müller") ||
			len(id.GroupDNs) != 3 || !hasGroups(id.GroupDNs, itInner, itMid, itOuter) {
			t.Fatalf("%s: %+v", name, id)
		}
	}

	// Komma im CN (escaped DN im IN_CHAIN-Filter)
	id, err := Authenticate(ctx, cfg, env.svcPW, "eva", env.userPW)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id.DN, `CN=Schmidt\, Eva,`) || len(id.GroupDNs) != 3 || !hasGroups(id.GroupDNs, itInner, itMid, itOuter) {
		t.Fatalf("eva: %+v", id)
	}
	t.Logf("eva: dn=%s groups=%v", id.DN, id.GroupDNs)

	// ohne verschachtelte Gruppen nur memberOf
	flat := cfg
	flat.Nested = false
	if id, err := Authenticate(ctx, flat, env.svcPW, "anna", env.userPW); err != nil || len(id.GroupDNs) != 2 || !hasGroups(id.GroupDNs, itInner, itAdmin) {
		t.Fatalf("not nested: %+v %v", id, err)
	}

	// falsches Bind-Passwort, fremde CA, Klartext ohne StartTLS
	if _, err := Test(ctx, cfg, env.svcPW+"x", ""); err == nil || strings.Contains(err.Error(), env.svcPW) {
		t.Fatalf("wrong bind password: %v", err)
	}
	if _, err := Test(t.Context(), cfg, env.svcPW, ""); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("unknown CA: %v", err)
	}
	plain := itADConfig("ldap://" + itAD)
	plain.StartTLS, plain.AllowPlain = false, true
	if _, err := Test(ctx, plain, env.svcPW, ""); err == nil {
		t.Fatal("AD accepted a simple bind without TLS")
	}
}

func TestIntegrationLDAP(t *testing.T) {
	env := itSetup(t)
	ctx := WithRootCAs(t.Context(), env.pool)
	for _, base := range []string{"dc=mo,dc=lan", "dc=plain,dc=lan"} {
		staff, admins, posix := "cn=staff,ou=groups,"+base, "cn=admins,ou=groups,"+base, "cn=posix,ou=groups,"+base
		for _, url := range []string{"ldaps://" + itLDAP, "ldap://" + itLDAP} {
			t.Run(base+" "+url, func(t *testing.T) {
				cfg := itLDAPConfig(url, base)
				res, err := Test(ctx, cfg, env.svcPW, "bob")
				if err != nil {
					t.Fatal(err)
				}
				if !res.TLS || !res.Found || res.Username != "bob" || res.DisplayName != "Bob Bauer" || !reUUID.MatchString(res.StableKey) {
					t.Fatalf("test result: %+v", res)
				}
				// mit Overlay nur memberOf (groupOfNames), ohne Overlay Suche ueber alle drei Gruppenarten
				want := []string{staff}
				if base == "dc=plain,dc=lan" {
					want = []string{staff, admins, posix}
				}
				if len(res.Groups) != len(want) || !hasGroups(res.Groups, want...) {
					t.Fatalf("groups: %v, want %v", res.Groups, want)
				}
				t.Logf("tls=%v key=%s groups=%v", res.TLS, res.StableKey, res.Groups)
				id, err := Authenticate(ctx, cfg, env.svcPW, "BOB", env.userPW)
				if err != nil || id.StableKey != res.StableKey || id.Username != "bob" {
					t.Fatalf("bob: %+v %v", id, err)
				}
				if _, err := Authenticate(ctx, cfg, env.svcPW, "bob", env.userPW+"x"); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("wrong password: %v", err)
				}
				for _, name := range []string{"jürgen", "JÜRGEN"} {
					id, err := Authenticate(ctx, cfg, env.svcPW, name, env.userPW)
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
					if id.Username != "jürgen" || id.DisplayName != "Jürgen Müller" || !reUUID.MatchString(id.StableKey) ||
						len(id.GroupDNs) != 1 || !hasGroups(id.GroupDNs, staff) {
						t.Fatalf("%s: %+v", name, id)
					}
				}
			})
		}
	}
}
