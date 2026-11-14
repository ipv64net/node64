// Package authcfg haelt die Einstellungen der Anmeldung, die Oberflaeche (internal/web), LDAP-Anbindung
// (internal/ldapauth) und Cluster (internal/usercluster) gemeinsam nutzen: AD/LDAP, 2FA-Pflicht und Anlage von
// SSO-Benutzern ueber Gruppen. Nur lokal fuer Node64 (kein Bezug zu ipv64.net).
package authcfg

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/ipv64net/node64/internal/store"
)

const (
	// SetLDAP: AD/LDAP-Anbindung als JSON (LDAPConfig); das Bind-Passwort steht mit secret.key verschluesselt darin.
	SetLDAP = "auth.ldap"
	// Set2FARequired: "1" = jeder lokale und LDAP-Benutzer braucht 2FA (SSO-Benutzer erledigen das beim Anbieter).
	Set2FARequired = "auth.2fa_required"
	// SetOIDCJIT: "1" = SSO legt Benutzer ueber den Gruppen-Claim an (Standard aus: nur verknuepfte Konten).
	SetOIDCJIT = "auth.oidc.jit"
	// SetOIDCGroupClaim: Name des Gruppen-Claims (Standard "groups").
	SetOIDCGroupClaim = "auth.oidc.group_claim"

	// Cluster: Bereich directory, ein Eintrag mit dieser Kennung (LDAP + 2FA-Pflicht)
	DirectoryID = "auth"

	ProfileAD   = "ad"   // Active Directory (sAMAccountName/userPrincipalName, memberOf verschachtelt)
	ProfileLDAP = "ldap" // OpenLDAP, LDAP64, lldap … (uid, memberOf bzw. groupOfNames)
)

// LDAPConfig ist die AD/LDAP-Anbindung (Client: Node64 meldet Benutzer gegen ein vorhandenes Verzeichnis an).
type LDAPConfig struct {
	Enabled         bool     `json:"enabled"`
	URLs            []string `json:"urls"`              // ldaps://host:636 oder ldap://host:389 (dann StartTLS)
	StartTLS        bool     `json:"starttls"`          // bei ldap:// StartTLS verlangen
	AllowPlain      bool     `json:"allow_plain"`       // ldap:// ohne TLS erlauben (nur Altgeraete)
	SkipVerify      bool     `json:"skip_verify"`       // Zertifikat nicht pruefen (Warnung in der Oberflaeche)
	Profile         string   `json:"profile"`           // ProfileAD oder ProfileLDAP
	BindDN          string   `json:"bind_dn"`           // Dienstkonto
	BindPasswordEnc string   `json:"bind_password_enc"` // mit secret.key verschluesselt (nie im Klartext gespeichert)
	BaseDN          string   `json:"base_dn"`
	UserFilter      string   `json:"user_filter"` // leer = Vorgabe des Profils; %s = Benutzername (escaped)
	Nested          bool     `json:"nested"`      // AD: verschachtelte Gruppen (LDAP_MATCHING_RULE_IN_CHAIN)
	TimeoutSec      int      `json:"timeout_sec"` // 0 = 10 s
}

// DefaultFilter: Benutzerfilter des Profils.
func (c LDAPConfig) DefaultFilter() string {
	if c.Profile == ProfileAD {
		return "(&(objectClass=user)(|(sAMAccountName=%s)(userPrincipalName=%s)))"
	}
	return "(&(objectClass=person)(uid=%s))"
}

// Filter: eingestellter oder vorgegebener Benutzerfilter.
func (c LDAPConfig) Filter() string {
	if strings.TrimSpace(c.UserFilter) != "" {
		return c.UserFilter
	}
	return c.DefaultFilter()
}

// LoadLDAP liest die Anbindung (ohne Einstellung: aus, Profil AD).
func LoadLDAP(ctx context.Context, st *store.Store) LDAPConfig {
	c := LDAPConfig{Profile: ProfileAD, Nested: true}
	_ = json.Unmarshal([]byte(st.SettingOr(ctx, SetLDAP, "{}")), &c)
	if c.Profile != ProfileLDAP {
		c.Profile = ProfileAD
	}
	return c
}

// SaveLDAP speichert die Anbindung und meldet sie an den Cluster (Bereich directory).
func SaveLDAP(ctx context.Context, st *store.Store, c LDAPConfig) error {
	b, _ := json.Marshal(c)
	if err := st.SetSetting(ctx, SetLDAP, string(b)); err != nil {
		return err
	}
	st.LoginChanged(ctx, "directory", DirectoryID, false)
	return nil
}

// TwoFARequired: Schalter „2FA fuer alle Pflicht“.
func TwoFARequired(ctx context.Context, st *store.Store) bool {
	return st.SettingOr(ctx, Set2FARequired, "0") == "1"
}

// SetTwoFARequired schaltet die 2FA-Pflicht und meldet sie an den Cluster (Bereich directory).
func SetTwoFARequired(ctx context.Context, st *store.Store, on bool) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := st.SetSetting(ctx, Set2FARequired, v); err != nil {
		return err
	}
	st.LoginChanged(ctx, "directory", DirectoryID, false)
	return nil
}

// SaveOIDCJIT speichert „Benutzer ueber Gruppen anlegen“ und den Claim-Namen ("" = Standard) und meldet die
// SSO-Einrichtung an den Cluster (Bereich sso, Kennung "oidc" wie usercluster). Ohne eingerichtetes SSO gibt es dort
// nichts zu melden (es wuerde als Entfernen gelten); die Werte gehen mit dem naechsten Speichern des SSO mit.
func SaveOIDCJIT(ctx context.Context, st *store.Store, on bool, claim string) error {
	v := "0"
	if on {
		v = "1"
	}
	if err := st.SetSetting(ctx, SetOIDCJIT, v); err != nil {
		return err
	}
	if err := st.SetSetting(ctx, SetOIDCGroupClaim, strings.TrimSpace(claim)); err != nil {
		return err
	}
	if st.SettingOr(ctx, "auth.oidc.issuer", "") != "" {
		st.LoginChanged(ctx, "sso", "oidc", false)
	}
	return nil
}

// OIDCJIT: SSO legt Benutzer ueber den Gruppen-Claim an; Claim-Name (Standard "groups").
func OIDCJIT(ctx context.Context, st *store.Store) (on bool, claim string) {
	claim = strings.TrimSpace(st.SettingOr(ctx, SetOIDCGroupClaim, ""))
	if claim == "" {
		claim = "groups"
	}
	return st.SettingOr(ctx, SetOIDCJIT, "0") == "1", claim
}
