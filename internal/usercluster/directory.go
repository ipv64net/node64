package usercluster

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/peer"
	"github.com/ipv64net/node64/internal/store"
)

// Bereich directory (ein Eintrag authcfg.DirectoryID): AD/LDAP-Anbindung und der Schalter „2FA fuer alle Pflicht“,
// damit jede Node dieselbe Regel hat. Beide Teile tragen ihren Zeitpunkt (authcfg.SetLDAPAt, Set2FARequiredAt): je
// Teil gewinnt die juengere Aenderung, ein hier nie gespeicherter Teil geht als unset hinaus und aendert drueben
// nichts. So verteilt eine Node ohne LDAP-Einrichtung beim Schalten der 2FA-Pflicht keine leere Anbindung, und das
// Speichern von LDAP nimmt eine juengere 2FA-Pflicht einer anderen Node nicht zurueck. Behaelt die Node einen Teil,
// den die andere nicht oder nur aelter hat, meldet sie den zusammengefuehrten Stand neu (keptError). Aeltere Nodes
// (bis 1.7.10) senden weder Zeitpunkte noch unset: dann gilt fuer beide Teile der Zeitpunkt ihrer Aenderung.
// Das Bind-Passwort geht wie das SSO-Client-Secret im Klartext ueber die Cluster-Verbindung und wird beim Empfaenger
// mit dessen secret.key neu verschluesselt; laesst es sich hier nicht entschluesseln, geht der Eintrag als incomplete
// hinaus und die anderen behalten ihren Stand. Einstellungen werden nie geloescht (ein Loeschvermerk aendert nichts).

// clusterDirectory ist directory im Cluster (Bind-Passwort im Klartext, BindPasswordEnc leer).
type clusterDirectory struct {
	LDAP          authcfg.LDAPConfig `json:"ldap"`
	BindPassword  string             `json:"bind_password,omitempty"`
	TwoFARequired bool               `json:"twofa_required"`
	Incomplete    bool               `json:"incomplete,omitempty"`
	// je Teil: hier nie gespeichert bzw. Zeitpunkt der letzten Aenderung (stampUnknown = unbekannt)
	LDAPUnset  bool   `json:"ldap_unset,omitempty"`
	TwoFAUnset bool   `json:"twofa_unset,omitempty"`
	LDAPAt     string `json:"ldap_at,omitempty"`
	TwoFAAt    string `json:"twofa_at,omitempty"`
}

// hasDirectory: LDAP oder 2FA-Pflicht wurden hier schon einmal gespeichert.
func (c *Cluster) hasDirectory(ctx context.Context) bool {
	return c.st.SettingOr(ctx, authcfg.SetLDAP, "") != "" || c.st.SettingOr(ctx, authcfg.Set2FARequired, "") != ""
}

func (c *Cluster) getDirectory(ctx context.Context, id string) (json.RawMessage, bool, error) {
	if id != authcfg.DirectoryID || !c.hasDirectory(ctx) {
		return nil, false, nil
	}
	out := clusterDirectory{LDAP: authcfg.LoadLDAP(ctx, c.st), TwoFARequired: authcfg.TwoFARequired(ctx, c.st),
		LDAPUnset: c.st.SettingOr(ctx, authcfg.SetLDAP, "") == "", TwoFAUnset: c.st.SettingOr(ctx, authcfg.Set2FARequired, "") == "",
		LDAPAt: stampOut(c.st.SettingOr(ctx, authcfg.SetLDAPAt, "")), TwoFAAt: stampOut(c.st.SettingOr(ctx, authcfg.Set2FARequiredAt, ""))}
	if enc := out.LDAP.BindPasswordEnc; enc != "" {
		if c.box == nil {
			out.Incomplete = true
		} else if v, err := c.box.Decrypt(enc); err != nil {
			out.Incomplete = true
		} else {
			out.BindPassword = v
		}
	}
	out.LDAP.BindPasswordEnc = ""
	b, err := json.Marshal(out)
	return b, err == nil, err
}

func (c *Cluster) applyDirectory(ctx context.Context, data json.RawMessage, deleted bool) error {
	if deleted {
		return nil // nie geloescht: die Node behaelt ihre Einstellungen
	}
	var in clusterDirectory
	if err := json.Unmarshal(data, &in); err != nil {
		return err
	}
	if in.Incomplete {
		return nil
	}
	_, at, _ := peer.ClusterOrigin(ctx)
	ldapAt, twoFAAt := stamp(in.LDAPAt, at, false), stamp(in.TwoFAAt, at, false)
	var ldap *authcfg.LDAPConfig
	var twoFA *bool
	kept := false // hier ein Teil, den die andere Node nicht oder nur aelter hat
	switch {
	case in.LDAPUnset:
		kept = c.st.SettingOr(ctx, authcfg.SetLDAP, "") != ""
	case ldapAt.Before(store.ParseTime(c.st.SettingOr(ctx, authcfg.SetLDAPAt, ""))):
		kept = true
	default:
		if in.LDAP.Profile != authcfg.ProfileLDAP {
			in.LDAP.Profile = authcfg.ProfileAD
		}
		in.LDAP.TimeoutSec = max(in.LDAP.TimeoutSec, 0)
		in.LDAP.BindPasswordEnc = "" // nie einen fremden verschluesselten Wert uebernehmen
		if in.BindPassword != "" && c.box != nil {
			in.LDAP.BindPasswordEnc = c.box.Encrypt(in.BindPassword)
		}
		ldap = &in.LDAP
	}
	switch {
	case in.TwoFAUnset:
		kept = kept || c.st.SettingOr(ctx, authcfg.Set2FARequired, "") != ""
	case twoFAAt.Before(store.ParseTime(c.st.SettingOr(ctx, authcfg.Set2FARequiredAt, ""))):
		kept = true
	default:
		twoFA = &in.TwoFARequired
	}
	if ldap != nil || twoFA != nil {
		if err := authcfg.ApplyDirectory(ctx, c.st, ldap, ldapAt, twoFA, twoFAAt); err != nil {
			return err
		}
		c.audit(ctx, "auth.cluster.directory", "", "ldap="+strconv.FormatBool(authcfg.LoadLDAP(ctx, c.st).Enabled)+
			" 2fa_required="+strconv.FormatBool(authcfg.TwoFARequired(ctx, c.st)))
	}
	if kept {
		c.st.LoginChanged(context.Background(), ItemDirectory, authcfg.DirectoryID, false) // ohne Herkunft: als eigene Aenderung
		return keptError{}
	}
	return nil
}
