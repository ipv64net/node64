package usercluster

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/ipv64net/node64/internal/authcfg"
)

// Bereich directory (ein Eintrag authcfg.DirectoryID): AD/LDAP-Anbindung und der Schalter „2FA fuer alle Pflicht“,
// damit jede Node dieselbe Regel hat. Die juengere Aenderung gewinnt als Ganzes. Das Bind-Passwort geht wie das
// SSO-Client-Secret im Klartext ueber die Cluster-Verbindung und wird beim Empfaenger mit dessen secret.key neu
// verschluesselt; laesst es sich hier nicht entschluesseln, geht der Eintrag als incomplete hinaus und die anderen
// behalten ihren Stand. Einstellungen werden nie geloescht (ein Loeschvermerk aendert nichts).

// clusterDirectory ist directory im Cluster (Bind-Passwort im Klartext, BindPasswordEnc leer).
type clusterDirectory struct {
	LDAP          authcfg.LDAPConfig `json:"ldap"`
	BindPassword  string             `json:"bind_password,omitempty"`
	TwoFARequired bool               `json:"twofa_required"`
	Incomplete    bool               `json:"incomplete,omitempty"`
}

// hasDirectory: LDAP oder 2FA-Pflicht wurden hier schon einmal gespeichert.
func (c *Cluster) hasDirectory(ctx context.Context) bool {
	return c.st.SettingOr(ctx, authcfg.SetLDAP, "") != "" || c.st.SettingOr(ctx, authcfg.Set2FARequired, "") != ""
}

func (c *Cluster) getDirectory(ctx context.Context, id string) (json.RawMessage, bool, error) {
	if id != authcfg.DirectoryID || !c.hasDirectory(ctx) {
		return nil, false, nil
	}
	out := clusterDirectory{LDAP: authcfg.LoadLDAP(ctx, c.st), TwoFARequired: authcfg.TwoFARequired(ctx, c.st)}
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
	if in.LDAP.Profile != authcfg.ProfileLDAP {
		in.LDAP.Profile = authcfg.ProfileAD
	}
	in.LDAP.TimeoutSec = max(in.LDAP.TimeoutSec, 0)
	in.LDAP.BindPasswordEnc = "" // nie einen fremden verschluesselten Wert uebernehmen
	if in.BindPassword != "" && c.box != nil {
		in.LDAP.BindPasswordEnc = c.box.Encrypt(in.BindPassword)
	}
	if err := authcfg.ApplyDirectory(ctx, c.st, in.LDAP, in.TwoFARequired); err != nil {
		return err
	}
	c.audit(ctx, "auth.cluster.directory", "", "ldap="+strconv.FormatBool(in.LDAP.Enabled)+" 2fa_required="+strconv.FormatBool(in.TwoFARequired))
	return nil
}
