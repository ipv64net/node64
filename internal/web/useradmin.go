package web

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/authcfg"
	"github.com/ipv64net/node64/internal/store"
)

// Einstellungen › Benutzerverwaltung (docs/PLAN-NODE64-BENUTZER.md, Teil A): Reiter Benutzer, Gruppen und Anmeldung
// (frueher /settings/login). Nur Administratoren; nur lokal fuer Node64. Oberflaeche und API (/api/users,
// /api/groups, /api/auth/2fa-required) nutzen dieselben Funktionen hier.

const userAdminPath = "/settings/users"

func (s *Server) userAdminRoutes() {
	s.mux.Handle("GET "+userAdminPath, s.admin(s.userAdminPage))
	s.mux.Handle("POST "+userAdminPath, s.admin(s.uaCreateSubmit))
	s.mux.Handle("POST "+userAdminPath+"/{id}", s.admin(s.uaUpdateSubmit))
	s.mux.Handle("POST "+userAdminPath+"/{id}/password", s.admin(s.uaPasswordSubmit))
	s.mux.Handle("POST "+userAdminPath+"/{id}/2fa-reset", s.admin(s.ua2FAResetSubmit))
	s.mux.Handle("POST "+userAdminPath+"/{id}/sessions-end", s.admin(s.uaSessionsEndSubmit))
	s.mux.Handle("POST "+userAdminPath+"/{id}/delete", s.admin(s.uaDeleteSubmit))
	s.mux.Handle("POST /settings/groups", s.admin(s.groupSaveSubmit))
	s.mux.Handle("POST /settings/groups/{uid}", s.admin(s.groupSaveSubmit))
	s.mux.Handle("POST /settings/groups/{uid}/delete", s.admin(s.groupDeleteSubmit))
	s.mux.Handle("POST /settings/auth/2fa-required", s.admin(s.twoFARequiredSubmit))

	s.mux.Handle("GET /api/users/{id}", s.admin(s.apiUserGet))
	s.mux.Handle("POST /api/users", s.admin(s.apiUserCreate))
	s.mux.Handle("PUT /api/users/{id}", s.admin(s.apiUserUpdate))
	s.mux.Handle("POST /api/users/{id}/password", s.admin(s.apiUserPassword))
	s.mux.Handle("POST /api/users/{id}/2fa-reset", s.admin(s.apiUser2FAReset))
	s.mux.Handle("POST /api/users/{id}/sessions-end", s.admin(s.apiUserSessionsEnd))
	s.mux.Handle("GET /api/groups", s.admin(s.apiGroups))
	s.mux.Handle("POST /api/groups", s.admin(s.apiGroupCreate))
	s.mux.Handle("GET /api/groups/{id}", s.admin(s.apiGroupGetOne))
	s.mux.Handle("PUT /api/groups/{id}", s.admin(s.apiGroupUpdate))
	s.mux.Handle("DELETE /api/groups/{id}", s.admin(s.apiGroupDelete))
	s.mux.Handle("GET /api/auth/2fa-required", s.admin(s.api2FARequiredGet))
	s.mux.Handle("PUT /api/auth/2fa-required", s.admin(s.api2FARequiredPut))
}

var (
	errUserName       = errors.New("username invalid or already taken")
	errLastAdmin      = errors.New("the last active local administrator cannot be disabled, demoted or deleted")
	errUserSelfChange = errors.New("you cannot disable or demote yourself")
	errUserNotLocal   = errors.New("password is managed by the directory or SSO provider")
	errRoleInvalid    = errors.New("role must be admin or read")
)

// ---------------------------------------------------------------- Kern (Oberflaeche und API)

// newUserIn sind die Angaben beim Anlegen.
type newUserIn struct {
	Username   string
	Password   string // leer mit MustChange = Einmal-Passwort erzeugen
	MustChange bool
	Role       string
	Email      string
	Groups     []string
}

// oneTimePassword: zufaelliges Passwort ohne leicht verwechselbare Zeichen (fuer „beim ersten Anmelden setzen“).
func oneTimePassword() string {
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 16)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[n.Int64()]
	}
	return string(b)
}

// knownGroups: nur vorhandene Gruppen-Kennungen uebernehmen.
func (s *Server) knownGroups(ctx context.Context, in []string) []string {
	groups, _ := s.Store.Groups(ctx)
	var out []string
	for _, id := range in {
		for _, g := range groups {
			if g.UID == strings.TrimSpace(id) {
				out = append(out, g.UID)
				break
			}
		}
	}
	return out
}

// uaCreate legt einen lokalen Benutzer an; otp ist das erzeugte Einmal-Passwort (sonst leer).
func (s *Server) uaCreate(r *http.Request, in newUserIn) (u *store.User, otp string, err error) {
	ctx := r.Context()
	in.Username = strings.TrimSpace(in.Username)
	if !usernameRe.MatchString(in.Username) {
		return nil, "", errUserName
	}
	if x, err := s.Store.UserByName(ctx, in.Username); err != nil {
		return nil, "", err
	} else if x != nil {
		return nil, "", errUserName
	}
	if in.Role == "" {
		in.Role = store.RoleRead
	}
	if !store.ValidRole(in.Role) {
		return nil, "", errRoleInvalid
	}
	pw := in.Password
	if pw == "" && in.MustChange {
		pw = oneTimePassword()
		otp = pw
	}
	if err := checkPassword(pw); err != nil {
		return nil, "", err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return nil, "", err
	}
	u, err = s.Store.CreateUserWith(ctx, store.NewUser{Username: in.Username, PasswordHash: hash, Role: in.Role, Source: store.SourceLocal,
		Email: strings.TrimSpace(in.Email), GroupUIDs: s.knownGroups(ctx, in.Groups), MustChange: in.MustChange})
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return nil, "", errUserName
		}
		return nil, "", err
	}
	s.audit(r, "user.create", u.Username, "role="+u.Role+" groups="+strings.Join(u.GroupUIDs, ",")+" must_change="+strconv.FormatBool(u.MustChange))
	return u, otp, nil
}

// activeLocalAdmin: zaehlt fuer die Schutzregel „letzter aktiver lokaler Administrator“.
func (s *Server) activeLocalAdmin(ctx context.Context, u *store.User) bool {
	return !u.Disabled && u.Source == store.SourceLocal && s.Store.EffectiveRole(ctx, u) == store.RoleAdmin
}

// uaUpdate aendert Rolle, Gruppen, E-Mail und Sperre. Schutz: nie den letzten aktiven lokalen Administrator sperren
// oder herabstufen, sich selbst nie. Sperre und geaenderte wirksame Rolle beenden die Sitzungen des Benutzers.
func (s *Server) uaUpdate(r *http.Request, u *store.User, a store.UserAdmin) error {
	ctx := r.Context()
	if !store.ValidRole(a.Role) {
		return errRoleInvalid
	}
	a.GroupUIDs = s.knownGroups(ctx, a.GroupUIDs)
	after := *u
	after.Role, after.Disabled, after.GroupUIDs = a.Role, a.Disabled, a.GroupUIDs
	before, now := s.Store.EffectiveRole(ctx, u), s.Store.EffectiveRole(ctx, &after)
	if u.ID == currentUser(r).ID && (a.Disabled || now != store.RoleAdmin) {
		return errUserSelfChange
	}
	if s.activeLocalAdmin(ctx, u) && !s.activeLocalAdmin(ctx, &after) {
		if n, err := s.Store.ActiveLocalAdmins(ctx, u.ID); err != nil {
			return err
		} else if n == 0 {
			return errLastAdmin
		}
	}
	if err := s.Store.UpdateUserAdmin(ctx, u.ID, a); err != nil {
		return err
	}
	if a.Disabled != u.Disabled || before != now {
		_ = s.Store.DeleteUserSessions(ctx, u.ID, "")
	}
	switch {
	case a.Disabled && !u.Disabled:
		s.audit(r, "user.disable", u.Username, "")
	case !a.Disabled && u.Disabled:
		s.audit(r, "user.enable", u.Username, "")
	}
	if a.Role != u.Role {
		s.audit(r, "user.role", u.Username, u.Role+" -> "+a.Role)
	}
	if a.Email != u.Email || strings.Join(a.GroupUIDs, ",") != strings.Join(u.GroupUIDs, ",") {
		s.audit(r, "user.update", u.Username, "groups="+strings.Join(a.GroupUIDs, ",")+" email="+a.Email)
	}
	return nil
}

// uaSetPassword setzt das Passwort eines lokalen Benutzers (leer mit mustChange = Einmal-Passwort) und beendet
// seine Sitzungen.
func (s *Server) uaSetPassword(r *http.Request, u *store.User, pw string, mustChange bool) (otp string, err error) {
	ctx := r.Context()
	if u.Source != store.SourceLocal {
		return "", errUserNotLocal
	}
	if pw == "" && mustChange {
		pw = oneTimePassword()
		otp = pw
	}
	if err := checkPassword(pw); err != nil {
		return "", err
	}
	hash, err := HashPassword(pw)
	if err != nil {
		return "", err
	}
	if err := s.Store.UpdateUserPassword(ctx, u.ID, hash); err != nil {
		return "", err
	}
	if err := s.Store.SetUserMustChange(ctx, u.ID, mustChange); err != nil {
		return "", err
	}
	_ = s.Store.DeleteUserSessions(ctx, u.ID, sessionID(r))
	s.audit(r, "user.password", u.Username, "must_change="+strconv.FormatBool(mustChange))
	return otp, nil
}

// ua2FAReset schaltet die App-2FA eines Benutzers ab (Geheimnis und Wiederherstellungscodes) und beendet seine
// Sitzungen; mit 2FA-Pflicht richtet er sie beim naechsten Anmelden neu ein.
func (s *Server) ua2FAReset(r *http.Request, u *store.User) error {
	if err := s.Store.SetUserTOTP(r.Context(), u.ID, "", ""); err != nil {
		return err
	}
	_ = s.Store.DeleteUserSessions(r.Context(), u.ID, sessionID(r))
	s.audit(r, "user.2fa_reset", u.Username, "")
	return nil
}

// uaSessionsEnd beendet alle Sitzungen eines Benutzers (die eigene laufende bleibt).
func (s *Server) uaSessionsEnd(r *http.Request, u *store.User) error {
	if err := s.Store.DeleteUserSessions(r.Context(), u.ID, sessionID(r)); err != nil {
		return err
	}
	s.audit(r, "user.sessions_end", u.Username, "")
	return nil
}

// groupIn sind die Felder einer Gruppe.
type groupIn struct {
	Name        string   `json:"name"`
	Role        string   `json:"role"`
	Description string   `json:"description"`
	LDAPGroups  []string `json:"ldap_groups"`
	OIDCGroups  []string `json:"oidc_groups"`
}

// groupSave legt eine Gruppe an (g.UID leer) oder aendert sie. Eine Rollenaenderung, die den letzten aktiven
// lokalen Administrator herabstufen wuerde, wird abgelehnt.
func (s *Server) groupSave(r *http.Request, g *store.Group) error {
	ctx := r.Context()
	if g.Role == "" {
		g.Role = store.RoleRead
	}
	if !store.ValidRole(g.Role) {
		return errRoleInvalid
	}
	isNew := g.UID == ""
	if !isNew && g.Role != store.RoleAdmin {
		if old, _ := s.Store.GroupByUID(ctx, g.UID); old != nil && old.Role == store.RoleAdmin {
			if err := s.groupDemoteOK(ctx, r, g.UID); err != nil {
				return err
			}
		}
	}
	if err := s.Store.SaveGroup(ctx, g); err != nil {
		return err
	}
	action := "group.update"
	if isNew {
		action = "group.create"
	}
	s.audit(r, action, g.Name, "role="+g.Role)
	return nil
}

// groupDemoteOK: nimmt man der Gruppe die Rolle Administrator (bzw. loescht sie), bleibt dann noch ein aktiver
// lokaler Administrator, und der angemeldete Benutzer bleibt selbst Administrator?
func (s *Server) groupDemoteOK(ctx context.Context, r *http.Request, uid string) error {
	users, err := s.Store.Users(ctx)
	if err != nil {
		return err
	}
	without := func(u *store.User) *store.User {
		x := *u
		x.GroupUIDs, x.ExtGroupUIDs = dropID(u.GroupUIDs, uid), dropID(u.ExtGroupUIDs, uid)
		return &x
	}
	n := 0
	for _, u := range users {
		x := without(u)
		if u.ID == currentUser(r).ID && s.Store.EffectiveRole(ctx, x) != store.RoleAdmin {
			return errUserSelfChange
		}
		if s.activeLocalAdmin(ctx, x) {
			n++
		}
	}
	if n == 0 {
		return errLastAdmin
	}
	return nil
}

func dropID(l []string, id string) []string {
	var out []string
	for _, x := range l {
		if x != id {
			out = append(out, x)
		}
	}
	return out
}

// groupDelete loescht eine Gruppe (mit derselben Schutzregel wie das Herabstufen).
func (s *Server) groupDelete(r *http.Request, uid string) (*store.Group, error) {
	ctx := r.Context()
	g, err := s.Store.GroupByUID(ctx, uid)
	if err != nil || g == nil {
		return nil, err
	}
	if g.Role == store.RoleAdmin {
		if err := s.groupDemoteOK(ctx, r, uid); err != nil {
			return nil, err
		}
	}
	if _, err := s.Store.DeleteGroup(ctx, uid); err != nil {
		return nil, err
	}
	s.audit(r, "group.delete", g.Name, "")
	return g, nil
}

// setTwoFARequired schaltet die 2FA-Pflicht (gilt im Cluster ueber den Bereich directory).
func (s *Server) setTwoFARequired(r *http.Request, on bool) error {
	if err := authcfg.SetTwoFARequired(r.Context(), s.Store, on); err != nil {
		return err
	}
	s.audit(r, "auth.2fa_required", "", "required="+strconv.FormatBool(on))
	return nil
}

// ---------------------------------------------------------------- Oberflaeche

// uaUserRow ist ein Benutzer in der Liste.
type uaUserRow struct {
	*store.User
	Effective string
	Groups    []string // Namen (von Hand)
	ExtGroups []string // Namen (LDAP/SSO)
	Passkeys  int
	Self      bool
}

// uaGroupRow ist eine Gruppe mit Mitgliedern.
type uaGroupRow struct {
	*store.Group
	Members    []string // von Hand
	ExtMembers []string // ueber LDAP/SSO
}

type userAdminData struct {
	Tab      string
	Users    []uaUserRow
	Groups   []uaGroupRow
	NewUser  string // eben angelegter Benutzer bzw. neues Passwort: "name" (einmal sichtbar)
	OTP      string // Einmal-Passwort dazu
	Required bool   // 2FA fuer alle Pflicht
	Login    loginMethodsData
}

func (s *Server) userAdminView(r *http.Request, tab string) *View {
	ctx := r.Context()
	v := s.view(r, "useradmin.title")
	d := userAdminData{Tab: tab, Required: authcfg.TwoFARequired(ctx, s.Store)}
	switch d.Tab {
	case "users", "groups", "login":
	default:
		d.Tab = "users"
	}
	groups, _ := s.Store.Groups(ctx)
	names := map[string]string{}
	for _, g := range groups {
		names[g.UID] = g.Name
		row := uaGroupRow{Group: g}
		man, ext, _ := s.Store.GroupMembers(ctx, g.UID)
		for _, u := range man {
			row.Members = append(row.Members, u.Username)
		}
		for _, u := range ext {
			row.ExtMembers = append(row.ExtMembers, u.Username)
		}
		d.Groups = append(d.Groups, row)
	}
	users, _ := s.Store.Users(ctx)
	for _, u := range users {
		row := uaUserRow{User: u, Effective: s.Store.EffectiveRole(ctx, u), Self: u.ID == v.User.ID}
		for _, id := range u.GroupUIDs {
			if n := names[id]; n != "" {
				row.Groups = append(row.Groups, n)
			}
		}
		for _, id := range u.ExtGroupUIDs {
			if n := names[id]; n != "" {
				row.ExtGroups = append(row.ExtGroups, n)
			}
		}
		pks, _ := s.Store.Passkeys(ctx, u.ID, "")
		row.Passkeys = len(pks)
		d.Users = append(d.Users, row)
	}
	sort.SliceStable(d.Users, func(i, j int) bool {
		return strings.ToLower(d.Users[i].Username) < strings.ToLower(d.Users[j].Username)
	})
	d.Login = s.loginMethodsData(r) // alle Reiter stehen auf einer Seite (Wechsel ohne Neuladen)
	v.Data = d
	return v
}

func (s *Server) userAdminPage(w http.ResponseWriter, r *http.Request) {
	v := s.userAdminView(r, r.URL.Query().Get("tab"))
	d := v.Data.(userAdminData)
	if k := s.takeNewKey(w, r, v.User.ID, "otp"); k != "" { // Einmal-Passwort nur einmal nach dem Anlegen sichtbar
		d.NewUser, d.OTP, _ = strings.Cut(k, "\n")
	}
	v.Data = d
	s.render(w, r, http.StatusOK, "useradmin", v)
}

// uaBack: zurueck zur Benutzerverwaltung (Reiter) mit Meldung.
func (s *Server) uaBack(w http.ResponseWriter, r *http.Request, tab, kind, text string) {
	s.flash(w, r, kind, text)
	http.Redirect(w, r, userAdminPath+"?tab="+url.QueryEscape(tab)+"#"+tab, http.StatusSeeOther)
}

// uaErrText: Fehler der Benutzerverwaltung als Meldung (unbekannte: interner Fehler, im Log).
func (s *Server) uaErrText(r *http.Request, err error) string {
	switch {
	case errors.Is(err, errUserName):
		return s.tr(r, "errors.username_invalid") + " " + s.tr(r, "useradmin.name_taken")
	case errors.Is(err, errWeakPassword):
		return s.tr(r, "errors.password_short")
	case errors.Is(err, errLastAdmin):
		return s.tr(r, "useradmin.last_admin")
	case errors.Is(err, errUserSelfChange), errors.Is(err, errUserSelf):
		return s.tr(r, "useradmin.self")
	case errors.Is(err, errUserNotLocal):
		return s.tr(r, "useradmin.not_local")
	case errors.Is(err, errRoleInvalid), errors.Is(err, errUserUnknown):
		return s.tr(r, "errors.validation")
	case errors.Is(err, store.ErrGroupName):
		return s.tr(r, "useradmin.group_name_taken")
	}
	s.log.Error("user administration", "err", err)
	return s.tr(r, "errors.internal")
}

// uaTarget: Benutzer aus dem Pfad (nil = Meldung schon gesendet).
func (s *Server) uaTarget(w http.ResponseWriter, r *http.Request) *store.User {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := s.Store.UserByID(r.Context(), id)
	if err != nil || u == nil {
		s.uaBack(w, r, "users", "danger", s.tr(r, "errors.not_found"))
		return nil
	}
	return u
}

func (s *Server) uaCreateSubmit(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	in := newUserIn{Username: r.PostFormValue("username"), Password: r.PostFormValue("password"), MustChange: r.PostFormValue("must_change") == "1",
		Role: r.PostFormValue("role"), Email: r.PostFormValue("email"), Groups: r.PostForm["groups"]}
	if in.MustChange {
		in.Password = "" // Einmal-Passwort erzeugen
	} else if in.Password != r.PostFormValue("password2") {
		s.uaBack(w, r, "users", "danger", s.tr(r, "errors.password_mismatch"))
		return
	}
	u, otp, err := s.uaCreate(r, in)
	if err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	if otp != "" {
		s.keepNewKey(w, r, currentUser(r).ID, "otp", u.Username+"\n"+otp)
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "useradmin.created", "name", u.Username))
}

func (s *Server) uaUpdateSubmit(w http.ResponseWriter, r *http.Request) {
	u := s.uaTarget(w, r)
	if u == nil {
		return
	}
	_ = r.ParseForm()
	a := store.UserAdmin{Role: r.PostFormValue("role"), Disabled: r.PostFormValue("disabled") == "1", Email: r.PostFormValue("email"), GroupUIDs: r.PostForm["groups"]}
	if err := s.uaUpdate(r, u, a); err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "common.saved"))
}

func (s *Server) uaPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	u := s.uaTarget(w, r)
	if u == nil {
		return
	}
	pw, must := r.PostFormValue("password"), r.PostFormValue("must_change") == "1"
	if must {
		pw = ""
	}
	otp, err := s.uaSetPassword(r, u, pw, must)
	if err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	if otp != "" {
		s.keepNewKey(w, r, currentUser(r).ID, "otp", u.Username+"\n"+otp)
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "useradmin.password_set", "name", u.Username))
}

func (s *Server) ua2FAResetSubmit(w http.ResponseWriter, r *http.Request) {
	u := s.uaTarget(w, r)
	if u == nil {
		return
	}
	if err := s.ua2FAReset(r, u); err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "useradmin.twofa_reset_done", "name", u.Username))
}

func (s *Server) uaSessionsEndSubmit(w http.ResponseWriter, r *http.Request) {
	u := s.uaTarget(w, r)
	if u == nil {
		return
	}
	if err := s.uaSessionsEnd(r, u); err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "useradmin.sessions_ended", "name", u.Username))
}

func (s *Server) uaDeleteSubmit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := s.deleteOtherUser(r, id)
	if err != nil {
		s.uaBack(w, r, "users", "danger", s.uaErrText(r, err))
		return
	}
	s.uaBack(w, r, "users", "success", s.tr(r, "sso.user_deleted", "name", u.Username))
}

// formLines: Textfeld mit einer Angabe je Zeile.
func formLines(v string) []string {
	var out []string
	for _, l := range strings.Split(v, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (s *Server) groupSaveSubmit(w http.ResponseWriter, r *http.Request) {
	g := &store.Group{UID: r.PathValue("uid"), Name: r.PostFormValue("name"), Role: r.PostFormValue("role"), Description: r.PostFormValue("description"),
		LDAPGroups: formLines(r.PostFormValue("ldap_groups")), OIDCGroups: formLines(r.PostFormValue("oidc_groups"))}
	if g.UID != "" {
		if old, _ := s.Store.GroupByUID(r.Context(), g.UID); old == nil {
			s.uaBack(w, r, "groups", "danger", s.tr(r, "errors.not_found"))
			return
		}
	}
	if err := s.groupSave(r, g); err != nil {
		s.uaBack(w, r, "groups", "danger", s.uaErrText(r, err))
		return
	}
	s.uaBack(w, r, "groups", "success", s.tr(r, "common.saved"))
}

func (s *Server) groupDeleteSubmit(w http.ResponseWriter, r *http.Request) {
	g, err := s.groupDelete(r, r.PathValue("uid"))
	switch {
	case err != nil:
		s.uaBack(w, r, "groups", "danger", s.uaErrText(r, err))
	case g == nil:
		s.uaBack(w, r, "groups", "warning", s.tr(r, "errors.not_found"))
	default:
		s.uaBack(w, r, "groups", "success", s.tr(r, "useradmin.group_deleted", "name", g.Name))
	}
}

func (s *Server) twoFARequiredSubmit(w http.ResponseWriter, r *http.Request) {
	if err := s.setTwoFARequired(r, r.PostFormValue("required") == "1"); err != nil {
		s.fail(w, r, err)
		return
	}
	s.uaBack(w, r, "login", "success", s.tr(r, "common.saved"))
}

// ---------------------------------------------------------------- API

// apiUserErr: Fehler der Benutzerverwaltung als HTTP-Status.
func (s *Server) apiUserErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errUserName), errors.Is(err, errWeakPassword), errors.Is(err, errRoleInvalid), errors.Is(err, store.ErrGroupName):
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
	case errors.Is(err, errLastAdmin), errors.Is(err, errUserSelfChange), errors.Is(err, errUserSelf), errors.Is(err, errUserNotLocal):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, errUserUnknown):
		writeErr(w, http.StatusNotFound, err.Error())
	default:
		s.log.Error("user administration", "err", err)
		writeErr(w, http.StatusInternalServerError, "database error")
	}
}

// apiTarget: Benutzer aus dem Pfad (nil = 404 gesendet).
func (s *Server) apiTarget(w http.ResponseWriter, r *http.Request) *store.User {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	u, err := s.Store.UserByID(r.Context(), id)
	if err != nil || u == nil {
		writeErr(w, http.StatusNotFound, errUserUnknown.Error())
		return nil
	}
	return u
}

// GET /api/users/{id}
func (s *Server) apiUserGet(w http.ResponseWriter, r *http.Request) {
	if u := s.apiTarget(w, r); u != nil {
		writeJSON(w, http.StatusOK, s.userJSON(r.Context(), u, currentUser(r).ID))
	}
}

// POST /api/users {username, password | must_change, role, email, groups}: lokaler Benutzer; mit must_change ohne
// Passwort kommt das Einmal-Passwort einmal in der Antwort ("password").
func (s *Server) apiUserCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username   string   `json:"username"`
		Password   string   `json:"password"`
		MustChange bool     `json:"must_change"`
		Role       string   `json:"role"`
		Email      string   `json:"email"`
		Groups     []string `json:"groups"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	u, otp, err := s.uaCreate(r, newUserIn{Username: in.Username, Password: in.Password, MustChange: in.MustChange, Role: in.Role, Email: in.Email, Groups: in.Groups})
	if err != nil {
		s.apiUserErr(w, err)
		return
	}
	out := s.userJSON(r.Context(), u, currentUser(r).ID)
	if otp != "" {
		out["password"] = otp
	}
	writeJSON(w, http.StatusCreated, out)
}

// PUT /api/users/{id} {role, groups, email, disabled}: fehlende Felder bleiben.
func (s *Server) apiUserUpdate(w http.ResponseWriter, r *http.Request) {
	u := s.apiTarget(w, r)
	if u == nil {
		return
	}
	var in struct {
		Role     *string   `json:"role"`
		Groups   *[]string `json:"groups"`
		Email    *string   `json:"email"`
		Disabled *bool     `json:"disabled"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	a := store.UserAdmin{Role: u.Role, Disabled: u.Disabled, Email: u.Email, GroupUIDs: u.GroupUIDs}
	if in.Role != nil {
		a.Role = strings.TrimSpace(*in.Role)
	}
	if in.Groups != nil {
		a.GroupUIDs = *in.Groups
	}
	if in.Email != nil {
		a.Email = strings.TrimSpace(*in.Email)
	}
	if in.Disabled != nil {
		a.Disabled = *in.Disabled
	}
	if err := s.uaUpdate(r, u, a); err != nil {
		s.apiUserErr(w, err)
		return
	}
	nu, err := s.Store.UserByID(r.Context(), u.ID)
	if err != nil || nu == nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, s.userJSON(r.Context(), nu, currentUser(r).ID))
}

// POST /api/users/{id}/password {password | must_change}: nur lokale Benutzer.
func (s *Server) apiUserPassword(w http.ResponseWriter, r *http.Request) {
	u := s.apiTarget(w, r)
	if u == nil {
		return
	}
	var in struct {
		Password   string `json:"password"`
		MustChange bool   `json:"must_change"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	otp, err := s.uaSetPassword(r, u, in.Password, in.MustChange)
	if err != nil {
		s.apiUserErr(w, err)
		return
	}
	if otp != "" {
		writeJSON(w, http.StatusOK, map[string]any{"password": otp, "must_change": true})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/users/{id}/2fa-reset
func (s *Server) apiUser2FAReset(w http.ResponseWriter, r *http.Request) {
	u := s.apiTarget(w, r)
	if u == nil {
		return
	}
	if err := s.ua2FAReset(r, u); err != nil {
		s.apiUserErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// POST /api/users/{id}/sessions-end
func (s *Server) apiUserSessionsEnd(w http.ResponseWriter, r *http.Request) {
	u := s.apiTarget(w, r)
	if u == nil {
		return
	}
	if err := s.uaSessionsEnd(r, u); err != nil {
		s.apiUserErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// groupJSON: Gruppe mit Mitgliedern (Benutzernamen).
func (s *Server) groupJSON(ctx context.Context, g *store.Group) map[string]any {
	man, ext, _ := s.Store.GroupMembers(ctx, g.UID)
	names := func(l []*store.User) []string {
		out := []string{}
		for _, u := range l {
			out = append(out, u.Username)
		}
		return out
	}
	orEmpty := func(l []string) []string {
		if l == nil {
			return []string{}
		}
		return l
	}
	return map[string]any{"uid": g.UID, "name": g.Name, "role": g.Role, "description": g.Description, "ldap_groups": orEmpty(g.LDAPGroups),
		"oidc_groups": orEmpty(g.OIDCGroups), "members": names(man), "ext_members": names(ext), "created_at": g.CreatedAt, "updated_at": g.UpdatedAt}
}

// GET /api/groups
func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	list, err := s.Store.Groups(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	out := make([]map[string]any, 0, len(list))
	for _, g := range list {
		out = append(out, s.groupJSON(r.Context(), g))
	}
	writeJSON(w, http.StatusOK, out)
}

// GET /api/groups/{id}
func (s *Server) apiGroupGetOne(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GroupByUID(r.Context(), r.PathValue("id"))
	if err != nil || g == nil {
		writeErr(w, http.StatusNotFound, "unknown group")
		return
	}
	writeJSON(w, http.StatusOK, s.groupJSON(r.Context(), g))
}

// POST /api/groups {name, role, description, ldap_groups, oidc_groups}
func (s *Server) apiGroupCreate(w http.ResponseWriter, r *http.Request) {
	var in groupIn
	if !decodeJSON(w, r, &in) {
		return
	}
	g := &store.Group{Name: in.Name, Role: in.Role, Description: in.Description, LDAPGroups: in.LDAPGroups, OIDCGroups: in.OIDCGroups}
	if err := s.groupSave(r, g); err != nil {
		s.apiUserErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, s.groupJSON(r.Context(), g))
}

// PUT /api/groups/{id}: fehlende Felder bleiben.
func (s *Server) apiGroupUpdate(w http.ResponseWriter, r *http.Request) {
	g, err := s.Store.GroupByUID(r.Context(), r.PathValue("id"))
	if err != nil || g == nil {
		writeErr(w, http.StatusNotFound, "unknown group")
		return
	}
	var in struct {
		Name        *string   `json:"name"`
		Role        *string   `json:"role"`
		Description *string   `json:"description"`
		LDAPGroups  *[]string `json:"ldap_groups"`
		OIDCGroups  *[]string `json:"oidc_groups"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Name != nil {
		g.Name = *in.Name
	}
	if in.Role != nil {
		g.Role = strings.TrimSpace(*in.Role)
	}
	if in.Description != nil {
		g.Description = *in.Description
	}
	if in.LDAPGroups != nil {
		g.LDAPGroups = *in.LDAPGroups
	}
	if in.OIDCGroups != nil {
		g.OIDCGroups = *in.OIDCGroups
	}
	if err := s.groupSave(r, g); err != nil {
		s.apiUserErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.groupJSON(r.Context(), g))
}

// DELETE /api/groups/{id}
func (s *Server) apiGroupDelete(w http.ResponseWriter, r *http.Request) {
	g, err := s.groupDelete(r, r.PathValue("id"))
	switch {
	case err != nil:
		s.apiUserErr(w, err)
	case g == nil:
		writeErr(w, http.StatusNotFound, "unknown group")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// GET /api/auth/2fa-required
func (s *Server) api2FARequiredGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"required": authcfg.TwoFARequired(r.Context(), s.Store)})
}

// PUT /api/auth/2fa-required {required}
func (s *Server) api2FARequiredPut(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Required *bool `json:"required"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if in.Required == nil {
		writeErr(w, http.StatusUnprocessableEntity, "required is missing")
		return
	}
	if err := s.setTwoFARequired(r, *in.Required); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"required": *in.Required})
}
