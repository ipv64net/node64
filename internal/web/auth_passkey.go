package web

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/ipv64net/node64/internal/store"
)

// Passkeys (WebAuthn) als alleinige Anmeldung: Knopf auf der Login-Seite, ohne Benutzernamen (discoverable
// credentials), Pruefung per Fingerabdruck/Face ID/PIN am Geraet. Passkeys gelten nur fuer den Hostnamen, unter dem
// sie angelegt wurden, und brauchen HTTPS mit einem Namen (keine IP-Adresse) - so verlangen es die Browser.
// Passwort und App-2FA bleiben daneben bestehen.

const (
	passkeyCookie = "node64_pk"
	passkeyTTL    = 5 * time.Minute
)

var (
	errPasskeyHost = errors.New("passkeys need a host name (not an IP address) and HTTPS")
	errPasskeyFlow = errors.New("passkey request expired")
)

// passkeyUser verbindet einen lokalen Benutzer mit seinen Passkeys fuer die webauthn-Bibliothek.
type passkeyUser struct {
	u     *store.User
	creds []webauthn.Credential
}

func passkeyHandle(id int64) []byte { return []byte("node64-user-" + strconv.FormatInt(id, 10)) }

func (p passkeyUser) WebAuthnID() []byte                         { return passkeyHandle(p.u.ID) }
func (p passkeyUser) WebAuthnName() string                       { return p.u.Username }
func (p passkeyUser) WebAuthnDisplayName() string                { return p.u.Username }
func (p passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.creds }

// relyingParty: Hostname (RP ID) und Herkunft der Anfrage; ohne Namen oder HTTPS keine Passkeys.
func (s *Server) relyingParty(r *http.Request) (*webauthn.WebAuthn, string, error) {
	host := r.Host
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if s.Cfg.TrustProxyHeaders {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
		if strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			scheme = "https"
		}
	}
	name := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		name = h
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" || net.ParseIP(strings.Trim(name, "[]")) != nil || (scheme != "https" && name != "localhost") {
		return nil, name, errPasskeyHost
	}
	wa, err := webauthn.New(&webauthn.Config{RPID: name, RPDisplayName: "Node64", RPOrigins: []string{scheme + "://" + host}})
	return wa, name, err
}

// ---------------------------------------------------------------- laufende Zeremonien

type passkeyFlow struct {
	session webauthn.SessionData
	userID  int64 // Registrierung: angemeldeter Benutzer; Anmeldung: 0
	next    string
	expires time.Time
}

var passkeyFlows struct {
	sync.Mutex
	m map[string]passkeyFlow
}

func (s *Server) passkeyPut(w http.ResponseWriter, r *http.Request, f passkeyFlow) {
	id := randomToken(24)
	passkeyFlows.Lock()
	if passkeyFlows.m == nil {
		passkeyFlows.m = map[string]passkeyFlow{}
	}
	for k, v := range passkeyFlows.m {
		if time.Now().After(v.expires) {
			delete(passkeyFlows.m, k)
		}
	}
	if len(passkeyFlows.m) < 1000 {
		f.expires = time.Now().Add(passkeyTTL)
		passkeyFlows.m[id] = f
	}
	passkeyFlows.Unlock()
	s.setCookie(w, r, passkeyCookie, id, int(passkeyTTL.Seconds()))
}

func (s *Server) passkeyTake(w http.ResponseWriter, r *http.Request) (passkeyFlow, bool) {
	c, err := r.Cookie(passkeyCookie)
	s.clearCookie(w, r, passkeyCookie)
	if err != nil {
		return passkeyFlow{}, false
	}
	passkeyFlows.Lock()
	defer passkeyFlows.Unlock()
	f, ok := passkeyFlows.m[c.Value]
	delete(passkeyFlows.m, c.Value)
	return f, ok && time.Now().Before(f.expires)
}

func (s *Server) passkeyUserOf(r *http.Request, u *store.User, rpID string) (passkeyUser, error) {
	list, err := s.Store.Passkeys(r.Context(), u.ID, rpID)
	if err != nil {
		return passkeyUser{}, err
	}
	pu := passkeyUser{u: u}
	for _, p := range list {
		var c webauthn.Credential
		if json.Unmarshal([]byte(p.Data), &c) == nil {
			pu.creds = append(pu.creds, c)
		}
	}
	return pu, nil
}

// ---------------------------------------------------------------- Registrierung (Einstellungen -> Anmeldung)

func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa, rpID, err := s.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	pu, err := s.passkeyUserOf(r, currentUser(r), rpID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	var excl []protocol.CredentialDescriptor
	for _, c := range pu.creds {
		excl = append(excl, c.Descriptor())
	}
	opts, sess, err := wa.BeginRegistration(pu, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired), webauthn.WithExclusions(excl))
	if err != nil {
		s.log.Warn("passkey registration begin", "err", err)
		writeErr(w, http.StatusInternalServerError, "passkey registration failed")
		return
	}
	s.passkeyPut(w, r, passkeyFlow{session: *sess, userID: currentUser(r).ID})
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	f, ok := s.passkeyTake(w, r)
	if !ok || f.userID != u.ID {
		writeErr(w, http.StatusBadRequest, errPasskeyFlow.Error())
		return
	}
	wa, rpID, err := s.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	pu, err := s.passkeyUserOf(r, u, rpID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	cred, err := wa.FinishRegistration(pu, f.session, r)
	if err != nil {
		s.log.Warn("passkey registration rejected", "user", u.Username, "err", err)
		writeErr(w, http.StatusBadRequest, "passkey not accepted")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	data, _ := json.Marshal(cred)
	if err := s.Store.AddPasskey(r.Context(), store.Passkey{UserID: u.ID, Name: truncate(name, 60), RPID: rpID,
		CredentialID: base64.RawURLEncoding.EncodeToString(cred.ID), Data: string(data)}); err != nil {
		writeErr(w, http.StatusInternalServerError, "database error")
		return
	}
	s.audit(r, "passkey.add", truncate(name, 60), rpID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) passkeyDelete(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "sso.title")
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ok, err := s.Store.DeletePasskey(r.Context(), currentUser(r).ID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ok {
		s.audit(r, "passkey.delete", strconv.FormatInt(id, 10), "")
		s.flash(w, r, "success", v.T("sso.pk_deleted"))
	}
	http.Redirect(w, r, "/settings/login#passkeys", http.StatusSeeOther)
}

// ---------------------------------------------------------------- Anmeldung (Login-Seite)

func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	wa, _, err := s.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if wait := s.limiter.retryAfter("ip:" + ipKey(s.clientIP(r))); wait > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeErr(w, http.StatusTooManyRequests, "too many attempts")
		return
	}
	opts, sess, err := wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "passkey login failed")
		return
	}
	s.passkeyPut(w, r, passkeyFlow{session: *sess, next: safeNext(r.URL.Query().Get("next"))})
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ip := s.clientIP(r)
	f, ok := s.passkeyTake(w, r)
	if !ok || f.userID != 0 {
		writeErr(w, http.StatusBadRequest, errPasskeyFlow.Error())
		return
	}
	wa, rpID, err := s.relyingParty(r)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	r.Body = io.NopCloser(bytes.NewReader(body))
	var found *store.User
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		id, err := strconv.ParseInt(strings.TrimPrefix(string(userHandle), "node64-user-"), 10, 64)
		if err != nil || !bytes.HasPrefix(userHandle, []byte("node64-user-")) {
			return nil, errors.New("unknown user handle")
		}
		u, err := s.Store.UserByID(ctx, id)
		if err != nil || u == nil {
			return nil, errors.New("unknown user")
		}
		found = u
		return s.passkeyUserOf(r, u, rpID)
	}
	_, cred, err := wa.FinishPasskeyLogin(handler, f.session, r)
	if err != nil || found == nil {
		s.limiter.fail("ip:" + ipKey(ip))
		s.loginFailed(r, ip)
		s.auditEntry(ctx, store.AuditEntry{Actor: "passkey", Action: "login.failed", Details: "passkey", IP: ip})
		s.log.Warn("passkey login failed", "ip", ip, "err", err)
		writeErr(w, http.StatusUnauthorized, "passkey not accepted")
		return
	}
	data, _ := json.Marshal(cred)
	_ = s.Store.UpdatePasskey(ctx, base64.RawURLEncoding.EncodeToString(cred.ID), string(data))
	if err := s.completeLogin(w, r, found, "passkey"); err != nil {
		writeErr(w, http.StatusInternalServerError, "session error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": f.next})
}
