package web

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/ipv64net/node64/internal/secrets"
)

// fakeIdP ist ein OIDC-Anbieter fuer Tests: Discovery, JWKS und Token-Endpunkt mit signiertem ID-Token.
type fakeIdP struct {
	srv       *httptest.Server
	key       *rsa.PrivateKey
	mu        sync.Mutex
	sub       string
	nonce     string
	challenge string
	slash     bool // Issuer mit "/" am Ende (wie authentik)
}

func (f *fakeIdP) issuer() string {
	if f.slash {
		return f.srv.URL + "/"
	}
	return f.srv.URL
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	f := &fakeIdP{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		u := f.srv.URL
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": f.issuer(), "authorization_endpoint": u + "/auth", "token_endpoint": u + "/token",
			"jwks_uri": u + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}, "response_types_supported": []string{"code"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		sub, nonce, ch := f.sub, f.nonce, f.challenge
		f.mu.Unlock()
		// PKCE: der Verifier muss zur Challenge passen
		h := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
		if base64.RawURLEncoding.EncodeToString(h[:]) != ch || r.PostFormValue("code") != "good" {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
		claims, _ := json.Marshal(map[string]any{"iss": f.issuer(), "sub": sub, "aud": "node64", "exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(), "nonce": nonce, "email": sub + "@example.com"})
		jws, _ := signer.Sign(claims)
		idt, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// authorize spielt den Browser beim Anbieter: merkt nonce und Challenge aus der Weiterleitung und liefert die
// Rueckleitung mit Code und state.
func (f *fakeIdP) authorize(t *testing.T, loc, sub string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(loc, f.srv.URL+"/auth") {
		t.Fatalf("not redirected to the provider: %q", loc)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" {
		t.Fatalf("PKCE/nonce missing: %v", q)
	}
	f.mu.Lock()
	f.sub, f.nonce, f.challenge = sub, q.Get("nonce"), q.Get("code_challenge")
	f.mu.Unlock()
	cb, _ := url.Parse(q.Get("redirect_uri"))
	return cb.Path + "?code=good&state=" + url.QueryEscape(q.Get("state"))
}

func TestOIDCLinkAndLogin(t *testing.T) {
	idp := newFakeIdP(t)
	dir := t.TempDir()
	box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
	a := newTestAppDeps(t, func(d *Deps) { d.Box = box })
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings/login")
	csrf := csrfOf(t, body)
	resp, _ := a.post(t, "/settings/login/oidc", url.Values{"_csrf": {csrf}, "issuer": {idp.srv.URL}, "client_id": {"node64"}, "client_secret": {"s3cret"}, "label": {"Authelia"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save: %d", resp.StatusCode)
	}
	if enc := a.store.SettingOr(t.Context(), setOIDCSecret, ""); enc == "" || strings.Contains(enc, "s3cret") {
		t.Fatalf("client secret must be stored encrypted: %q", enc)
	}
	// verknuepfen
	resp, _ = a.post(t, "/settings/login/oidc/link", url.Values{"_csrf": {csrf}})
	cb := idp.authorize(t, resp.Header.Get("Location"), "alice")
	resp, _ = a.get(t, cb)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/login" {
		t.Fatalf("link callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ := a.store.UserByName(t.Context(), "admin")
	if ids, _ := a.store.Identities(t.Context(), u.ID); len(ids) != 1 || ids[0].Subject != "alice" || ids[0].Label != "alice@example.com" {
		t.Fatalf("identity not linked: %+v", ids)
	}
	// Login-Seite zeigt den Knopf; abmelden und per SSO anmelden
	_, _ = a.post(t, "/logout", url.Values{"_csrf": {csrf}})
	_, body = a.get(t, "/login")
	if !strings.Contains(body, "/login/oidc") || !strings.Contains(body, "Authelia") {
		t.Fatal("login page without SSO button")
	}
	resp, _ = a.get(t, "/login/oidc?next=/settings")
	resp, _ = a.get(t, idp.authorize(t, resp.Header.Get("Location"), "alice"))
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings" {
		t.Fatalf("sso login: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ = a.get(t, "/settings"); resp.StatusCode != 200 {
		t.Fatalf("not signed in after sso: %d", resp.StatusCode)
	}
	// nicht verknuepftes Konto kommt nicht rein; ein state gilt nur einmal
	_, body = a.get(t, "/settings")
	_, _ = a.post(t, "/logout", url.Values{"_csrf": {csrfOf(t, body)}})
	resp, _ = a.get(t, "/login/oidc")
	cb = idp.authorize(t, resp.Header.Get("Location"), "mallory")
	resp, _ = a.get(t, cb)
	if resp.Header.Get("Location") != "/login" {
		t.Fatalf("unlinked account must be rejected: %s", resp.Header.Get("Location"))
	}
	if resp, _ = a.get(t, "/settings"); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unlinked account got a session: %d", resp.StatusCode)
	}
	if resp, _ = a.get(t, cb); resp.Header.Get("Location") != "/login" {
		t.Fatal("state must be single use")
	}
}

// Issuer mit und ohne "/" am Ende: gespeichert wird wie eingegeben, Discovery und ID-Token passen in beiden
// Schreibweisen (authentik hat den Schraegstrich, Authelia/Keycloak nicht).
func TestOIDCIssuerTrailingSlash(t *testing.T) {
	for _, tc := range []struct {
		name         string
		slash        bool
		input, store string
	}{{"authentik as given", true, "/", "/"}, {"authentik without slash", true, "", ""}, {"authelia with slash", false, "/", "/"}} {
		t.Run(tc.name, func(t *testing.T) {
			idp := newFakeIdP(t)
			idp.slash = tc.slash
			dir := t.TempDir()
			box, _ := secrets.Load(filepath.Join(dir, "secret.key"))
			a := newTestAppDeps(t, func(d *Deps) { d.Box = box })
			loginAs(t, a, "admin", "sehr geheimes passwort")
			_, body := a.get(t, "/settings/login")
			csrf := csrfOf(t, body)
			_, _ = a.post(t, "/settings/login/oidc", url.Values{"_csrf": {csrf}, "issuer": {idp.srv.URL + tc.input}, "client_id": {"node64"}, "client_secret": {"s3cret"}})
			if got := a.store.SettingOr(t.Context(), setOIDCIssuer, ""); got != idp.srv.URL+tc.store {
				t.Fatalf("stored issuer %q", got)
			}
			resp, _ := a.post(t, "/settings/login/oidc/link", url.Values{"_csrf": {csrf}})
			cb := idp.authorize(t, resp.Header.Get("Location"), "alice")
			resp, _ = a.get(t, cb)
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/settings/login" {
				t.Fatalf("link callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
			u, _ := a.store.UserByName(t.Context(), "admin")
			if ids, _ := a.store.Identities(t.Context(), u.ID); len(ids) != 1 || ids[0].Subject != "alice" {
				t.Fatalf("identity not linked: %+v", ids)
			}
		})
	}
}
