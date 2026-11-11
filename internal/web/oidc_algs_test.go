package web

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// algIdP: Discovery mit einstellbaren Verfahren, JWKS mit einem RSA- und einem EC-Schluessel (#46).
func algIdP(t *testing.T, algs []string) (*httptest.Server, *rsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/auth", "token_endpoint": srv.URL + "/token",
			"jwks_uri": srv.URL + "/jwks", "id_token_signing_alg_values_supported": algs, "response_types_supported": []string{"code"}})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &rk.PublicKey, KeyID: "rsa", Algorithm: "RS256", Use: "sig"},
			{Key: &ek.PublicKey, KeyID: "ec", Algorithm: "ES256", Use: "sig"}}})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, rk, ek
}

func signIDToken(t *testing.T, iss string, alg jose.SignatureAlgorithm, key any, kid string) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ := json.Marshal(map[string]any{"iss": iss, "sub": "u1", "aud": "node64", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()})
	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

func TestOIDCSigningAlgs(t *testing.T) {
	const secret = "client-secret-0123456789abcdef0123"
	cases := []struct {
		name   string
		algs   []string
		secret string
		token  func(iss string, rk *rsa.PrivateKey, ek *ecdsa.PrivateKey) string
		ok     bool
	}{
		{"rs256", []string{"RS256"}, "", func(iss string, rk *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.RS256, rk, "rsa")
		}, true},
		{"es256 (authentik mit EC-Schluessel)", []string{"ES256"}, "", func(iss string, _ *rsa.PrivateKey, ek *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.ES256, ek, "ec")
		}, true},
		{"hs256 mit secret (authentik ohne Schluessel)", []string{"HS256"}, secret, func(iss string, _ *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.HS256, []byte(secret), "")
		}, true},
		{"hs256 ohne secret", []string{"HS256"}, "", func(iss string, _ *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.HS256, []byte(secret), "")
		}, false},
		{"hs256 mit falschem secret", []string{"HS256"}, secret, func(iss string, _ *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.HS256, []byte("anderes-secret-0123456789abcdef-xyz"), "")
		}, false},
		{"verwechslung: hs256 mit oeffentlichem rsa-schluessel", []string{"RS256", "HS256"}, secret, func(iss string, rk *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			pub, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
			return signIDToken(t, iss, jose.HS256, pub, "rsa")
		}, false},
		{"es256 nicht angekuendigt", []string{"RS256"}, "", func(iss string, _ *rsa.PrivateKey, ek *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.ES256, ek, "ec")
		}, false},
		{"ohne angabe: rs256", nil, "", func(iss string, rk *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			return signIDToken(t, iss, jose.RS256, rk, "rsa")
		}, true},
		{"none", []string{"RS256", "none"}, secret, func(iss string, _ *rsa.PrivateKey, _ *ecdsa.PrivateKey) string {
			h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
			c, _ := json.Marshal(map[string]any{"iss": iss, "sub": "u1", "aud": "node64", "exp": time.Now().Add(time.Hour).Unix()})
			return h + "." + base64.RawURLEncoding.EncodeToString(c) + "."
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, rk, ek := algIdP(t, c.algs)
			p, err := oidc.NewProvider(t.Context(), srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			v, allowed, err := oidcVerifier(p, oidcSettings{Issuer: srv.URL, ClientID: "node64", Secret: c.secret}, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, a := range allowed {
				if a == "none" || (strings.HasPrefix(a, "HS") && c.secret == "") {
					t.Fatalf("not allowed: %v", allowed)
				}
			}
			raw := c.token(srv.URL, rk, ek)
			idt, err := v.Verify(t.Context(), raw)
			if c.ok && (err != nil || idt.Subject != "u1") {
				t.Fatalf("want ok (allowed %v): %v", allowed, err)
			}
			if !c.ok && err == nil {
				t.Fatalf("want rejected (allowed %v)", allowed)
			}
		})
	}
	if a := oidcTokenAlg(signIDToken(t, "x", jose.HS256, []byte(secret), "")); a != "HS256" {
		t.Fatalf("token alg: %q", a)
	}
	if a := oidcTokenAlg("kaputt"); a != "" {
		t.Fatalf("broken token alg: %q", a)
	}
}
