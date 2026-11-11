package web

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// Signaturverfahren des ID-Tokens (#46): erlaubt sind die Verfahren, die der Anbieter in der Discovery nennt
// (id_token_signing_alg_values_supported). Asymmetrische (RS/PS/ES/EdDSA) prueft der JWKS des Anbieters, HS256/384/512
// das Client-Secret - nur wenn eins eingetragen ist. Ein HS-Token wird nie mit einem oeffentlichen Schluessel aus dem
// JWKS geprueft und ein asymmetrisches nie mit dem Secret (keine Verwechslung der Verfahren). "none" gibt es nie.
// Ohne verwertbare Angabe in der Discovery: RS256 (Pflichtverfahren von OpenID Connect).

var oidcAsymAlgs = map[string]bool{
	oidc.RS256: true, oidc.RS384: true, oidc.RS512: true, oidc.PS256: true, oidc.PS384: true, oidc.PS512: true,
	oidc.ES256: true, oidc.ES384: true, oidc.ES512: true, oidc.EdDSA: true,
}

var oidcHMACAlgs = map[string]bool{"HS256": true, "HS384": true, "HS512": true}

// oidcDiscovery: die Felder des Discovery-Dokuments, die go-oidc nicht herausgibt.
type oidcDiscovery struct {
	Issuer string   `json:"issuer"`
	JWKS   string   `json:"jwks_uri"`
	Algs   []string `json:"id_token_signing_alg_values_supported"`
}

// oidcAllowedAlgs: erlaubte Verfahren aus der Discovery (HS nur mit Secret); leer = RS256.
func oidcAllowedAlgs(advertised []string, haveSecret bool) []string {
	var out []string
	for _, a := range advertised {
		if oidcAsymAlgs[a] || (haveSecret && oidcHMACAlgs[a]) {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		out = []string{oidc.RS256}
	}
	return out
}

// oidcKeySet prueft die Signatur: HS mit dem Secret, sonst ueber den JWKS des Anbieters.
type oidcKeySet struct {
	remote  oidc.KeySet
	secret  []byte
	allowed []jose.SignatureAlgorithm
}

func (k *oidcKeySet) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	jws, err := jose.ParseSigned(raw, k.allowed)
	if err != nil {
		return nil, err
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("oidc: exactly one signature expected")
	}
	if oidcHMACAlgs[jws.Signatures[0].Header.Algorithm] {
		if len(k.secret) == 0 {
			return nil, errors.New("oidc: HMAC-signed id token but no client secret configured")
		}
		return jws.Verify(k.secret)
	}
	return k.remote.VerifySignature(ctx, raw)
}

// JWKS je Adresse und Satz eigener CAs, langlebig (die Schluessel werden zwischengespeichert und bei unbekannter kid
// neu geholt). Aendern sich die eigenen CAs, gibt es einen neuen Eintrag mit dem neuen Client.
var oidcJWKS struct {
	sync.Mutex
	m map[string]*oidc.RemoteKeySet
}

func oidcRemoteKeys(jwksURL string, hc *http.Client) *oidc.RemoteKeySet {
	oidcJWKS.Lock()
	defer oidcJWKS.Unlock()
	if oidcJWKS.m == nil {
		oidcJWKS.m = map[string]*oidc.RemoteKeySet{}
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	key := fmt.Sprintf("%s|%p", jwksURL, hc.Transport) // Transport je CA-Satz geteilt (oidcClient)
	ks := oidcJWKS.m[key]
	if ks == nil {
		if len(oidcJWKS.m) >= 32 { // alte CA-Saetze bzw. Adressen nicht ewig halten
			clear(oidcJWKS.m)
		}
		ctx := oidc.ClientContext(context.Background(), hc)
		ks = oidc.NewRemoteKeySet(ctx, jwksURL)
		oidcJWKS.m[key] = ks
	}
	return ks
}

// Transport zum SSO-Anbieter je Satz eigener CAs (ein Transport fuer alle Anmeldungen statt je Anmeldung einer, der
// nie geschlossen wird).
var oidcTr struct {
	sync.Mutex
	key string
	tr  *http.Transport
}

// oidcClient: HTTP-Client fuer den SSO-Anbieter - System-CAs plus die eigenen CAs der Node (Anbieter im eigenen
// Netz mit Zertifikat der eigenen CA, z. B. authentik; Forum).
func (s *Server) oidcClient(ctx context.Context) *http.Client {
	hc := &http.Client{Timeout: 10 * time.Second}
	if s.Certs == nil {
		return hc
	}
	pool, key := s.Certs.TrustPoolKey(ctx)
	if pool == nil {
		return hc
	}
	oidcTr.Lock()
	defer oidcTr.Unlock()
	if oidcTr.tr == nil || oidcTr.key != key {
		if oidcTr.tr != nil {
			oidcTr.tr.CloseIdleConnections()
		}
		oidcTr.key = key
		oidcTr.tr = &http.Transport{Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			IdleConnTimeout: 90 * time.Second, MaxIdleConnsPerHost: 2}
	}
	hc.Transport = oidcTr.tr
	return hc
}

// oidcVerifier: Pruefer fuer das ID-Token dieses Anbieters und die erlaubten Verfahren.
func oidcVerifier(p *oidc.Provider, o oidcSettings, hc *http.Client) (*oidc.IDTokenVerifier, []string, error) {
	var d oidcDiscovery
	if err := p.Claims(&d); err != nil {
		return nil, nil, err
	}
	allowed := oidcAllowedAlgs(d.Algs, o.Secret != "")
	ja := make([]jose.SignatureAlgorithm, 0, len(allowed))
	for _, a := range allowed {
		ja = append(ja, jose.SignatureAlgorithm(a))
	}
	var remote oidc.KeySet = &oidc.StaticKeySet{} // ohne JWKS: nur HS moeglich
	if d.JWKS != "" {
		remote = oidcRemoteKeys(d.JWKS, hc)
	}
	ks := &oidcKeySet{remote: remote, secret: []byte(o.Secret), allowed: ja}
	return oidc.NewVerifier(d.Issuer, ks, &oidc.Config{ClientID: o.ClientID, SupportedSigningAlgs: allowed}), allowed, nil
}

// oidcTokenAlg: Verfahren aus dem Kopf eines JWT (fuer die Fehlermeldung; "" = nicht lesbar).
func oidcTokenAlg(raw string) string {
	head, _, ok := strings.Cut(raw, ".")
	if !ok {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(head)
	if err != nil {
		return ""
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(b, &h) != nil || len(h.Alg) > 16 {
		return ""
	}
	return h.Alg
}
