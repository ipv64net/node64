package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeCA ist eine kleine ACME-Stelle nach RFC 8555 fuer Tests: prueft die Antworten auf dns-01 (ueber txt) und
// http-01 (ueber httpGet) wirklich und stellt Zertifikate mit einstellbarer Laufzeit aus. Signaturen der
// Anfragen prueft sie nicht.
type fakeCA struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	n        int
	thumb    string
	accounts int
	orders   map[string]*fOrder
	authz    map[string]*fAuthz
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	validity time.Duration
	issued   int
	eab      bool   // External Account Binding verlangen
	eabKID   string // zuletzt gesehene KID

	txt     func(fqdn string) []string               // sichtbare TXT-Werte (folgt CNAMEs selbst)
	httpGet func(name, token string) (string, error) // Abruf von http://<name>/.well-known/acme-challenge/<token>
}

type fOrder struct {
	id     string
	names  []string
	authz  []string
	status string
	cert   []byte
}

type fAuthz struct {
	id, name, token, status string
	wildcard                bool
}

func newFakeCA(t *testing.T) *fakeCA {
	ca := &fakeCA{t: t, orders: map[string]*fOrder{}, authz: map[string]*fAuthz{}, validity: 90 * 24 * time.Hour}
	ca.caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Fake ACME CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &ca.caKey.PublicKey, ca.caKey)
	ca.caCert, _ = x509.ParseCertificate(der)
	ca.srv = httptest.NewServer(http.HandlerFunc(ca.serve))
	t.Cleanup(ca.srv.Close)
	return ca
}

func (ca *fakeCA) url(p string) string { return ca.srv.URL + p }

func (ca *fakeCA) id() string {
	ca.n++
	return fmt.Sprint(ca.n)
}

func (ca *fakeCA) reply(w http.ResponseWriter, status int, loc string, v any) {
	w.Header().Set("Replay-Nonce", "n"+fmt.Sprint(time.Now().UnixNano()))
	if loc != "" {
		w.Header().Set("Location", loc)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (ca *fakeCA) serve(w http.ResponseWriter, r *http.Request) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if r.URL.Path == "/dir" {
		ca.reply(w, 200, "", map[string]any{"newNonce": ca.url("/nonce"), "newAccount": ca.url("/acct"), "newOrder": ca.url("/order"),
			"revokeCert": ca.url("/revoke"), "keyChange": ca.url("/kc"), "meta": map[string]any{"termsOfService": "https://example.test/tos",
				"externalAccountRequired": ca.eab}})
		return
	}
	if r.URL.Path == "/nonce" {
		w.Header().Set("Replay-Nonce", "n0")
		w.WriteHeader(200)
		return
	}
	var jws struct{ Protected, Payload string }
	_ = json.NewDecoder(r.Body).Decode(&jws)
	var prot struct {
		JWK json.RawMessage `json:"jwk"`
	}
	b, _ := base64.RawURLEncoding.DecodeString(jws.Protected)
	_ = json.Unmarshal(b, &prot)
	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch parts[0] {
	case "acct":
		if len(parts) == 1 {
			var jwk struct{ Crv, Kty, X, Y string }
			_ = json.Unmarshal(prot.JWK, &jwk)
			h := sha256.Sum256([]byte(fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)))
			ca.thumb = base64.RawURLEncoding.EncodeToString(h[:])
			var acct struct {
				EAB *struct{ Protected string } `json:"externalAccountBinding"`
			}
			_ = json.Unmarshal(payload, &acct)
			if acct.EAB != nil {
				var p struct{ KID string }
				pb, _ := base64.RawURLEncoding.DecodeString(acct.EAB.Protected)
				_ = json.Unmarshal(pb, &p)
				ca.eabKID = p.KID
			}
			if ca.eab && ca.eabKID == "" {
				w.Header().Set("Content-Type", "application/problem+json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"type":"urn:ietf:params:acme:error:externalAccountRequired","detail":"eab required"}`))
				return
			}
			ca.accounts++
			status := 201
			if ca.accounts > 1 {
				status = 200
			}
			ca.reply(w, status, ca.url("/acct/1"), map[string]any{"status": "valid"})
			return
		}
		ca.reply(w, 200, ca.url("/acct/1"), map[string]any{"status": "valid"})
	case "order":
		if len(parts) == 1 { // neuer Auftrag
			var req struct {
				Identifiers []struct{ Type, Value string }
			}
			_ = json.Unmarshal(payload, &req)
			o := &fOrder{id: ca.id(), status: "pending"}
			for _, idf := range req.Identifiers {
				a := &fAuthz{id: ca.id(), name: strings.TrimPrefix(idf.Value, "*."), wildcard: strings.HasPrefix(idf.Value, "*."), token: "tok" + ca.id(), status: "pending"}
				ca.authz[a.id] = a
				o.authz = append(o.authz, a.id)
				o.names = append(o.names, idf.Value)
			}
			ca.orders[o.id] = o
			ca.reply(w, 201, ca.url("/order/"+o.id), ca.orderJSON(o))
			return
		}
		o := ca.orders[parts[1]]
		ca.refresh(o)
		ca.reply(w, 200, ca.url("/order/"+o.id), ca.orderJSON(o))
	case "authz":
		a := ca.authz[parts[1]]
		ca.reply(w, 200, "", ca.authzJSON(a))
	case "chal":
		a := ca.authz[parts[2]]
		ca.validate(a, parts[1])
		ca.reply(w, 200, "", map[string]any{"type": parts[1], "url": ca.url("/chal/" + parts[1] + "/" + a.id), "token": a.token, "status": a.status})
	case "finalize":
		o := ca.orders[parts[1]]
		var req struct{ CSR string }
		_ = json.Unmarshal(payload, &req)
		der, _ := base64.RawURLEncoding.DecodeString(req.CSR)
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil || o.status != "ready" {
			ca.reply(w, 403, "", map[string]any{"type": "urn:ietf:params:acme:error:orderNotReady", "detail": "not ready"})
			return
		}
		tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Minute),
			NotAfter: time.Now().Add(ca.validity), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
		crt, _ := x509.CreateCertificate(rand.Reader, tpl, ca.caCert, csr.PublicKey, ca.caKey)
		o.cert = append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.caCert.Raw})...)
		o.status = "valid"
		ca.issued++
		ca.reply(w, 200, ca.url("/order/"+o.id), ca.orderJSON(o))
	case "cert":
		o := ca.orders[parts[1]]
		w.Header().Set("Replay-Nonce", "n1")
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(o.cert)
	default:
		w.WriteHeader(404)
	}
}

func (ca *fakeCA) refresh(o *fOrder) {
	if o.status != "pending" {
		return
	}
	for _, id := range o.authz {
		switch ca.authz[id].status {
		case "invalid":
			o.status = "invalid"
			return
		case "pending":
			return
		}
	}
	o.status = "ready"
}

func (ca *fakeCA) orderJSON(o *fOrder) map[string]any {
	ids := []map[string]string{}
	for _, n := range o.names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	var az []string
	for _, id := range o.authz {
		az = append(az, ca.url("/authz/"+id))
	}
	v := map[string]any{"status": o.status, "identifiers": ids, "authorizations": az, "finalize": ca.url("/finalize/" + o.id)}
	if o.status == "valid" {
		v["certificate"] = ca.url("/cert/" + o.id)
	}
	return v
}

func (ca *fakeCA) authzJSON(a *fAuthz) map[string]any {
	chals := []map[string]any{}
	types := []string{"dns-01"}
	if !a.wildcard {
		types = append(types, "http-01")
	}
	for _, typ := range types {
		chals = append(chals, map[string]any{"type": typ, "url": ca.url("/chal/" + typ + "/" + a.id), "token": a.token, "status": a.status})
	}
	return map[string]any{"status": a.status, "identifier": map[string]string{"type": "dns", "value": a.name}, "challenges": chals, "wildcard": a.wildcard}
}

// validate prueft die Antwort wie Let's Encrypt (Aufrufer haelt ca.mu).
func (ca *fakeCA) validate(a *fAuthz, typ string) {
	keyAuth := a.token + "." + ca.thumb
	ok := false
	switch typ {
	case "dns-01":
		h := sha256.Sum256([]byte(keyAuth))
		want := base64.RawURLEncoding.EncodeToString(h[:])
		ca.mu.Unlock()
		for _, v := range ca.txt("_acme-challenge." + a.name) {
			ok = ok || v == want
		}
		ca.mu.Lock()
	case "http-01":
		ca.mu.Unlock()
		got, err := ca.httpGet(a.name, a.token)
		ca.mu.Lock()
		ok = err == nil && strings.TrimSpace(got) == keyAuth
	}
	if ok {
		a.status = "valid"
	} else {
		a.status = "invalid"
	}
}

// fakeDNS ist die ipv64-API fuer Tests (Domains und TXT-Records), dazu CNAMEs beim "fremden" Anbieter.
type fakeDNS struct {
	mu      sync.Mutex
	domains []string
	txt     map[string][]string // fqdn -> Werte
	cname   map[string]string
	added   int
	peak    int // hoechste Zahl gleichzeitiger Werte unter einem Namen
}

func newFakeDNS(domains ...string) *fakeDNS {
	return &fakeDNS{domains: domains, txt: map[string][]string{}, cname: map[string]string{}}
}

func (f *fakeDNS) records() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, v := range f.txt {
		n += len(v)
	}
	return n
}

func (f *fakeDNS) lookup(fqdn string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t, ok := f.cname[fqdn]; ok {
		fqdn = strings.TrimSuffix(t, ".")
	}
	return append([]string(nil), f.txt[fqdn]...)
}
