package web

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softKey ist ein Authenticator in Software (ES256, Attestation "none") fuer Tests.
type softKey struct {
	key    *ecdsa.PrivateKey
	credID []byte
	handle []byte
	count  uint32
}

var b64u = base64.RawURLEncoding

func (k *softKey) authData(rpID string, attested bool) []byte {
	h := sha256.Sum256([]byte(rpID))
	var buf bytes.Buffer
	buf.Write(h[:])
	flags := byte(0x01 | 0x04) // UP, UV
	if attested {
		flags |= 0x40 // AT
	}
	buf.WriteByte(flags)
	k.count++
	_ = binary.Write(&buf, binary.BigEndian, k.count)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(k.credID)))
		buf.Write(k.credID)
		cose, _ := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: k.key.X.FillBytes(make([]byte, 32)), -3: k.key.Y.FillBytes(make([]byte, 32))})
		buf.Write(cose)
	}
	return buf.Bytes()
}

func clientData(typ, challenge, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin})
	return b
}

// call schickt JSON wie passkey.js an die Node (Host = localhost, damit Passkeys erlaubt sind).
func pkCall(t *testing.T, a *testApp, host, path, csrf string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = strings.NewReader("{}")
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest("POST", a.srv.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", csrf)
	resp := doAsHost(t, a, req, host)
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestPasskeyRegisterAndLogin(t *testing.T) {
	a := newTestApp(t)
	u := loginAs(t, a, "admin", "sehr geheimes passwort")
	port := strings.TrimPrefix(a.srv.URL, "http://127.0.0.1:")
	host, origin := "localhost:"+port, "http://localhost:"+port
	_, body := a.get(t, "/settings/login")
	csrf := csrfOf(t, body)
	// unter einer IP-Adresse gibt es keine Passkeys
	if c, _ := pkCall(t, a, "127.0.0.1:"+port, "/settings/login/passkeys/begin", csrf, nil); c != http.StatusUnprocessableEntity {
		t.Fatalf("passkeys under an IP must be refused: %d", c)
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k := &softKey{key: key, credID: []byte("cred-0123456789")}
	c, opts := pkCall(t, a, host, "/settings/login/passkeys/begin", csrf, nil)
	if c != 200 {
		t.Fatalf("begin registration: %d %v", c, opts)
	}
	pub := opts["publicKey"].(map[string]any)
	k.handle, _ = b64u.DecodeString(pub["user"].(map[string]any)["id"].(string))
	att, _ := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData("localhost", true)})
	cd := clientData("webauthn.create", pub["challenge"].(string), origin)
	c, out := pkCall(t, a, host, "/settings/login/passkeys/finish?name=Testkey", csrf, map[string]any{
		"id": b64u.EncodeToString(k.credID), "rawId": b64u.EncodeToString(k.credID), "type": "public-key",
		"response": map[string]any{"attestationObject": b64u.EncodeToString(att), "clientDataJSON": b64u.EncodeToString(cd)}})
	if c != 200 {
		t.Fatalf("finish registration: %d %v", c, out)
	}
	if list, _ := a.store.Passkeys(t.Context(), u.ID, "localhost"); len(list) != 1 || list[0].Name != "Testkey" {
		t.Fatalf("passkey not stored: %+v", list)
	}
	// abmelden, Login-Seite zeigt den Knopf, Anmeldung mit dem Passkey
	_, _ = a.post(t, "/logout", url.Values{"_csrf": {csrf}})
	req, _ := http.NewRequest("GET", a.srv.URL+"/login", nil)
	resp := doAsHost(t, a, req, host)
	lb, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(lb), "passkey-login") {
		t.Fatal("login page without passkey button")
	}
	csrf = csrfOf(t, string(lb))
	login := func(sign func(ad, cd []byte) []byte) (int, map[string]any) {
		c, opts := pkCall(t, a, host, "/login/passkey/begin?next=/settings", csrf, nil)
		if c != 200 {
			t.Fatalf("begin login: %d", c)
		}
		ch := opts["publicKey"].(map[string]any)["challenge"].(string)
		ad := k.authData("localhost", false)
		cd := clientData("webauthn.get", ch, origin)
		return pkCall(t, a, host, "/login/passkey/finish", csrf, map[string]any{
			"id": b64u.EncodeToString(k.credID), "rawId": b64u.EncodeToString(k.credID), "type": "public-key",
			"response": map[string]any{"authenticatorData": b64u.EncodeToString(ad), "clientDataJSON": b64u.EncodeToString(cd),
				"signature": b64u.EncodeToString(sign(ad, cd)), "userHandle": b64u.EncodeToString(k.handle)}})
	}
	good := func(ad, cd []byte) []byte {
		h := sha256.Sum256(cd)
		d := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
		sig, _ := ecdsa.SignASN1(rand.Reader, key, d[:])
		return sig
	}
	// falsche Signatur: abgelehnt, keine Sitzung
	if c, _ := login(func(ad, cd []byte) []byte { return good(ad, []byte("other")) }); c != http.StatusUnauthorized {
		t.Fatalf("wrong signature must be rejected: %d", c)
	}
	if resp, _ := a.get(t, "/settings"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("no session after a rejected passkey")
	}
	c, out = login(good)
	if c != 200 || out["redirect"] != "/settings" {
		t.Fatalf("passkey login: %d %v", c, out)
	}
	if resp, _ := a.get(t, "/settings"); resp.StatusCode != 200 {
		t.Fatalf("not signed in after passkey: %d", resp.StatusCode)
	}
}

// doAsHost schickt eine Anfrage mit anderem Host-Kopf; die Cookies der Sitzung gehen ausdruecklich mit (der
// Cookie-Jar waehlt sonst nach dem Host-Kopf) und neue Cookies landen wieder im Jar.
func doAsHost(t *testing.T, a *testApp, req *http.Request, host string) *http.Response {
	t.Helper()
	base, _ := url.Parse(a.srv.URL)
	req.Host = host
	for _, c := range a.client.Jar.Cookies(base) {
		req.AddCookie(c)
	}
	resp, err := (&http.Client{CheckRedirect: a.client.CheckRedirect}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	a.client.Jar.SetCookies(base, resp.Cookies())
	return resp
}
