package notify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

// secntfyFake bildet api.secntfy.app nach: Schluessel zum Geraete-Token, Nachricht entschluesseln.
type secntfyFake struct {
	key    *rsa.PrivateKey
	pkcs1  bool // Schluessel als PKCS#1 statt SubjectPublicKeyInfo
	status int  // Status in der Antwort auf POST /Message
	mu     sync.Mutex
	got    []map[string]any
	plain  []map[string]string
}

func (f *secntfyFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tok := r.Header.Get("X-NTFYME-DEVICE-KEY")
	if tok != "NTFY-DEVICE-abc123" {
		w.WriteHeader(401)
		_, _ = w.Write([]byte(`{"Status":401,"Message":"unknown device ` + tok + `"}`))
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/Message/Device":
		der, _ := x509.MarshalPKIXPublicKey(&f.key.PublicKey)
		if f.pkcs1 {
			der = x509.MarshalPKCS1PublicKey(&f.key.PublicKey)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": 200, "Token": base64.StdEncoding.EncodeToString(der)})
	case r.Method == http.MethodPost && r.URL.Path == "/Message":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		dec := map[string]string{}
		for _, k := range []string{"title", "body", "image"} {
			c, _ := base64.StdEncoding.DecodeString(body[k].(string))
			p, err := rsa.DecryptPKCS1v15(rand.Reader, f.key, c)
			if err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			dec[k] = string(p)
		}
		f.mu.Lock()
		f.got, f.plain = append(f.got, body), append(f.plain, dec)
		f.mu.Unlock()
		st := f.status
		if st == 0 {
			st = 200
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Status": st, "Message": "quota exceeded for NTFY-DEVICE-abc123"})
	default:
		http.NotFound(w, r)
	}
}

func newSecntfy(t *testing.T) (*secntfyFake, *httptest.Server) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &secntfyFake{key: key}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	old := secntfyServer
	secntfyServer = srv.URL
	t.Cleanup(func() { secntfyServer = old })
	return f, srv
}

// Titel, Text und Bild kommen verschluesselt an und lassen sich mit dem Schluessel des Geraets lesen; kritisch nur bei
// Stoerung und eingeschaltetem Schalter.
func TestSecNtfySend(t *testing.T) {
	f, _ := newSecntfy(t)
	ch := &Channel{Type: TypeApp, Config: map[string]string{"device_key": "NTFY-DEVICE-abc123", "critical": "true"}}
	s := secntfySender{"node64/test"}
	if err := s.Send(context.Background(), ch, Message{Kind: KindDown, Title: "Check web ist gestört", Text: "Grund: Timeout\n\nSeit: 12:00"}); err != nil {
		t.Fatal(err)
	}
	f.pkcs1 = true
	if err := s.Send(context.Background(), ch, Message{Kind: KindUp, Title: "Check web ok", Text: "wieder da"}); err != nil {
		t.Fatal(err)
	}
	if len(f.plain) != 2 || f.plain[0]["title"] != "Check web ist gestört" || f.plain[0]["body"] != "Grund: Timeout\nSeit: 12:00" || f.plain[0]["image"] != "" {
		t.Fatalf("plain: %v", f.plain)
	}
	if strings.Contains(f.got[0]["title"].(string), "web") {
		t.Fatal("title not encrypted")
	}
	n0, n1 := f.got[0]["notification"].(map[string]any), f.got[1]["notification"].(map[string]any)
	if n0["critical"] != true || n1["critical"] != false || n0["mutablecontent"] != float64(1) {
		t.Fatalf("notification: %v / %v", n0, n1)
	}
}

// Nur SecNtfy kuerzt: Text hoechstens 150 Zeichen, Titel passend zum RSA-Block, jeweils mit „...“ an Zeichengrenzen.
func TestSecNtfyCut(t *testing.T) {
	f, _ := newSecntfy(t)
	ch := &Channel{Type: TypeApp, Config: map[string]string{"device_key": "NTFY-DEVICE-abc123"}}
	long := strings.Repeat("Störung äöü ", 40)
	if err := (secntfySender{"t"}).Send(context.Background(), ch, Message{Kind: KindDown, Title: strings.Repeat("ü", 200), Text: long}); err != nil {
		t.Fatal(err)
	}
	title, body := f.plain[0]["title"], f.plain[0]["body"]
	if !strings.HasSuffix(body, "...") || utf8.RuneCountInString(body) > 153 || !utf8.ValidString(body) || !strings.HasPrefix(long, strings.TrimSuffix(body, "...")) {
		t.Fatalf("body: %d %q", utf8.RuneCountInString(body), body)
	}
	if !strings.HasSuffix(title, "...") || len(title) > 245 || !utf8.ValidString(title) {
		t.Fatalf("title: %d %q", len(title), title)
	}
	if got := secntfyCut("kurz", 245, 150); got != "kurz" {
		t.Fatal(got)
	}
}

// Fehler: falscher Token (vor jeder Anfrage), unbekanntes Geraet, Ablehnung – der Token steht in keiner Meldung.
func TestSecNtfyErrors(t *testing.T) {
	f, _ := newSecntfy(t)
	s := secntfySender{"t"}
	send := func(tok string) error {
		ch := &Channel{Type: TypeApp, Config: map[string]string{"device_key": tok}}
		return s.Send(context.Background(), ch, Message{Kind: KindTest, Title: "Test", Text: "x"})
	}
	if err := send("abc"); err == nil || !strings.Contains(err.Error(), "NTFY-DEVICE-") {
		t.Fatalf("bad token: %v", err)
	}
	if err := send("NTFY-DEVICE-other"); err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "NTFY-DEVICE-other") {
		t.Fatalf("unknown device: %v", err)
	}
	f.status = 429
	if err := send("NTFY-DEVICE-abc123"); err == nil || !strings.Contains(err.Error(), "status 429") || strings.Contains(err.Error(), "abc123") {
		t.Fatalf("rejected: %v", err)
	}
	// alter Typ secntfy wird zu app, ein gespeicherter Server faellt weg (fest)
	c := &Channel{Type: TypeSecNtfy, Name: "x", Config: map[string]string{"server": "https://example.org/", "device_key": "token"}}
	if err := c.Validate(); err == nil {
		t.Fatal("invalid token accepted")
	}
	c.Config["device_key"] = " NTFY-DEVICE-abc "
	if err := c.Validate(); err != nil || c.Type != TypeApp || c.Config["device_key"] != "NTFY-DEVICE-abc" || c.Config["server"] != "" {
		t.Fatalf("validate: %v %s %v", err, c.Type, c.Config)
	}
}
