package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

// SecNtfy (secntfy.app): Ende-zu-Ende verschluesselte Push-Nachrichten. Der Server liefert zum Geraete-Token den
// oeffentlichen RSA-Schluessel des Geraets (GET /Message/Device), Titel, Text und Bild-URL gehen einzeln mit RSA
// (PKCS#1 v1.5) verschluesselt an POST /Message – wie die offizielle Bibliothek (github.com/SecNtfy/SecNtfy-PHP).
// Ein RSA-Block fasst nur Schluessellaenge-11 Bytes (245 bei 2048 Bit), der Text hoechstens 150 Zeichen: gekuerzt
// wird nur hier, die anderen Kanaele bekommen die volle Meldung.

const (
	secntfyDefaultServer = "https://api.secntfy.app"
	secntfyTokenPrefix   = "NTFY-DEVICE-"
	secntfyMaxText       = 150 // Zeichen (Vorgabe der Bibliothek)
)

type secntfySender struct{ ua string }

func (s secntfySender) Send(ctx context.Context, ch *Channel, m Message) error {
	server := strings.TrimRight(ch.Config["server"], "/")
	if server == "" {
		server = secntfyDefaultServer
	}
	token := strings.TrimSpace(ch.Config["device_key"])
	if !validSecntfyToken(token) {
		return errors.New("secntfy: device token must start with " + secntfyTokenPrefix)
	}
	var keyResp struct {
		Status int
		Token  string
	}
	if err := s.call(ctx, http.MethodGet, server+"/Message/Device", token, nil, &keyResp); err != nil {
		return err
	}
	if keyResp.Status != 200 || keyResp.Token == "" {
		return fmt.Errorf("secntfy: no public key for this device (status %d)", keyResp.Status)
	}
	pub, err := secntfyKey(keyResp.Token)
	if err != nil {
		return err
	}
	max := pub.Size() - 11
	text := strings.Join(chatLines(m.Text), "\n")
	title, body, image := "", "", ""
	if title, err = secntfyEnc(pub, secntfyCut(m.Title, max, 0)); err != nil {
		return err
	}
	if body, err = secntfyEnc(pub, secntfyCut(text, max, secntfyMaxText)); err != nil {
		return err
	}
	if image, err = secntfyEnc(pub, ""); err != nil {
		return err
	}
	critical := false
	switch m.Kind {
	case KindDown, KindReminder, KindSummary:
		critical = ch.Config["critical"] == "true" || ch.Config["critical"] == "on"
	}
	payload := map[string]any{"title": title, "body": body, "image": image,
		"notification": map[string]any{"critical": critical, "priority": 0, "mutablecontent": 1, "sound": map[string]any{"name": "default", "volume": 1.0}}}
	var res struct {
		Status  int
		Message string
	}
	if err := s.call(ctx, http.MethodPost, server+"/Message", token, payload, &res); err != nil {
		return err
	}
	if res.Status < 200 || res.Status > 299 {
		msg := strings.ReplaceAll(res.Message, token, "[redacted]")
		if msg == "" {
			msg = "rejected"
		}
		return fmt.Errorf("secntfy: %s (status %d)", msg, res.Status)
	}
	return nil
}

func validSecntfyToken(t string) bool {
	if !strings.HasPrefix(t, secntfyTokenPrefix) || len(t) == len(secntfyTokenPrefix) {
		return false
	}
	for _, r := range t {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// secntfyKey liest den oeffentlichen Schluessel (Base64-DER, SubjectPublicKeyInfo oder PKCS#1).
func secntfyKey(b64 string) (*rsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(der) == 0 {
		return nil, errors.New("secntfy: invalid public key")
	}
	if k, err := x509.ParsePKIXPublicKey(der); err == nil {
		if rk, ok := k.(*rsa.PublicKey); ok {
			return rk, nil
		}
		return nil, errors.New("secntfy: public key is not RSA")
	}
	if rk, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return rk, nil
	}
	return nil, errors.New("secntfy: unreadable public key")
}

func secntfyEnc(pub *rsa.PublicKey, s string) (string, error) {
	c, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(s))
	if err != nil {
		return "", fmt.Errorf("secntfy: encrypt: %w", err)
	}
	return base64.StdEncoding.EncodeToString(c), nil
}

// secntfyCut kuerzt auf hoechstens maxChars Zeichen (0 = egal) und maxBytes Bytes, an Zeichengrenzen, mit „...“.
func secntfyCut(s string, maxBytes, maxChars int) string {
	if (maxChars == 0 || utf8.RuneCountInString(s) <= maxChars) && len(s) <= maxBytes {
		return s
	}
	const dots = "..."
	var b strings.Builder
	n := 0
	for _, r := range s {
		if maxChars > 0 && n >= maxChars || b.Len()+utf8.RuneLen(r) > maxBytes-len(dots) {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRight(b.String(), " \n") + dots
}

func (s secntfySender) call(ctx context.Context, method, u, token string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-NTFYME-DEVICE-KEY", token)
	req.Header.Set("User-Agent", s.ua)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return netErr(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct{ Message string }
		if json.Unmarshal(rb, &e) == nil && e.Message != "" {
			return statusErr(resp.StatusCode, fmt.Errorf("secntfy: HTTP %d: %s", resp.StatusCode, excerpt(strings.ReplaceAll(e.Message, token, "[redacted]"))))
		}
		return statusErr(resp.StatusCode, fmt.Errorf("secntfy: HTTP %d", resp.StatusCode))
	}
	if err := json.Unmarshal(rb, out); err != nil {
		return errors.New("secntfy: invalid JSON response")
	}
	return nil
}
