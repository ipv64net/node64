// Package totp implementiert zeitbasierte Einmalcodes nach RFC 6238
// (6 Stellen, 30 Sekunden, HMAC-SHA1), kompatibel mit den ueblichen
// Authenticator-Apps.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // von RFC 6238 vorgegeben
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	Digits = 6
	Period = 30
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret erzeugt ein Geheimnis mit 160 Bit als Base32.
func NewSecret() string {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return enc.EncodeToString(b)
}

// Code berechnet den Code fuer einen Zeitpunkt.
func Code(secret string, t time.Time) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.ReplaceAll(secret, " ", "")))
	if err != nil {
		return "", fmt.Errorf("invalid secret")
	}
	counter := uint64(t.Unix() / Period)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000), nil
}

// Verify prueft einen Code mit einem Fenster von +-1 Periode.
func Verify(secret, code string, t time.Time) bool {
	_, ok := VerifyStep(secret, code, t)
	return ok
}

// VerifyStep prueft wie Verify und liefert zusaetzlich den getroffenen Zeitschritt (Zaehler nach RFC 6238). Der
// Aufrufer merkt sich den verbrauchten Schritt und nimmt danach nur groessere an, damit ein Code nur einmal gilt.
func VerifyStep(secret, code string, t time.Time) (int64, bool) {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != Digits || strings.TrimSpace(secret) == "" { // ohne Geheimnis gilt kein Code
		return 0, false
	}
	for _, d := range []int{0, -1, 1} {
		at := t.Add(time.Duration(d) * Period * time.Second)
		want, err := Code(secret, at)
		if err != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return at.Unix() / Period, true
		}
	}
	return 0, false
}

// URL liefert den otpauth-Link fuer QR-Codes.
func URL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {fmt.Sprint(Digits)}, "period": {fmt.Sprint(Period)}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// NewRecoveryCodes erzeugt n Wiederherstellungscodes (Klartext) und ihre Hashes.
func NewRecoveryCodes(n int) (codes []string, hashes []string) {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
	for i := 0; i < n; i++ {
		b := make([]byte, 10)
		if _, err := rand.Read(b); err != nil {
			panic(err)
		}
		for j := range b {
			b[j] = alphabet[int(b[j])%len(alphabet)]
		}
		code := string(b[:5]) + "-" + string(b[5:])
		codes = append(codes, code)
		hashes = append(hashes, HashRecovery(code))
	}
	return codes, hashes
}

// HashRecovery hasht einen Wiederherstellungscode.
func HashRecovery(code string) string {
	code = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// UseRecovery prueft einen Code gegen die Hash-Liste und liefert die Liste ohne ihn.
func UseRecovery(code string, hashes []string) ([]string, bool) {
	h := HashRecovery(code)
	for i, x := range hashes {
		if subtle.ConstantTimeCompare([]byte(x), []byte(h)) == 1 {
			return append(append([]string{}, hashes[:i]...), hashes[i+1:]...), true
		}
	}
	return hashes, false
}
