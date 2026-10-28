package cdn64

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// API-Keys einer Zugriffsliste: fuer Apps und Skripte, die keine Anmeldeseite koennen. PROXY64 erzeugt sie, zeigt sie
// einmal und speichert nur den SHA-256-Wert. Angenommen als "Authorization: Bearer <key>", im Header X-API-Key oder als
// Passwort bei Basic Auth (Benutzername beliebig). Nur Werte mit dem Praefix p64k_ zaehlen als Versuch, andere Tokens
// gehoeren dem Ziel und bleiben unberuehrt.

const (
	keyPrefix  = "p64k_"
	keyHeader  = "X-API-Key"
	maxKeys    = 50
	keyHintLen = len(keyPrefix) + 6
)

// AccessKey ist ein API-Key einer Liste (nur der Hash wird gespeichert).
type AccessKey struct {
	Name      string    `json:"name"`
	Hash      string    `json:"hash,omitempty"`
	Hint      string    `json:"hint"` // Anfang des Keys, zum Wiedererkennen und Loeschen
	CreatedAt time.Time `json:"created_at"`
}

func keyHash(k string) string {
	s := sha256.Sum256([]byte(k))
	return hex.EncodeToString(s[:])
}

// newAccessKey erzeugt einen Key; den Klartext gibt es nur hier.
func newAccessKey(name string) (AccessKey, string) {
	b := make([]byte, 30)
	_, _ = rand.Read(b)
	k := keyPrefix + base64.RawURLEncoding.EncodeToString(b)
	return AccessKey{Name: name, Hash: keyHash(k), Hint: k[:keyHintLen], CreatedAt: time.Now().UTC()}, k
}

// keyOf: mitgeschickter Key (Bearer, X-API-Key oder Basic-Auth-Passwort) mit Praefix p64k_, sonst "".
func keyOf(r *http.Request) string {
	if v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && strings.HasPrefix(strings.TrimSpace(v), keyPrefix) {
		return strings.TrimSpace(v)
	}
	if v := strings.TrimSpace(r.Header.Get(keyHeader)); strings.HasPrefix(v, keyPrefix) {
		return v
	}
	if _, p, ok := r.BasicAuth(); ok && strings.HasPrefix(p, keyPrefix) {
		return p
	}
	return ""
}

// keyOK prueft den mitgeschickten Key: name des Keys, ok, tried (ein p64k_-Wert war dabei).
func (g *guard) keyOK(r *http.Request) (name string, ok, tried bool) {
	k := keyOf(r)
	if k == "" {
		return "", false, false
	}
	h := []byte(keyHash(k))
	for _, ak := range g.list.Keys {
		if subtle.ConstantTimeCompare(h, []byte(ak.Hash)) == 1 {
			return ak.Name, true, true
		}
	}
	return "", false, true
}

// stripKey entfernt den Key aus der Anfrage, bevor sie ans Ziel geht.
func stripKey(r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "+keyPrefix) {
		r.Header.Del("Authorization")
	}
	if _, p, ok := r.BasicAuth(); ok && strings.HasPrefix(p, keyPrefix) {
		r.Header.Del("Authorization")
	}
	if strings.HasPrefix(strings.TrimSpace(r.Header.Get(keyHeader)), keyPrefix) {
		r.Header.Del(keyHeader)
	}
}

// normalizeKeys prueft Namen und Anzahl (Hashes setzt nur newAccessKey).
func normalizeKeys(a *AccessList) error {
	var out []AccessKey
	for _, k := range a.Keys {
		k.Name = strings.TrimSpace(k.Name)
		if k.Name == "" || len(k.Name) > 64 || len(k.Hash) != 64 {
			return &FieldError{Field: "keys", Key: "cdn64.err.acl_key", Name: k.Name}
		}
		out = append(out, k)
	}
	if len(out) > maxKeys {
		return &FieldError{Field: "keys", Key: "cdn64.err.acl_keys_max", Name: strconv.Itoa(maxKeys)}
	}
	if out == nil {
		out = []AccessKey{}
	}
	a.Keys = out
	return nil
}
