package store

import (
	"crypto/sha256"
	"encoding/hex"
)

// ExternalUID liefert die feste Cluster-Kennung (users.uid) fuer einen Benutzer, der beim ersten Anmelden ueber
// LDAP/SSO angelegt wird. Deterministisch aus Quelle und Schluessel, damit dieselbe Person auf zwei Nodes dieselbe
// Kennung bekommt und im Cluster kein Konflikt zur Wahl entsteht. Aufruf: ("ldap", objectGUID-hex bzw. entryUUID)
// oder ("oidc", issuer+"\x00"+subject). Ergebnis: 32 Hex-Zeichen (wie die zufaelligen Kennungen).
func ExternalUID(source, key string) string {
	h := sha256.Sum256([]byte(source + "\x00" + key))
	return hex.EncodeToString(h[:])[:32]
}
