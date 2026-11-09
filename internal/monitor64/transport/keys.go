package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/ssh"
)

// GenerateKey erzeugt den Schluessel der Node (ed25519). privPEM ist der private Schluessel im OpenSSH-Format
// (PEM, unverschluesselt - der Aufrufer legt ihn verschluesselt in internal/secrets ab).
func GenerateKey(comment string) (privPEM []byte, signer ssh.Signer, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	blk, err := ssh.MarshalPrivateKey(priv, cleanComment(comment))
	if err != nil {
		return nil, nil, err
	}
	signer, err = ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(blk), signer, nil
}

// ParseKey liest einen privaten Schluessel (OpenSSH- oder PEM-Format) als ssh.Signer.
func ParseKey(privPEM []byte) (ssh.Signer, error) {
	return ssh.ParsePrivateKey(privPEM)
}

// Fingerprint liefert den Fingerabdruck wie OpenSSH ("SHA256:...").
func Fingerprint(pub ssh.PublicKey) string {
	return ssh.FingerprintSHA256(pub)
}

// NormalizeFingerprint vereinheitlicht eingegebene Fingerabdruecke ("SHA256:" vorne, ohne "="-Auffuellung).
func NormalizeFingerprint(fp string) string {
	fp = strings.TrimSpace(fp)
	if fp == "" {
		return ""
	}
	if len(fp) > 7 && strings.EqualFold(fp[:7], "SHA256:") {
		fp = fp[7:]
	}
	return "SHA256:" + strings.TrimRight(fp, "=")
}

// AuthorizedKeyLine liefert die Zeile fuer authorized_keys bzw. den Installationsbefehl des Agents
// ("ssh-ed25519 AAAA... kommentar").
func AuthorizedKeyLine(pub ssh.PublicKey, comment string) string {
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	if c := cleanComment(comment); c != "" {
		line += " " + c
	}
	return line
}

// cleanComment: Kommentar ohne Steuerzeichen und Anfuehrungszeichen (steht im Installationsbefehl).
func cleanComment(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\'' || r == '`' || r == '\\' || r == '$' {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), "_")
	if len(s) > 100 {
		s = strings.ToValidUTF8(s[:100], "")
	}
	return s
}
