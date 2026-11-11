package proxmox

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Schluessel fuer die Docker-Tests ueber SSH (frueher fuer die Healthchecks im Programm; Monitor64 hat eigene).

// GenerateDockerSSHKey erzeugt einen ed25519-Schluessel (PEM).
func GenerateDockerSSHKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	blk, err := ssh.MarshalPrivateKey(priv, "node64")
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(blk)), nil
}

// DockerSSHPublicKey liefert die Zeile fuer authorized_keys zum privaten Schluessel ("" bei Fehler).
func DockerSSHPublicKey(privPEM string) string {
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))) + " node64"
}
