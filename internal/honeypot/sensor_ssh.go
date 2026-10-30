package honeypot

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH-Falle: Banner und Algorithmen je Profil (OpenSSH Debian 12 / Ubuntu 24.04, Dropbear), jede Anmeldung
// (Passwort, Public Key, Keyboard-Interactive) wird abgelehnt und gemeldet. Kein Kanal, keine Shell, keine
// Weiterleitung (die Verbindung endet mit der Anmeldung).
const (
	sensorSSHTries   = 6
	sensorSSHTimeout = 60 * time.Second
)

var errSensorDenied = errors.New("permission denied")

// sensorSSHConfig liefert Banner, Algorithmen und Host-Schluessel zum Profil: die Reihenfolge wie beim Original,
// soweit x/crypto/ssh die Verfahren kennt (sntrup761, group18, umac fehlen; mlkem bieten OpenSSH 9.2/9.6 und
// Dropbear 2024 nicht an). OpenSSH ohne ssh-rsa (SHA-1), Dropbear mit.
func sensorSSHConfig(persona string, id *sensorIdent, keys *sensorSSHKeys) (string, ssh.Config, []ssh.Signer) {
	banner := id.sshBanner(persona)
	rsaAlgos := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	cfg := ssh.Config{
		KeyExchanges: []string{ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP256, ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP521,
			ssh.KeyExchangeDHGEXSHA256, ssh.KeyExchangeDH16SHA512, ssh.KeyExchangeDH14SHA256},
		Ciphers: []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES128CTR, ssh.CipherAES192CTR, ssh.CipherAES256CTR, ssh.CipherAES128GCM, ssh.CipherAES256GCM},
		MACs:    []string{ssh.HMACSHA256ETM, ssh.HMACSHA512ETM, ssh.HMACSHA256, ssh.HMACSHA512, ssh.HMACSHA1},
	}
	order := []ssh.Signer{keys.rsa, keys.ecdsa, keys.ed25519}
	if persona == PersonaDropbear {
		rsaAlgos = []string{ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		cfg = ssh.Config{
			KeyExchanges: []string{ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP521, ssh.KeyExchangeECDHP384, ssh.KeyExchangeECDHP256,
				ssh.KeyExchangeDH14SHA256, ssh.InsecureKeyExchangeDH14SHA1},
			Ciphers: []string{ssh.CipherChaCha20Poly1305, ssh.CipherAES128CTR, ssh.CipherAES256CTR},
			MACs:    []string{ssh.HMACSHA1, ssh.HMACSHA256},
		}
		order = []ssh.Signer{keys.ed25519, keys.ecdsa, keys.rsa}
	}
	var hostKeys []ssh.Signer
	for _, k := range order {
		if as, ok := k.(ssh.AlgorithmSigner); ok && k == keys.rsa {
			if ms, err := ssh.NewSignerWithAlgorithms(as, rsaAlgos); err == nil {
				k = ms
			}
		}
		hostKeys = append(hostKeys, k)
	}
	return banner, cfg, hostKeys
}

func (s *Sensor) handleSSH(c *trapConn, keys *sensorSSHKeys) {
	p := s.personas()
	banner, algos, hostKeys := sensorSSHConfig(p.of(c.t.key), p.identFor(c.t.key), keys)
	_ = c.SetDeadline(time.Now().Add(sensorSSHTimeout))
	attempts := 0
	var client string
	ev := func(m ssh.ConnMetadata) Event {
		e := c.event(KindSSHBrute)
		e.Username = m.User()
		e.Client = string(m.ClientVersion())
		return e
	}
	cfg := &ssh.ServerConfig{
		Config:        algos,
		MaxAuthTries:  sensorSSHTries,
		ServerVersion: banner,
		PasswordCallback: func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			attempts++
			e := ev(m)
			e.Password = string(pw)
			s.login(e)
			return nil, errSensorDenied
		},
		PublicKeyCallback: func(m ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			attempts++
			e := ev(m)
			e.Detail = ssh.FingerprintSHA256(key)
			s.login(e)
			return nil, errSensorDenied
		},
		KeyboardInteractiveCallback: func(m ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ask("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(ans) != 1 {
				return nil, errSensorDenied
			}
			attempts++
			e := ev(m)
			e.Password = ans[0]
			s.login(e)
			return nil, errSensorDenied
		},
		AuthLogCallback: func(m ssh.ConnMetadata, _ string, _ error) {
			client = string(m.ClientVersion())
		},
	}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	if sc, _, _, err := ssh.NewServerConn(c, cfg); err == nil {
		_ = sc.Close() // kann nicht passieren (alles wird abgelehnt), sicherheitshalber
	}
	if attempts == 0 {
		// Verbindung ohne Anmeldeversuch (Banner-Abfrage, Scanner)
		e := c.event(KindProbe)
		e.Client = client // kein Username: zaehlt sonst als Login
		s.emit(e)
	}
}
