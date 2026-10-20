package honeypot

import (
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSH-Falle: Banner wie ein OpenSSH auf Debian 12, jede Anmeldung (Passwort, Public Key, Keyboard-Interactive)
// wird abgelehnt und gemeldet. Kein Kanal, keine Shell, keine Weiterleitung (die Verbindung endet mit der Anmeldung).
const (
	sensorSSHBanner  = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3"
	sensorSSHTries   = 6
	sensorSSHTimeout = 60 * time.Second
)

var errSensorDenied = errors.New("permission denied")

func (s *Sensor) handleSSH(c *trapConn, signer ssh.Signer) {
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
		MaxAuthTries:  sensorSSHTries,
		ServerVersion: sensorSSHBanner,
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
	cfg.AddHostKey(signer)
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
