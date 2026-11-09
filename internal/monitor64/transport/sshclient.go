package transport

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

const (
	sshRunTimeout   = 60 * time.Second
	maxScriptBytes  = 256 << 10
	defaultSSHPort  = 22
	maxScriptArgCnt = 8
)

// ScriptArgs sind die einzigen Argumente, die an das feste Skript gehen ("sh -s -- <args>"). Werte von Hosts oder
// Benutzern kommen nie in den Befehl (Plan, Abschnitt "Sicherheit").
var ScriptArgs = map[string]bool{
	"smart":   true, // SMART lesen (sudo -n smartctl)
	"updates": true, // Paket-Updates pruefen (stuendlich)
}

// SSHConfig beschreibt einen Host ohne Agent.
type SSHConfig struct {
	Addr     string     // Host oder Host:Port (Standard 22)
	User     string     // Pflicht, empfohlen "monitor64"
	Signer   ssh.Signer // Schluessel der Node (Standard)
	Password string     // nur als Ausnahme fuer Systeme ohne Schluessel-Anmeldung
	// HostKey, OnHostKey: TOFU wie bei AgentConfig.
	HostKey     string
	OnHostKey   func(fingerprint string)
	DialTimeout time.Duration
	IdleTimeout time.Duration
}

// SSHClient fuehrt das feste Abfrageskript per SSH aus. Sicher fuer gleichzeitige Nutzung.
type SSHClient struct {
	*conn
	cfg SSHConfig
}

// NewSSHClient legt den Client an; verbunden wird erst bei der ersten Anfrage.
func NewSSHClient(cfg SSHConfig) (*SSHClient, error) {
	if cfg.Addr == "" || cfg.User == "" {
		return nil, errors.New("monitor64: address or user missing")
	}
	var auth []ssh.AuthMethod
	if cfg.Signer != nil {
		auth = append(auth, ssh.PublicKeys(cfg.Signer))
	}
	if cfg.Password != "" {
		pw := cfg.Password
		auth = append(auth, ssh.Password(pw), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, echos []bool) ([]string, error) {
				// Nur die uebliche Passwortabfrage beantworten (eine Frage ohne Echo).
				if len(questions) == 0 {
					return nil, nil
				}
				if len(questions) != 1 || echos[0] {
					return nil, errors.New("unexpected keyboard-interactive question")
				}
				return []string{pw}, nil
			}))
	}
	if len(auth) == 0 {
		return nil, errors.New("monitor64: neither key nor password")
	}
	return &SSHClient{cfg: cfg, conn: newConn(connConfig{multiKey: true,
		addr:        HostPort(cfg.Addr, defaultSSHPort),
		user:        cfg.User,
		auth:        auth,
		hostKey:     cfg.HostKey,
		onHostKey:   cfg.OnHostKey,
		dialTimeout: cfg.DialTimeout,
		idleTimeout: cfg.IdleTimeout,
	})}, nil
}

// Run fuehrt script per "sh -s -- <args>" aus (Skript ueber stdin). args nur aus ScriptArgs. Die Ausgabe ist auf
// m64proto.MaxReportBytes begrenzt; bei *RemoteError (Exit-Status != 0) wird sie trotzdem geliefert.
func (c *SSHClient) Run(ctx context.Context, script string, args ...string) ([]byte, error) {
	if len(script) > maxScriptBytes {
		return nil, errors.New("monitor64: script too large")
	}
	if len(args) > maxScriptArgCnt {
		return nil, errors.New("monitor64: too many script arguments")
	}
	for _, a := range args {
		if !ScriptArgs[a] {
			return nil, fmt.Errorf("monitor64: script argument %q not allowed", a)
		}
	}
	cmd := "sh -s"
	if len(args) > 0 {
		cmd += " -- " + strings.Join(args, " ")
	}
	ctx, cancel := withDefaultTimeout(ctx, sshRunTimeout)
	defer cancel()
	return c.exec(ctx, cmd, strings.NewReader(script), m64proto.MaxReportBytes)
}
