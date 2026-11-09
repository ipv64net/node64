package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Zeitlimits je Anfrage, wenn der Aufrufer keines vorgibt.
const (
	infoTimeout    = 15 * time.Second
	collectTimeout = 30 * time.Second // wie das hoechste Zeitlimit einer Abfragerunde der Node
	keysTimeout    = 30 * time.Second
	updateTimeout  = 10 * time.Minute
)

// AgentUser ist der Benutzername der Node beim Agent (der Agent prueft nur den Schluessel).
const AgentUser = "monitor64"

// AgentConfig beschreibt einen Agent.
type AgentConfig struct {
	Addr   string     // Host oder Host:Port (Standard-Port m64proto.DefaultPort)
	Signer ssh.Signer // privater Schluessel der Node (Pflicht)
	// Extra: weitere Schluessel der Node, die nach Signer angeboten werden (Cluster: alter Schluessel, bis der Agent
	// umgestellt ist)
	Extra []ssh.Signer
	// HostKey ist der gemerkte Fingerabdruck ("SHA256:..."); leer = ersten akzeptieren (TOFU) und ueber
	// OnHostKey bzw. HostKey() zurueckmelden. Abweichend = *HostKeyError (errors.Is ErrHostKeyChanged).
	HostKey string
	// OnHostKey wird beim ersten Kontakt mit dem uebernommenen Fingerabdruck aufgerufen (darf den Client nicht
	// aufrufen).
	OnHostKey   func(fingerprint string)
	DialTimeout time.Duration // 0 = 10 s
	IdleTimeout time.Duration // offene Verbindung ohne Anfrage schliessen (0 = 5 min)

	// Push-Betrieb (Hosts hinter NAT/VPS, push.go): der Agent verbindet sich selbst mit dem Lauscher Push und meldet
	// sich mit PushToken. Statt zu waehlen wartet eine Anfrage hoechstens PushWait (0 = 5 s) auf seine Verbindung,
	// sonst ErrNotConnected. Addr ist dann nur Anzeige (darf leer sein).
	Push      *PushListener
	PushToken string
	PushWait  time.Duration
}

// AgentClient spricht mit einem Monitor64-Agent. Sicher fuer gleichzeitige Nutzung.
type AgentClient struct {
	*conn
	cfg AgentConfig
}

// NewAgentClient legt den Client an; verbunden wird erst bei der ersten Anfrage.
func NewAgentClient(cfg AgentConfig) (*AgentClient, error) {
	if cfg.Signer == nil {
		return nil, errors.New("monitor64: node key missing")
	}
	addr := "push"
	if cfg.Push != nil {
		if !ValidPushToken(cfg.PushToken) {
			return nil, errors.New("monitor64: invalid push token")
		}
		if cfg.Addr != "" {
			addr = cfg.Addr
		}
	} else {
		if cfg.Addr == "" {
			return nil, errors.New("monitor64: address missing")
		}
		addr = HostPort(cfg.Addr, m64proto.DefaultPort)
	}
	c := &AgentClient{cfg: cfg, conn: newConn(connConfig{
		addr:        addr,
		user:        AgentUser,
		auth:        []ssh.AuthMethod{ssh.PublicKeys(append([]ssh.Signer{cfg.Signer}, cfg.Extra...)...)},
		hostKey:     cfg.HostKey,
		onHostKey:   cfg.OnHostKey,
		dialTimeout: cfg.DialTimeout,
		idleTimeout: cfg.IdleTimeout,
		push:        cfg.Push,
		pushToken:   cfg.PushToken,
		pushWait:    cfg.PushWait,
	})}
	if cfg.Push != nil {
		cfg.Push.register(cfg.PushToken, c.conn)
	}
	return c, nil
}

// Info fragt Version, System und Faehigkeiten ab.
func (c *AgentClient) Info(ctx context.Context) (*m64proto.Info, error) {
	ctx, cancel := withDefaultTimeout(ctx, infoTimeout)
	defer cancel()
	out, err := c.exec(ctx, m64proto.ReqInfo, nil, m64proto.MaxInfoBytes)
	if err != nil {
		return nil, err
	}
	var info m64proto.Info
	if err := json.Unmarshal(out, &info); err != nil {
		return nil, CleanError(fmt.Errorf("monitor64: info: invalid answer: %w", err))
	}
	return &info, nil
}

// Collect fragt Werte ab; ohne Abschnitte alle. Es gilt das Zeitlimit des Aufrufers (Abfragerunde der Node,
// 24-30 s; der Agent antwortet innerhalb von 20 s und liefert langsame Abschnitte aus seinem Zwischenspeicher).
// Laeuft es ab, ist der Fehler *TimeoutError (errors.Is ErrTimeout).
func (c *AgentClient) Collect(ctx context.Context, sections ...string) (*m64proto.Report, error) {
	cmd := m64proto.ReqCollect
	if len(sections) > 0 {
		for _, s := range sections {
			if !validSection(s) {
				return nil, fmt.Errorf("monitor64: invalid section %q", s)
			}
		}
		cmd += " " + strings.Join(sections, ",")
	}
	ctx, cancel := withDefaultTimeout(ctx, collectTimeout)
	defer cancel()
	out, err := c.exec(ctx, cmd, nil, m64proto.MaxReportBytes)
	if err != nil {
		return nil, err
	}
	var rep m64proto.Report
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, CleanError(fmt.Errorf("monitor64: collect: invalid answer: %w", err))
	}
	return &rep, nil
}

// Update schickt eine signierte neue Datei (Header + Inhalt aus r, genau h.Size Byte). Der Agent prueft Signatur,
// Version und Plattform, tauscht die Datei und startet neu; die Verbindung bricht danach ab.
func (c *AgentClient) Update(ctx context.Context, h m64proto.UpdateHeader, r io.Reader) (*m64proto.UpdateResult, error) {
	if h.Size <= 0 || h.Size > m64proto.MaxUpdateBytes {
		return nil, fmt.Errorf("monitor64: invalid update size %d", h.Size)
	}
	hdr, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	ctx, cancel := withDefaultTimeout(ctx, updateTimeout)
	defer cancel()
	in := io.MultiReader(bytes.NewReader(append(hdr, '\n')), io.LimitReader(r, h.Size))
	out, err := c.exec(ctx, m64proto.ReqUpdate, in, m64proto.MaxInfoBytes)
	var res m64proto.UpdateResult
	if out != nil && json.Unmarshal(out, &res) == nil && (res.OK || res.Error != "") {
		if !res.OK {
			return &res, fmt.Errorf("monitor64: update refused: %s", cleanRemote(res.Error))
		}
		// Der Agent beendet sich nach der Antwort: Verbindung verwerfen.
		c.drop()
		return &res, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("monitor64: update: invalid answer")
}

// SetKeys ersetzt die Schluesselliste des Agents (authorized_keys-Zeilen). Eine leere Liste lehnt schon der Client
// ab (sonst sperrt man sich aus).
func (c *AgentClient) SetKeys(ctx context.Context, keys []string) (*m64proto.KeysResult, error) {
	var buf bytes.Buffer
	n := 0
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\r\n") {
			return nil, errors.New("monitor64: key contains a line break")
		}
		if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k)); err != nil {
			return nil, fmt.Errorf("monitor64: invalid key: %w", err)
		}
		buf.WriteString(k)
		buf.WriteByte('\n')
		n++
	}
	if n == 0 {
		return nil, errors.New("monitor64: empty key list")
	}
	if buf.Len() > m64proto.MaxKeysBytes {
		return nil, errors.New("monitor64: key list too large")
	}
	ctx, cancel := withDefaultTimeout(ctx, keysTimeout)
	defer cancel()
	out, err := c.exec(ctx, m64proto.ReqKeys, &buf, m64proto.MaxInfoBytes)
	var res m64proto.KeysResult
	if out != nil && json.Unmarshal(out, &res) == nil && (res.OK || res.Error != "") {
		if !res.OK {
			return &res, fmt.Errorf("monitor64: keys refused: %s", cleanRemote(res.Error))
		}
		return &res, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, errors.New("monitor64: keys: invalid answer")
}

// drop schliesst die offene Verbindung (naechste Anfrage verbindet neu).
func (c *conn) drop() {
	c.mu.Lock()
	cl := c.client
	c.client = nil
	c.mu.Unlock()
	if cl != nil {
		_ = cl.Close()
	}
}

func validSection(s string) bool {
	if s == "" || len(s) > 16 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}
