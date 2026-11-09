package transport

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultForget: so lange ungenutzte Clients wirft der Pool weg (ihre Verbindung schliesst schon nach IdleTimeout).
const DefaultForget = 30 * time.Minute

// Pool haelt die Clients je Host-Schluessel (z. B. Zugangs-UID). Aendert sich die Konfiguration eines Zugangs
// (Adresse, Schluessel, gemerkter Hostschluessel ...), ersetzt er den Client. Die Aufraeum-Goroutine laeuft erst ab
// dem ersten Client und endet mit Close.
type Pool struct {
	forget time.Duration

	mu      sync.Mutex
	entries map[string]*poolEntry
	stop    chan struct{}
	closed  bool
}

type poolEntry struct {
	sig    string
	agent  *AgentClient
	ssh    *SSHClient
	used   time.Time
	client interface{ Close() error }
}

// NewPool legt einen Pool an; forget 0 = DefaultForget.
func NewPool(forget time.Duration) *Pool {
	if forget <= 0 {
		forget = DefaultForget
	}
	return &Pool{forget: forget, entries: map[string]*poolEntry{}}
}

// Agent liefert den Client fuer key (neu angelegt oder ersetzt, wenn sich cfg geaendert hat).
func (p *Pool) Agent(key string, cfg AgentConfig) (*AgentClient, error) {
	sig := "agent|" + cfg.Addr + "|" + signerSig(cfg.Signer) + "|" + fmt.Sprint(cfg.DialTimeout, cfg.IdleTimeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	if e := p.entries[key]; e != nil && e.agent != nil && e.sig == sig && sameHostKey(e.agent.conn, cfg.HostKey) {
		e.used = time.Now()
		return e.agent, nil
	}
	c, err := NewAgentClient(cfg)
	if err != nil {
		return nil, err
	}
	p.put(key, &poolEntry{sig: sig, agent: c, client: c})
	return c, nil
}

// SSH liefert den Client fuer key (neu angelegt oder ersetzt, wenn sich cfg geaendert hat).
func (p *Pool) SSH(key string, cfg SSHConfig) (*SSHClient, error) {
	pw := ""
	if cfg.Password != "" {
		h := sha256.Sum256([]byte(cfg.Password))
		pw = hex.EncodeToString(h[:])
	}
	sig := "ssh|" + cfg.Addr + "|" + cfg.User + "|" + signerSig(cfg.Signer) + "|" + pw + "|" +
		fmt.Sprint(cfg.DialTimeout, cfg.IdleTimeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil, ErrClosed
	}
	if e := p.entries[key]; e != nil && e.ssh != nil && e.sig == sig && sameHostKey(e.ssh.conn, cfg.HostKey) {
		e.used = time.Now()
		return e.ssh, nil
	}
	c, err := NewSSHClient(cfg)
	if err != nil {
		return nil, err
	}
	p.put(key, &poolEntry{sig: sig, ssh: c, client: c})
	return c, nil
}

// Remove schliesst und entfernt den Client fuer key.
func (p *Pool) Remove(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.entries[key]; e != nil {
		_ = e.client.Close()
		delete(p.entries, key)
	}
}

// Len liefert die Zahl der Clients.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// Close schliesst alle Clients und beendet die Aufraeum-Goroutine.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	for k, e := range p.entries {
		_ = e.client.Close()
		delete(p.entries, k)
	}
	if p.stop != nil {
		close(p.stop)
	}
}

// put ersetzt den Eintrag (unter p.mu).
func (p *Pool) put(key string, e *poolEntry) {
	if old := p.entries[key]; old != nil {
		_ = old.client.Close()
	}
	e.used = time.Now()
	p.entries[key] = e
	if p.stop == nil {
		p.stop = make(chan struct{})
		go p.janitor(p.stop)
	}
}

func (p *Pool) janitor(stop chan struct{}) {
	t := time.NewTicker(min(p.forget/2, time.Minute))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			p.mu.Lock()
			for k, e := range p.entries {
				if now.Sub(e.used) > p.forget {
					_ = e.client.Close()
					delete(p.entries, k)
				}
			}
			p.mu.Unlock()
		}
	}
}

// sameHostKey: gleich, wenn der Aufrufer den gemerkten (ggf. per TOFU gerade gelernten) Fingerabdruck uebergibt.
func sameHostKey(c *conn, want string) bool {
	return NormalizeFingerprint(want) == NormalizeFingerprint(c.cfg.hostKey) || NormalizeFingerprint(want) == c.HostKey()
}

func signerSig(s ssh.Signer) string {
	if s == nil {
		return ""
	}
	return Fingerprint(s.PublicKey())
}
