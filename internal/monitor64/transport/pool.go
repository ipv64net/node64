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
// Als Nutzung zaehlt jede Anfrage ueber den Client, nicht nur das Holen aus dem Pool.
const DefaultForget = 30 * time.Minute

// Pool haelt die Clients je Host-Schluessel (z. B. Zugangs-UID). Aendert sich die Konfiguration eines Zugangs
// (Adresse, Schluessel, gemerkter Hostschluessel ...), ersetzt er den Client. Die Aufraeum-Goroutine laeuft erst ab
// dem ersten Client und endet mit Close. Unter p.mu wird nie auf eine Verbindung gewartet (Schliessen alter Clients
// geschieht danach), damit ein haengender Host andere Hosts nicht blockiert.
type Pool struct {
	forget time.Duration

	mu      sync.Mutex
	entries map[string]*poolEntry
	stop    chan struct{}
	closed  bool
}

type poolEntry struct {
	sig     string
	agent   *AgentClient
	ssh     *SSHClient
	conn    *conn
	used    time.Time   // zuletzt aus dem Pool geholt
	release *time.Timer // Release: Entfernen nach der Karenz, wenn ihn niemand wieder holt
}

// push: Client im Push-Betrieb (seine Anmeldung beim Lauscher haelt die Verbindungen des Agents).
func (e *poolEntry) push() bool { return e.agent != nil && e.agent.cfg.Push != nil }

// keep: der Eintrag wird wieder benutzt (eine laufende Karenz endet).
func (e *poolEntry) keep() {
	e.used = time.Now()
	if e.release != nil {
		e.release.Stop()
		e.release = nil
	}
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
	sig := "agent|" + cfg.Addr + "|" + signerSig(cfg.Signer) + extraSig(cfg.Extra) + "|" + fmt.Sprint(cfg.DialTimeout, cfg.IdleTimeout)
	if cfg.Push != nil {
		sig += fmt.Sprintf("|push|%p|%s|%s", cfg.Push, cfg.PushToken, cfg.PushWait)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	if e := p.entries[key]; e != nil && e.agent != nil && e.sig == sig && sameHostKey(e.conn, cfg.HostKey) {
		e.keep()
		p.mu.Unlock()
		return e.agent, nil
	}
	c, err := NewAgentClient(cfg) // verbindet noch nicht
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	old := p.put(key, &poolEntry{sig: sig, agent: c, conn: c.conn})
	p.mu.Unlock()
	closeConn(old)
	return c, nil
}

// SSH liefert den Client fuer key (neu angelegt oder ersetzt, wenn sich cfg geaendert hat).
func (p *Pool) SSH(key string, cfg SSHConfig) (*SSHClient, error) {
	pw := ""
	if cfg.Password != "" {
		h := sha256.Sum256([]byte(cfg.Password))
		pw = hex.EncodeToString(h[:])
	}
	sig := "ssh|" + cfg.Addr + "|" + cfg.User + "|" + signerSig(cfg.Signer) + extraSig(cfg.Extra) + "|" + pw + "|" +
		fmt.Sprint(cfg.DialTimeout, cfg.IdleTimeout)
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	if e := p.entries[key]; e != nil && e.ssh != nil && e.sig == sig && sameHostKey(e.conn, cfg.HostKey) {
		e.keep()
		p.mu.Unlock()
		return e.ssh, nil
	}
	c, err := NewSSHClient(cfg) // verbindet noch nicht
	if err != nil {
		p.mu.Unlock()
		return nil, err
	}
	old := p.put(key, &poolEntry{sig: sig, ssh: c, conn: c.conn})
	p.mu.Unlock()
	closeConn(old)
	return c, nil
}

// Remove schliesst und entfernt den Client fuer key (z. B. Zugang geaendert/entfernt, Hostschluessel verworfen).
func (p *Pool) Remove(key string) {
	p.mu.Lock()
	e := p.entries[key]
	delete(p.entries, key)
	if e != nil {
		e.keep()
	}
	p.mu.Unlock()
	if e != nil {
		closeConn(e.conn)
	}
}

// Release gibt den Client fuer key frei und entfernt ihn erst nach grace, wenn ihn bis dahin niemand mit gleicher
// Konfiguration wieder holt (Push: ReloadHost baut den Sammler neu, die offene Verbindung des Agents und die
// Anmeldung seines Tokens beim Lauscher bleiben dann bestehen). Eine geaenderte Konfiguration ersetzt ihn wie sonst.
func (p *Pool) Release(key string, grace time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e := p.entries[key]
	if e == nil || p.closed {
		return
	}
	if e.release != nil {
		e.release.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(grace, func() {
		p.mu.Lock()
		gone := p.entries[key] == e && e.release == t
		if gone {
			delete(p.entries, key)
			e.release = nil
		}
		p.mu.Unlock()
		if gone {
			closeConn(e.conn)
		}
	})
	e.release = t
}

// Existing liefert den vorhandenen Agent-Client fuer key (nil ohne; legt keinen an und zaehlt nicht als Nutzung).
func (p *Pool) Existing(key string) *AgentClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e := p.entries[key]; e != nil {
		return e.agent
	}
	return nil
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
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	var old []*conn
	for k, e := range p.entries {
		e.keep()
		old = append(old, e.conn)
		delete(p.entries, k)
	}
	if p.stop != nil {
		close(p.stop)
	}
	p.mu.Unlock()
	for _, c := range old {
		closeConn(c)
	}
}

// put ersetzt den Eintrag (unter p.mu) und liefert die Verbindung des alten (vom Aufrufer nach p.mu zu schliessen).
func (p *Pool) put(key string, e *poolEntry) *conn {
	var old *conn
	if o := p.entries[key]; o != nil {
		o.keep() // Karenz des alten endet: er wird ohnehin geschlossen
		old = o.conn
	}
	e.used = time.Now()
	p.entries[key] = e
	if p.stop == nil {
		p.stop = make(chan struct{})
		go p.janitor(p.stop)
	}
	return old
}

func (p *Pool) janitor(stop chan struct{}) {
	t := time.NewTicker(min(p.forget/2, time.Minute))
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			p.sweep(now)
		}
	}
}

// sweep wirft Clients weg, die laenger als forget weder geholt noch benutzt wurden (laufende Anfragen zaehlen
// als Nutzung). Push-Clients bleiben (pausierter Host, im Cluster nicht zustaendig): mit dem Client ginge die
// Anmeldung des Tokens, und der Agent wuerde abgewiesen und sperrte sich in seine Wartezeit; sie gehen mit Remove
// bzw. Release, wenn der Zugang wegfaellt.
func (p *Pool) sweep(now time.Time) {
	p.mu.Lock()
	var old []*conn
	for k, e := range p.entries {
		if e.push() {
			continue
		}
		active, last := e.conn.usage()
		if active > 0 || now.Sub(e.used) <= p.forget || now.Sub(last) <= p.forget {
			continue
		}
		old = append(old, e.conn)
		delete(p.entries, k)
	}
	p.mu.Unlock()
	for _, c := range old {
		closeConn(c)
	}
}

func closeConn(c *conn) {
	if c != nil {
		_ = c.Close()
	}
}

// sameHostKey: gleich, wenn der Aufrufer den gemerkten (ggf. per TOFU gerade gelernten) Fingerabdruck des Clients
// uebergibt. Ein leerer Fingerabdruck (Zugang neu angelegt oder "neuen uebernehmen") passt nur zu einem Client,
// der noch keinen gelernt hat - sonst entsteht ein neuer Client, der beim naechsten Kontakt neu lernt.
func sameHostKey(c *conn, want string) bool {
	return NormalizeFingerprint(want) == c.HostKey()
}

// extraSig: weitere Schluessel (Reihenfolge zaehlt), leer ohne.
func extraSig(l []ssh.Signer) string {
	out := ""
	for _, s := range l {
		out += "+" + signerSig(s)
	}
	return out
}

func signerSig(s ssh.Signer) string {
	if s == nil {
		return ""
	}
	return Fingerprint(s.PublicKey())
}
