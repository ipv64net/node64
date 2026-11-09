package m64agent

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Grenzen der Schluesselliste.
const (
	maxKeys        = 100
	maxKeyLineLen  = 16 << 10
	minRSABits     = 2048
	keysRecheckGap = time.Second // Datei hoechstens einmal je Sekunde auf Aenderung pruefen
)

// allowedKeyTypes sind die Schluesselarten, die der Agent annimmt (kein DSA, keine Zertifikate).
var allowedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoRSA:        true, // Signatur nur mit rsa-sha2-256/512 (pubKeyAuthAlgos)
}

// pubKeyAuthAlgos: Signaturverfahren fuer die Anmeldung (ohne ssh-rsa/SHA-1 und DSA).
var pubKeyAuthAlgos = []string{
	ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoSKECDSA256,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512,
}

// ignoredKeyOptions sind authorized_keys-Optionen, die beim Agent ohnehin gelten (keine Shell, keine Weiterleitung).
var ignoredKeyOptions = map[string]bool{
	"restrict": true, "no-port-forwarding": true, "no-agent-forwarding": true, "no-x11-forwarding": true,
	"no-pty": true, "no-user-rc": true,
}

// keyEntry ist eine Zeile der Schluesselliste.
type keyEntry struct {
	key     ssh.PublicKey
	wire    []byte
	comment string
	from    []string // Muster aus from="..." (leer = jede Adresse)
}

// ParseKeys prueft eine Schluesselliste im authorized_keys-Format streng: jede Zeile ausser Leerzeilen und
// Kommentaren muss ein erlaubter Schluessel sein. Liefert die Anzahl der Schluessel.
func ParseKeys(data []byte) (int, error) {
	keys, err := parseKeys(data, true)
	return len(keys), err
}

// parseKeys liest eine Schluesselliste. strict=false ueberspringt fehlerhafte Zeilen (Datei auf der Platte: eine
// kaputte Zeile darf nicht alle Nodes aussperren), strict=true lehnt die ganze Liste ab (Anfrage "keys").
func parseKeys(data []byte, strict bool) ([]keyEntry, error) {
	var out []keyEntry
	var skipped []string
	for i, raw := range bytes.Split(data, []byte("\n")) {
		line := bytes.TrimSpace(raw)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		e, err := parseKeyLine(line)
		if err != nil {
			err = fmt.Errorf("line %d: %w", i+1, err)
			if strict {
				return nil, err
			}
			skipped = append(skipped, err.Error())
			continue
		}
		if len(out) >= maxKeys {
			if strict {
				return nil, fmt.Errorf("more than %d keys", maxKeys)
			}
			skipped = append(skipped, fmt.Sprintf("line %d: more than %d keys", i+1, maxKeys))
			break
		}
		out = append(out, e)
	}
	if len(skipped) > 0 {
		return out, errors.New(strings.Join(skipped, "; "))
	}
	return out, nil
}

func parseKeyLine(line []byte) (keyEntry, error) {
	if len(line) > maxKeyLineLen {
		return keyEntry{}, errors.New("line too long")
	}
	pub, comment, opts, rest, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		return keyEntry{}, errors.New("not a public key")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return keyEntry{}, errors.New("more than one key in a line")
	}
	if !allowedKeyTypes[pub.Type()] {
		return keyEntry{}, fmt.Errorf("key type %s not allowed", pub.Type())
	}
	if pub.Type() == ssh.KeyAlgoRSA {
		ck, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return keyEntry{}, errors.New("invalid RSA key")
		}
		rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rk.N.BitLen() < minRSABits {
			return keyEntry{}, fmt.Errorf("RSA key shorter than %d bits", minRSABits)
		}
	}
	e := keyEntry{key: pub, wire: pub.Marshal(), comment: comment}
	for _, o := range opts {
		name, val, hasVal := strings.Cut(o, "=")
		name = strings.ToLower(name)
		switch {
		case name == "from" && hasVal:
			pats := strings.Split(strings.Trim(val, `"`), ",")
			for _, p := range pats {
				if p = strings.TrimSpace(p); p != "" {
					e.from = append(e.from, p)
				}
			}
			if len(e.from) == 0 {
				return keyEntry{}, errors.New("empty from= option")
			}
		case ignoredKeyOptions[name] && !hasVal:
		default:
			return keyEntry{}, fmt.Errorf("option %q not supported", name)
		}
	}
	return e, nil
}

// fromAllows prueft eine Adresse gegen die Muster aus from="..." wie OpenSSH: mindestens ein positives Muster passt
// und kein verneintes ("!"). Muster: IP, CIDR oder IP mit * und ?; Hostnamen werden nicht aufgeloest (passen nie).
func fromAllows(pats []string, ip netip.Addr) bool {
	if len(pats) == 0 {
		return true
	}
	ip = ip.Unmap()
	s := ip.String()
	allowed := false
	for _, p := range pats {
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		var hit bool
		if strings.Contains(p, "/") {
			if pfx, err := netip.ParsePrefix(p); err == nil {
				hit = pfx.Contains(ip)
			}
		} else if a, err := netip.ParseAddr(p); err == nil {
			hit = a.Unmap() == ip
		} else if !strings.ContainsAny(p, "[\\") {
			hit, _ = path.Match(p, s)
		}
		if hit {
			if neg {
				return false
			}
			allowed = true
		}
	}
	return allowed
}

// keyStore haelt die Schluesselliste aus der Datei und liest sie bei Aenderung neu.
type keyStore struct {
	path string
	log  func(msg string, args ...any)

	mu      sync.Mutex
	checked time.Time
	modTime time.Time
	size    int64
	keys    []keyEntry
	lastErr string
}

// lookup sucht den Schluessel; liefert den Eintrag oder nil.
func (s *keyStore) lookup(pub ssh.PublicKey) *keyEntry {
	wire := pub.Marshal()
	for _, e := range s.current() {
		if bytes.Equal(e.wire, wire) {
			return &e
		}
	}
	return nil
}

func (s *keyStore) current() []keyEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.checked) < keysRecheckGap && !s.checked.IsZero() {
		return s.keys
	}
	s.checked = now
	fi, err := os.Stat(s.path)
	if err != nil {
		s.keys, s.modTime, s.size = nil, time.Time{}, 0
		s.report("keys file not readable - every login is refused", err)
		return nil
	}
	if fi.ModTime().Equal(s.modTime) && fi.Size() == s.size && s.keys != nil {
		return s.keys
	}
	if fi.Size() > maxKeysFileBytes {
		s.keys = nil
		s.report("keys file too large - every login is refused", fmt.Errorf("%d bytes", fi.Size()))
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		s.keys = nil
		s.report("keys file not readable - every login is refused", err)
		return nil
	}
	keys, perr := parseKeys(data, false)
	s.keys, s.modTime, s.size = keys, fi.ModTime(), fi.Size()
	if s.keys == nil {
		s.keys = []keyEntry{}
	}
	if perr != nil {
		s.report("keys file: lines ignored", perr)
	} else {
		s.lastErr = ""
	}
	return s.keys
}

// invalidate erzwingt das Neulesen (nach "keys").
func (s *keyStore) invalidate() {
	s.mu.Lock()
	s.checked = time.Time{}
	s.modTime = time.Time{}
	s.mu.Unlock()
}

func (s *keyStore) report(msg string, err error) {
	if e := msg + ": " + err.Error(); e != s.lastErr {
		s.lastErr = e
		if s.log != nil {
			s.log("monitor64-agent: "+msg, "file", s.path, "err", err)
		}
	}
}

// Fehlversuche je IP bremsen.
const (
	failFree     = 5                // so viele fehlgeschlagene Anmeldungen ohne Sperre
	failBlockMin = time.Minute      // erste Sperre, verdoppelt sich je weiterem Fehlversuch
	failBlockMax = 30 * time.Minute //
	failForget   = time.Hour        // Zaehler verfaellt nach so langer Ruhe
	failMaxIPs   = 4096             // hoechstens so viele Adressen merken
)

type failState struct {
	fails int
	last  time.Time
	until time.Time
}

type limiter struct {
	mu sync.Mutex
	m  map[string]*failState
}

// limiterKey fasst IPv6 je /64 zusammen (sonst wechselt ein Angreifer einfach die Adresse).
func limiterKey(addr net.Addr) string {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip := ap.Addr().Unmap()
	if ip.Is6() {
		p, _ := ip.Prefix(64)
		return p.String()
	}
	return ip.String()
}

func (l *limiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.m[key]
	return st != nil && now.Before(st.until)
}

func (l *limiter) fail(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]*failState{}
	}
	st := l.m[key]
	if st == nil {
		if len(l.m) >= failMaxIPs {
			for k, v := range l.m {
				if now.Sub(v.last) > failForget && !now.Before(v.until) {
					delete(l.m, k)
				}
			}
			if len(l.m) >= failMaxIPs {
				return
			}
		}
		st = &failState{}
		l.m[key] = st
	}
	if now.Sub(st.last) > failForget {
		st.fails = 0
	}
	st.fails++
	st.last = now
	if st.fails >= failFree {
		d := failBlockMin << min(st.fails-failFree, 10)
		st.until = now.Add(min(d, failBlockMax))
	}
}

func (l *limiter) ok(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
