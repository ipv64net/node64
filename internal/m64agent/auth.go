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
			// Wie OpenSSH: ein ungueltiges Muster (auch verneint) macht die ganze Zeile ungueltig; mehrere from=
			// in einer Zeile sind nicht eindeutig und werden ebenfalls abgelehnt.
			if e.from != nil {
				return keyEntry{}, errors.New("more than one from= option")
			}
			e.from = []string{}
			for _, p := range strings.Split(strings.Trim(val, `"`), ",") {
				p = strings.TrimSpace(p)
				if err := checkFromPattern(p); err != nil {
					return keyEntry{}, fmt.Errorf("from=: %w", err)
				}
				e.from = append(e.from, p)
			}
		case ignoredKeyOptions[name] && !hasVal:
		default:
			return keyEntry{}, fmt.Errorf("option %q not supported", name)
		}
	}
	return e, nil
}

// checkFromPattern prueft ein Muster aus from="...": IP (auch mit Zone), CIDR ohne gesetzte Hostbits oder IP mit
// * und ?, optional mit "!" verneint. Hostnamen werden nicht aufgeloest und deshalb abgelehnt (ein verneinter
// Hostname wuerde sonst still nichts sperren).
func checkFromPattern(p string) error {
	q := strings.TrimPrefix(p, "!")
	switch {
	case q == "":
		return errors.New("empty pattern")
	case strings.Contains(q, "/"):
		pfx, err := netip.ParsePrefix(q)
		if err != nil || pfx != pfx.Masked() {
			return fmt.Errorf("invalid network %q", p)
		}
		return nil
	case strings.ContainsAny(q, "*?"):
		if strings.Trim(q, "0123456789abcdefABCDEF.:*?") != "" {
			return fmt.Errorf("pattern %q not supported (IP, CIDR or IP with * and ?)", p)
		}
		return nil
	}
	if _, err := netip.ParseAddr(q); err != nil {
		return fmt.Errorf("pattern %q not supported (IP, CIDR or IP with * and ?)", p)
	}
	return nil
}

// fromAllows prueft eine Adresse gegen die Muster aus from="..." wie OpenSSH: mindestens ein positives Muster passt
// und kein verneintes ("!"). Die Zone einer IPv6-Adresse zaehlt nicht (sonst passte "fe80::/10" nicht auf
// "fe80::1%eth0"). Ein ungueltiges Muster (parseKeyLine laesst keins durch) verweigert immer.
func fromAllows(pats []string, ip netip.Addr) bool {
	if len(pats) == 0 {
		return true
	}
	ip = ip.Unmap().WithZone("")
	s := ip.String()
	allowed := false
	for _, p := range pats {
		if checkFromPattern(p) != nil {
			return false
		}
		neg := strings.HasPrefix(p, "!")
		p = strings.TrimPrefix(p, "!")
		var hit bool
		if strings.Contains(p, "/") {
			pfx, _ := netip.ParsePrefix(p)
			hit = pfx.Contains(ip)
		} else if a, err := netip.ParseAddr(p); err == nil {
			hit = a.Unmap().WithZone("") == ip
		} else {
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

// allowed prueft Schluessel (Wire-Format) und Adresse gegen die aktuelle Liste (Datei, from=). Liefert den Eintrag
// oder einen Fehler.
func (s *keyStore) allowed(wire []byte, remote net.Addr) (*keyEntry, error) {
	var e *keyEntry
	for _, k := range s.current() {
		if bytes.Equal(k.wire, wire) {
			e = &k
			break
		}
	}
	if e == nil {
		return nil, errors.New("unknown key")
	}
	if len(e.from) > 0 {
		ap, err := netip.ParseAddrPort(remote.String())
		if err != nil || !fromAllows(e.from, ap.Addr()) {
			return nil, errors.New("address not allowed for this key")
		}
	}
	return e, nil
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

// Fehlversuche je IP bremsen. Als Fehlversuch zaehlt jede Verbindung, die nicht zur Anmeldung fuehrt (falscher
// Schluessel, Zeitlimit, abgebrochener Handshake, zu viele gleichzeitige Verbindungen ohne Anmeldung).
const (
	failFree     = 5                // so viele Fehlversuche ohne Sperre
	failBlockMin = time.Minute      // erste Sperre, verdoppelt sich je weiterem Fehlversuch
	failBlockMax = 30 * time.Minute //
	failForget   = time.Hour        // Zaehler verfaellt nach so langer Ruhe
	failMaxIPs   = 4096             // hoechstens so viele Adressen merken (volle Liste: aelteste verdraengen)
	goodForget   = 24 * time.Hour   // Adresse mit erfolgreicher Anmeldung gilt so lange als bekannt
	goodMaxIPs   = 1024             // hoechstens so viele bekannte Adressen merken
)

// Verbindungen ohne Anmeldung (Handshake laeuft) begrenzen, damit sie die Plaetze angemeldeter Nodes nicht belegen.
const (
	preAuthMax   = 8 // insgesamt
	preAuthPerIP = 3 // je Adresse (IPv6 je /64)
)

type failState struct {
	fails int
	last  time.Time
	until time.Time
}

type limiter struct {
	mu   sync.Mutex
	m    map[string]*failState
	good map[string]time.Time // Adressen mit erfolgreicher Anmeldung (Zeitpunkt)
}

// limiterKey fasst IPv6 je /64 zusammen (sonst wechselt ein Angreifer einfach die Adresse).
func limiterKey(addr net.Addr) string {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return addr.String()
	}
	ip := ap.Addr().Unmap().WithZone("")
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

// known meldet, ob sich von der Adresse in den letzten 24 Std. eine Node angemeldet hat. Bekannte Adressen werden
// nicht gesperrt und zaehlen nicht gegen die Obergrenze fuer Verbindungen ohne Anmeldung (Angreifer duerfen
// angemeldete Nodes nicht aussperren).
func (l *limiter) known(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.good[key]
	return ok && now.Sub(t) < goodForget
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
			l.evict(now)
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

// evict macht Platz in der vollen Liste: erst verfallene Eintraege, sonst der aelteste nicht gesperrte, notfalls der
// aelteste ueberhaupt (lieber eine alte Sperre vergessen als neue Fehlversuche nicht mehr zaehlen).
func (l *limiter) evict(now time.Time) {
	var oldest, oldestFree string
	var tOld, tFree time.Time
	for k, v := range l.m {
		if now.Sub(v.last) > failForget && !now.Before(v.until) {
			delete(l.m, k)
			continue
		}
		if oldest == "" || v.last.Before(tOld) {
			oldest, tOld = k, v.last
		}
		if !now.Before(v.until) && (oldestFree == "" || v.last.Before(tFree)) {
			oldestFree, tFree = k, v.last
		}
	}
	if len(l.m) < failMaxIPs {
		return
	}
	if oldestFree != "" {
		delete(l.m, oldestFree)
	} else {
		delete(l.m, oldest)
	}
}

// ok vergisst die Fehlversuche und merkt die Adresse als bekannt.
func (l *limiter) ok(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, key)
	if l.good == nil {
		l.good = map[string]time.Time{}
	}
	if _, ok := l.good[key]; !ok && len(l.good) >= goodMaxIPs {
		var oldest string
		var t time.Time
		for k, v := range l.good {
			if now.Sub(v) >= goodForget {
				delete(l.good, k)
				continue
			}
			if oldest == "" || v.Before(t) {
				oldest, t = k, v
			}
		}
		if len(l.good) >= goodMaxIPs {
			delete(l.good, oldest)
		}
	}
	l.good[key] = now
}

// preAuthGate zaehlt Verbindungen, deren Handshake noch laeuft.
type preAuthGate struct {
	mu    sync.Mutex
	total int
	per   map[string]int
}

// acquire belegt einen Platz; known = Adresse einer bereits angemeldeten Node (nur die Grenze je Adresse gilt).
func (g *preAuthGate) acquire(key string, known bool) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.per == nil {
		g.per = map[string]int{}
	}
	if g.per[key] >= preAuthPerIP || (!known && g.total >= preAuthMax) {
		return false
	}
	g.per[key]++
	g.total++
	return true
}

func (g *preAuthGate) release(key string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.per[key] <= 1 {
		delete(g.per, key)
	} else {
		g.per[key]--
	}
	g.total--
}
