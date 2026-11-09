package m64agent

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path"
	"strconv"
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

// checkFromPattern prueft ein Muster aus from="...", optional mit "!" verneint:
//   - IP; eine Zone (fe80::1%eth0) nur bei Link-Local-Adressen, sie muss dann beim Abgleich stimmen,
//   - CIDR ohne gesetzte Hostbits; IPv4-gemappte Netze (::ffff:a.b.c.d/n) ab /96, sie gelten als IPv4-Netz,
//   - IPv4 mit * und ? (IPv6 mit Jokern nicht - die Kurzschreibweise passt nicht zuverlaessig, dafuer CIDR),
//     "*" allein = jede Adresse.
//
// Hostnamen werden nicht aufgeloest und deshalb abgelehnt. Alles, was hier durchgeht, bedeutet in fromAllows genau
// das (ein verneintes Muster, das still nichts trifft, wuerde sonst nichts sperren).
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
		if pfx.Addr().Is4In6() && pfx.Bits() < 96 {
			return fmt.Errorf("IPv4-mapped network %q shorter than /96 not supported", p)
		}
		return nil
	case strings.ContainsAny(q, "*?"):
		if strings.Trim(q, "0123456789.*?") != "" {
			return fmt.Errorf("pattern %q not supported (wildcards only for IPv4 - use CIDR for IPv6)", p)
		}
		return nil
	}
	a, err := netip.ParseAddr(q)
	if err != nil {
		return fmt.Errorf("pattern %q not supported (IP, CIDR or IPv4 with * and ?)", p)
	}
	if a.Zone() != "" && !a.IsLinkLocalUnicast() {
		return fmt.Errorf("pattern %q: zone only for link-local addresses", p)
	}
	return nil
}

// fromAllows prueft eine Adresse gegen die Muster aus from="..." wie OpenSSH: mindestens ein positives Muster passt
// und kein verneintes ("!"). IPv4-gemappte Adressen und Netze zaehlen als IPv4. Netze und Muster ohne Zone passen
// auf jede Zone (sonst passte "!fe80::/10" nicht auf "fe80::1%eth0"); eine Zone im Muster muss stimmen. Ein
// ungueltiges Muster (parseKeyLine laesst keins durch) verweigert immer.
func fromAllows(pats []string, ip netip.Addr) bool {
	if len(pats) == 0 {
		return true
	}
	ip = ip.Unmap()
	plain := ip.WithZone("")
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
			if pfx.Addr().Is4In6() {
				pfx = netip.PrefixFrom(pfx.Addr().Unmap(), pfx.Bits()-96)
			}
			hit = pfx.Contains(plain)
		} else if a, err := netip.ParseAddr(p); err == nil {
			hit = a.Unmap().WithZone("") == plain && (a.Zone() == "" || zoneEqual(a.Zone(), ip.Zone()))
		} else if strings.Trim(p, "*") == "" {
			hit = true
		} else if plain.Is4() {
			hit, _ = path.Match(p, plain.String())
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

// zoneEqual vergleicht zwei Zonen; Name und Nummer derselben Schnittstelle sind gleich (Go meldet den Namen, wenn
// er bekannt ist, sonst die Nummer).
func zoneEqual(a, b string) bool {
	if a == "" || b == "" {
		return a == b
	}
	if a == b {
		return true
	}
	ia, ea := strconv.Atoi(a)
	ib, eb := strconv.Atoi(b)
	switch {
	case ea == nil && eb == nil:
		return ia == ib
	case ea == nil:
		ifi, err := net.InterfaceByName(b)
		return err == nil && ifi.Index == ia
	case eb == nil:
		ifi, err := net.InterfaceByName(a)
		return err == nil && ifi.Index == ib
	}
	return false
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

// Fehlversuche je Adresse bremsen. Als Fehlversuch zaehlt jede Verbindung, die einen Platz bekommen hat und nicht
// zur Anmeldung fuehrt (falscher Schluessel, Zeitlimit, abgebrochener Handshake). Abgewiesene Verbindungen (alle
// Plaetze belegt) zaehlen nicht: volle Plaetze kann ein Angreifer verursachen, er wuerde sonst neue Nodes sperren.
// Gezaehlt wird je exakter Adresse und je Netz (IPv6 /64): ein Angreifer im selben /64 wie eine Node wird gesperrt,
// auch wenn er die Adresse wechselt; die Node mit ihrer bekannten Adresse nicht.
const (
	failFree     = 5                // so viele Fehlversuche ohne Sperre
	failBlockMin = time.Minute      // erste Sperre, verdoppelt sich je weiterem Fehlversuch
	failBlockMax = 30 * time.Minute //
	failForget   = time.Hour        // Zaehler verfaellt nach so langer Ruhe
	failMaxIPs   = 4096             // hoechstens so viele Eintraege merken (volle Liste: siehe evict)
	goodForget   = 24 * time.Hour   // Adresse mit erfolgreicher Anmeldung gilt so lange als bekannt
	goodMaxIPs   = 1024             // hoechstens so viele bekannte Adressen merken
)

// Verbindungen ohne Anmeldung (Handshake laeuft) begrenzen, damit sie die Plaetze angemeldeter Nodes nicht belegen.
// Bekannte Adressen (dort hat sich schon eine Node angemeldet) haben einen eigenen Topf: ein Nachbar hinter
// derselben NAT-Adresse kann ihn zwar fuellen, aber ein Platz, dessen Handshake nach preAuthEvictAge noch laeuft,
// wird fuer eine neue Verbindung derselben Adresse geraeumt (eine Node schafft den Handshake schneller).
const (
	preAuthMax      = 8               // insgesamt (unbekannte Adressen)
	preAuthPerNet   = 3               // je Netz (IPv6 /64, IPv4 je Adresse)
	preAuthPerGroup = 4               // je IPv6-/48 (viele /64 eines Angreifers belegen nicht alle Plaetze)
	preAuthPerKnown = 8               // je bekannter Adresse (zaehlt nicht gegen preAuthMax)
	preAuthKnownMax = 32              // alle bekannten Adressen zusammen
	preAuthEvictAge = 2 * time.Second // so alt muss ein Platz einer bekannten Adresse sein, um geraeumt zu werden
)

// peer ist die Gegenstelle in drei Stufen: exakte Adresse (ohne Zone), Netz (IPv6 /64, IPv4 = Adresse) und Gruppe
// (IPv6 /48, IPv4 leer).
type peer struct {
	ip, net, grp string
}

func peerOf(addr net.Addr) peer {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		s := addr.String()
		return peer{ip: s, net: s}
	}
	ip := ap.Addr().Unmap().WithZone("")
	p := peer{ip: ip.String(), net: ip.String()}
	if ip.Is6() {
		n, _ := ip.Prefix(64)
		g, _ := ip.Prefix(48)
		p.net, p.grp = n.String(), g.String()
	}
	return p
}

type failState struct {
	fails int
	last  time.Time
	until time.Time
}

type limiter struct {
	mu   sync.Mutex
	m    map[string]*failState // exakte Adressen und IPv6-Netze (/64)
	good map[string]time.Time  // exakte Adressen mit erfolgreicher Anmeldung (Zeitpunkt)
}

func (l *limiter) blocked(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.m[key]
	return st != nil && now.Before(st.until)
}

// known meldet, ob sich von der exakten Adresse in den letzten 24 Std. eine Node angemeldet hat. Bekannte Adressen
// werden nicht gesperrt und haben einen eigenen Topf fuer Verbindungen ohne Anmeldung (Angreifer duerfen angemeldete
// Nodes nicht aussperren).
func (l *limiter) known(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	t, ok := l.good[ip]
	return ok && now.Sub(t) < goodForget
}

// refused meldet, ob eine Verbindung wegen Fehlversuchen abgewiesen wird: nie bei bekannter Adresse, sonst wenn die
// exakte Adresse oder ihr Netz gesperrt ist.
func (l *limiter) refused(p peer, now time.Time) bool {
	if l.known(p.ip, now) {
		return false
	}
	return l.blocked(p.ip, now) || (p.net != p.ip && l.blocked(p.net, now))
}

// failPeer zaehlt einen Fehlversuch je exakter Adresse und je Netz (bekannte Adressen nicht: sie werden ohnehin
// nicht gesperrt, und ihr Netz soll nicht fuer andere Nodes darin gesperrt werden).
func (l *limiter) failPeer(p peer, now time.Time) {
	if l.known(p.ip, now) {
		return
	}
	l.fail(p.ip, now)
	if p.net != p.ip {
		l.fail(p.net, now)
	}
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

// evict macht Platz in der vollen Liste: erst verfallene Eintraege, sonst der nicht gesperrte mit den wenigsten
// Fehlversuchen (bei Gleichstand der aelteste), notfalls die Sperre, die am fruehesten ausliefe. So verdraengt ein
// Angreifer mit vielen neuen Adressen vor allem seine eigenen frischen Eintraege, nicht seine laengeren Sperren
// (lieber eine kurze Sperre vergessen als neue Fehlversuche nicht mehr zaehlen).
func (l *limiter) evict(now time.Time) {
	var free, soonest string
	var fFree int
	var tFree, tSoon time.Time
	for k, v := range l.m {
		if now.Sub(v.last) > failForget && !now.Before(v.until) {
			delete(l.m, k)
			continue
		}
		if !now.Before(v.until) {
			if free == "" || v.fails < fFree || (v.fails == fFree && v.last.Before(tFree)) {
				free, fFree, tFree = k, v.fails, v.last
			}
		} else if soonest == "" || v.until.Before(tSoon) {
			soonest, tSoon = k, v.until
		}
	}
	if len(l.m) < failMaxIPs {
		return
	}
	if free != "" {
		delete(l.m, free)
	} else {
		delete(l.m, soonest)
	}
}

// ok vergisst die Fehlversuche der exakten Adresse und merkt sie als bekannt (die Zaehlung des Netzes bleibt: eine
// Anmeldung im /64 darf die Sperre eines Nachbarn nicht aufheben).
func (l *limiter) ok(ip string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, ip)
	if l.good == nil {
		l.good = map[string]time.Time{}
	}
	if _, ok := l.good[ip]; !ok && len(l.good) >= goodMaxIPs {
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
	l.good[ip] = now
}

// preAuthSlot ist ein belegter Platz ohne Anmeldung.
type preAuthSlot struct {
	p     peer
	known bool
	since time.Time
	conn  io.Closer
	done  bool // freigegeben oder geraeumt
}

// preAuthGate zaehlt Verbindungen, deren Handshake noch laeuft.
type preAuthGate struct {
	mu       sync.Mutex
	evictAge time.Duration // 0 = preAuthEvictAge (Tests setzen weniger)

	total, knownTotal int
	perNet, perGrp    map[string]int
	known             map[string][]*preAuthSlot // Plaetze je bekannter Adresse, aelteste zuerst
}

// acquire belegt einen Platz; known = exakte Adresse einer bereits angemeldeten Node (eigener Topf). Ist der Topf
// der bekannten Adresse voll, wird ihr aeltester Platz geraeumt (dessen Verbindung geschlossen), sofern dessen
// Handshake schon evictAge laeuft. Liefert nil, wenn kein Platz frei ist.
func (g *preAuthGate) acquire(p peer, known bool, c io.Closer, now time.Time) *preAuthSlot {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.perNet == nil {
		g.perNet, g.perGrp, g.known = map[string]int{}, map[string]int{}, map[string][]*preAuthSlot{}
	}
	sl := &preAuthSlot{p: p, known: known, since: now, conn: c}
	if !known {
		if g.perNet[p.net] >= preAuthPerNet || (p.grp != "" && g.perGrp[p.grp] >= preAuthPerGroup) ||
			g.total >= preAuthMax {
			return nil
		}
		g.perNet[p.net]++
		if p.grp != "" {
			g.perGrp[p.grp]++
		}
		g.total++
		return sl
	}
	own := g.known[p.ip]
	if len(own) >= preAuthPerKnown || g.knownTotal >= preAuthKnownMax {
		age := g.evictAge
		if age <= 0 {
			age = preAuthEvictAge
		}
		if len(own) == 0 || now.Sub(own[0].since) < age {
			return nil
		}
		old := own[0]
		g.drop(old)
		if old.conn != nil {
			_ = old.conn.Close()
		}
	}
	g.known[p.ip] = append(g.known[p.ip], sl)
	g.knownTotal++
	return sl
}

func (g *preAuthGate) release(sl *preAuthSlot) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.drop(sl)
}

// drop gibt einen Platz frei (mehrfach aufrufbar; g.mu gehalten).
func (g *preAuthGate) drop(sl *preAuthSlot) {
	if sl == nil || sl.done {
		return
	}
	sl.done = true
	if sl.known {
		own := g.known[sl.p.ip]
		for i, o := range own {
			if o == sl {
				own = append(own[:i:i], own[i+1:]...)
				break
			}
		}
		if len(own) == 0 {
			delete(g.known, sl.p.ip)
		} else {
			g.known[sl.p.ip] = own
		}
		g.knownTotal--
		return
	}
	decr(g.perNet, sl.p.net)
	if sl.p.grp != "" {
		decr(g.perGrp, sl.p.grp)
	}
	g.total--
}

func decr(m map[string]int, k string) {
	if m[k] <= 1 {
		delete(m, k)
	} else {
		m[k]--
	}
}
