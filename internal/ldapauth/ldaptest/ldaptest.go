// Package ldaptest ist ein minimaler LDAP-Server fuer Tests (ldapauth und web); nur von Tests importiert.
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Server ist ein minimaler LDAP-Server fuer Tests (eigener Fake statt gldap: keine zusaetzliche Abhaengigkeit,
// und die Filter werden wirklich ausgewertet, damit Injection-Tests etwas pruefen): Bind (einfach), Suche mit
// and/or/not/equality/present und LDAP_MATCHING_RULE_IN_CHAIN, StartTLS, ldaps. Ein leeres Passwort meldet er wie
// echte Server als Erfolg (anonymer Bind).
type Server struct {
	t        *testing.T
	ln       net.Listener
	tlsCfg   *tls.Config
	Pool     *x509.CertPool                 // CA des Testzertifikats
	entries  map[string]map[string][]string // DN -> Attribut (klein) -> Werte
	order    []string
	mu       sync.Mutex
	dirMu    sync.RWMutex // Eintraege (Add/Set gegen Bind/Suche)
	binds    []string     // DN jedes Binds mit Passwort ("" = anonym)
	empty    int          // Binds mit leerem Passwort
	conns    int
	searches []string // Filter jeder Suche (lesbar)
	delay    time.Duration
}

// Dienstkonto im Testverzeichnis
const (
	Service         = "cn=svc,dc=example,dc=org"
	ServicePassword = "svcpw"
	oidInChain      = "1.2.840.113556.1.4.1941"
)

func New(t *testing.T, ldaps bool) *Server {
	t.Helper()
	f := &Server{t: t, entries: map[string]map[string][]string{}}
	f.tlsCfg, f.Pool = testCert(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if ldaps {
		ln = tls.NewListener(ln, f.tlsCfg)
	}
	f.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	f.Add(Service, map[string][]string{"objectclass": {"person"}, "userpassword": {ServicePassword}})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.conns++
			f.mu.Unlock()
			go f.serve(c)
		}
	}()
	return f
}

// URL: Adresse mit Schema (ldap oder ldaps).
func (f *Server) URL(scheme string) string { return scheme + "://" + f.ln.Addr().String() }

// Add legt einen Eintrag an (Attributnamen ohne Gross/klein; userPassword fuer Binds).
func (f *Server) Add(dn string, attrs map[string][]string) {
	f.dirMu.Lock()
	defer f.dirMu.Unlock()
	m := map[string][]string{}
	for k, v := range attrs {
		m[strings.ToLower(k)] = v
	}
	f.entries[strings.ToLower(dn)] = m
	f.order = append(f.order, dn)
}

// Set aendert ein Attribut eines vorhandenen Eintrags (z. B. Gruppenmitglieder zwischen zwei Anmeldungen).
func (f *Server) Set(dn, attr string, vals ...string) {
	f.dirMu.Lock()
	defer f.dirMu.Unlock()
	if e := f.entries[strings.ToLower(dn)]; e != nil {
		e[strings.ToLower(attr)] = vals
	}
}

// SetDelay: jede Suche antwortet erst nach d (langsames Verzeichnis).
func (f *Server) SetDelay(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.delay = d
}

// Stats: DNs der Binds mit Passwort, Zahl der Binds mit leerem Passwort, Zahl der Verbindungen.
func (f *Server) Stats() (binds []string, empty, conns int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.binds...), f.empty, f.conns
}

func testCert(t *testing.T) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "fake-ldap"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12}, pool
}

func pstr(p *ber.Packet) string {
	if p == nil || p.Data == nil {
		return ""
	}
	return p.Data.String()
}

func (f *Server) serve(c net.Conn) {
	defer c.Close()
	bound := ""
	for {
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		p, err := ber.ReadPacket(c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case 0: // BindRequest
			dn, pw := pstr(op.Children[1]), pstr(op.Children[2])
			f.mu.Lock()
			if pw == "" {
				f.empty++
			} else {
				f.binds = append(f.binds, dn)
			}
			f.mu.Unlock()
			code := 49
			if pw == "" {
				code, bound = 0, "" // unauthenticated bind: echte Server melden Erfolg
			} else if f.checkPassword(dn, pw) {
				code, bound = 0, dn
			}
			f.result(c, id, 1, code)
		case 2: // Unbind
			return
		case 3: // SearchRequest
			if bound == "" {
				f.result(c, id, 5, 50)
				continue
			}
			f.search(c, id, op)
		case 23: // ExtendedRequest (StartTLS)
			if pstr(op.Children[0]) != "1.3.6.1.4.1.1466.20037" {
				f.result(c, id, 24, 2)
				continue
			}
			f.result(c, id, 24, 0)
			tc := tls.Server(c, f.tlsCfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			c = tc
		default:
			return
		}
	}
}

func (f *Server) checkPassword(dn, pw string) bool {
	f.dirMu.RLock()
	defer f.dirMu.RUnlock()
	e := f.entries[strings.ToLower(dn)]
	return e != nil && len(e["userpassword"]) > 0 && e["userpassword"][0] == pw
}

func envelope(id int64, op *ber.Packet) []byte {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	p.AppendChild(op)
	return p.Bytes()
}

func (f *Server) result(c net.Conn, id int64, tag ber.Tag, code int) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", ""))
	_, _ = c.Write(envelope(id, op))
}

func (f *Server) search(c net.Conn, id int64, op *ber.Packet) {
	base := strings.ToLower(pstr(op.Children[0]))
	limit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	var want []string
	for _, a := range op.Children[7].Children {
		want = append(want, strings.ToLower(pstr(a)))
	}
	f.mu.Lock()
	f.searches = append(f.searches, filterString(filter))
	delay := f.delay
	f.mu.Unlock()
	time.Sleep(delay)
	f.dirMu.RLock()
	defer f.dirMu.RUnlock()
	n := 0
	for _, dn := range f.order {
		e := f.entries[strings.ToLower(dn)]
		if !strings.HasSuffix(strings.ToLower(dn), base) || !f.match(dn, e, filter) {
			continue
		}
		if limit > 0 && int64(n) >= limit {
			f.result(c, id, 5, 4) // sizeLimitExceeded
			return
		}
		n++
		ent := ber.Encode(ber.ClassApplication, ber.TypeConstructed, 4, nil, "")
		ent.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, ""))
		attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		for name, vals := range e {
			if name == "userpassword" || !wanted(want, name) {
				continue
			}
			a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
			a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, ""))
			set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
			for _, v := range vals {
				set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, ""))
			}
			a.AppendChild(set)
			attrs.AppendChild(a)
		}
		ent.AppendChild(attrs)
		_, _ = c.Write(envelope(id, ent))
	}
	f.result(c, id, 5, 0)
}

func wanted(want []string, name string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if w == "1.1" {
			return false
		}
		if w == "*" || w == name {
			return true
		}
	}
	return false
}

var dnAttrs = map[string]bool{"member": true, "uniquemember": true, "memberof": true}

func (f *Server) match(dn string, e map[string][]string, p *ber.Packet) bool {
	switch p.Tag {
	case 0: // and
		for _, ch := range p.Children {
			if !f.match(dn, e, ch) {
				return false
			}
		}
		return true
	case 1: // or
		for _, ch := range p.Children {
			if f.match(dn, e, ch) {
				return true
			}
		}
		return false
	case 2: // not
		return !f.match(dn, e, p.Children[0])
	case 3: // equalityMatch
		attr, val := strings.ToLower(pstr(p.Children[0])), pstr(p.Children[1])
		for _, v := range e[attr] {
			if (dnAttrs[attr] && normDN(v) == normDN(val)) || strings.EqualFold(v, val) {
				return true
			}
		}
		return false
	case 7: // present
		attr := strings.ToLower(pstr(p))
		return attr == "objectclass" || len(e[attr]) > 0
	case 9: // extensibleMatch: nur member:1.2.840.113556.1.4.1941:=<dn>
		var rule, attr, val string
		for _, ch := range p.Children {
			switch ch.Tag {
			case 1:
				rule = pstr(ch)
			case 2:
				attr = strings.ToLower(pstr(ch))
			case 3:
				val = pstr(ch)
			}
		}
		return rule == oidInChain && attr == "member" && f.inChain(e, normDN(val), 0)
	}
	return false
}

// inChain: ist user (normalisiert) direkt oder ueber Untergruppen Mitglied der Gruppe e?
func (f *Server) inChain(e map[string][]string, user string, depth int) bool {
	if depth > 10 {
		return false
	}
	for _, m := range e["member"] {
		if normDN(m) == user {
			return true
		}
		if sub := f.entries[strings.ToLower(m)]; sub != nil && f.inChain(sub, user, depth+1) {
			return true
		}
	}
	return false
}

// filterString: lesbare Form fuer Pruefungen in Tests (Werte in Anfuehrungszeichen).
func filterString(p *ber.Packet) string {
	switch p.Tag {
	case 0, 1, 2:
		s := map[ber.Tag]string{0: "&", 1: "|", 2: "!"}[p.Tag]
		for _, ch := range p.Children {
			s += filterString(ch)
		}
		return "(" + s + ")"
	case 3:
		return "(" + pstr(p.Children[0]) + "=" + strconv.Quote(pstr(p.Children[1])) + ")"
	case 7:
		return "(" + pstr(p) + "=*)"
	}
	return "(?)"
}

// Searches: Filter aller Suchen in lesbarer Form (Werte in Anfuehrungszeichen).
func (f *Server) Searches() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string{}, f.searches...)
}

// normDN: DN ohne Gross/klein und Leerzeichen (nicht lesbar = klein geschrieben).
func normDN(s string) string {
	d, err := ldap.ParseDN(strings.TrimSpace(s))
	if err != nil || d == nil {
		return strings.ToLower(strings.TrimSpace(s))
	}
	var parts []string
	for _, r := range d.RDNs {
		for _, a := range r.Attributes {
			parts = append(parts, strings.ToLower(a.Type)+"="+strings.ToLower(a.Value))
		}
	}
	return strings.Join(parts, ",")
}
