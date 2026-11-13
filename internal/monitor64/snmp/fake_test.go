package snmp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Test-Hilfen: Aufzeichnungen im Format von "snmpwalk -On" (testdata/*.walk), ein Fake-Agent in-process (conn)
// und ein kleiner UDP-Agent, der ueber gosnmp echte Pakete beantwortet (v1/v2c).

// mib ist ein sortierter Satz von Werten.
type mib struct {
	mu   sync.Mutex
	oids []oid
	vals map[string]pdu
}

func newMIB() *mib { return &mib{vals: map[string]pdu{}} }

// set setzt bzw. ersetzt einen Wert.
func (m *mib) set(o string, typ gosnmp.Asn1BER, v any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	po, ok := parseOID(o)
	if !ok {
		panic("bad oid " + o)
	}
	n := po.String()
	if _, ok := m.vals[n]; !ok {
		i := sort.Search(len(m.oids), func(i int) bool { return cmpOID(m.oids[i], po) >= 0 })
		m.oids = append(m.oids, nil)
		copy(m.oids[i+1:], m.oids[i:])
		m.oids[i] = po
	}
	m.vals[n] = pdu{Name: n, Type: typ, Value: v}
}

func (m *mib) del(o string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := normOID(o)
	delete(m.vals, n)
	for i, x := range m.oids {
		if x.String() == n {
			m.oids = append(m.oids[:i], m.oids[i+1:]...)
			break
		}
	}
}

// add erhoeht einen Zaehler.
func (m *mib) add(o string, d uint64) {
	m.mu.Lock()
	p := m.vals[normOID(o)]
	m.mu.Unlock()
	switch v := p.Value.(type) {
	case uint:
		m.set(o, p.Type, uint(uint32(uint64(v)+d)))
	case uint64:
		m.set(o, p.Type, v+d)
	default:
		panic("kein Zaehler: " + o)
	}
}

func (m *mib) get(o string) pdu {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := normOID(o)
	if p, ok := m.vals[n]; ok {
		return p
	}
	return pdu{Name: n, Type: gosnmp.NoSuchObject}
}

func (m *mib) next(o string) pdu {
	m.mu.Lock()
	defer m.mu.Unlock()
	po, _ := parseOID(o)
	i := sort.Search(len(m.oids), func(i int) bool { return cmpOID(m.oids[i], po) > 0 })
	if i >= len(m.oids) {
		return pdu{Name: po.String(), Type: gosnmp.EndOfMibView}
	}
	return m.vals[m.oids[i].String()]
}

// loadWalk liest eine Aufzeichnung ("OID = TYP: Wert").
func loadWalk(t testing.TB, path string) *mib {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := newMIB()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		o, rest, ok := strings.Cut(line, " = ")
		if !ok {
			continue
		}
		typ, val, ok := strings.Cut(rest, ": ")
		if !ok {
			if strings.HasSuffix(rest, ":") || rest == `""` { // "STRING:" ohne Wert
				typ, val = strings.TrimSuffix(rest, ":"), ""
			} else {
				continue // "No Such Object ..."
			}
		}
		switch typ {
		case "STRING":
			m.set(o, gosnmp.OctetString, []byte(strings.Trim(val, `"`)))
		case "Hex-STRING":
			var b []byte
			for _, h := range strings.Fields(val) {
				x, err := strconv.ParseUint(h, 16, 8)
				if err != nil {
					t.Fatalf("%s: %v", line, err)
				}
				b = append(b, byte(x))
			}
			m.set(o, gosnmp.OctetString, b)
		case "OID":
			m.set(o, gosnmp.ObjectIdentifier, val)
		case "INTEGER":
			m.set(o, gosnmp.Integer, int(leadInt(t, val)))
		case "Counter32":
			m.set(o, gosnmp.Counter32, uint(leadInt(t, val)))
		case "Gauge32":
			m.set(o, gosnmp.Gauge32, uint(leadInt(t, val)))
		case "Counter64":
			m.set(o, gosnmp.Counter64, uint64(leadInt(t, val)))
		case "Timeticks":
			if i := strings.Index(val, "("); i >= 0 {
				val = val[i+1:]
			}
			m.set(o, gosnmp.TimeTicks, uint32(leadInt(t, val)))
		case "IpAddress":
			m.set(o, gosnmp.IPAddress, val)
		default:
			t.Fatalf("unbekannter Typ %q in %s", typ, line)
		}
	}
	return m
}

// leadInt liest die fuehrende Zahl ("1024 Bytes", "up(1)" -> 1).
func leadInt(t testing.TB, s string) int64 {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "("); i > 0 && strings.HasSuffix(s, ")") {
		s = s[i+1 : len(s)-1]
	}
	j := 0
	for j < len(s) && (s[j] == '-' || s[j] >= '0' && s[j] <= '9') {
		j++
	}
	v, err := strconv.ParseInt(s[:j], 10, 64)
	if err != nil {
		t.Fatalf("Zahl %q: %v", s, err)
	}
	return v
}

// fakeConn beantwortet Anfragen aus einer mib (v2c-Verhalten bzw. v1 mit noSuchName).
type fakeConn struct {
	m       *mib
	isV1    bool
	reqs    int
	failOn  string // OID-Praefix, bei dem die Anfrage scheitert (Teilfehler)
	emptyOn string // OID-Praefix, bei dem GETBULK eine Antwort ohne Werte liefert (wie HP LaserJet bei fehlender Tabelle)
	fail    bool   // jede Anfrage scheitert (Zeitueberschreitung)
	maxResp int    // hoechstens so viele Varbinds je Antwort (abgeschnittene GETBULK-Antworten)
	onReq   func() // vor jeder Anfrage (z. B. Uhr weiterstellen)
}

func (f *fakeConn) v1() bool { return f.isV1 }
func (f *fakeConn) close()   {}

func (f *fakeConn) check(oids []string) error {
	f.reqs++
	if f.onReq != nil {
		f.onReq()
	}
	if f.fail {
		return errors.New("request timeout (after 1 retries)")
	}
	for _, o := range oids {
		if f.failOn != "" && strings.HasPrefix(normOID(o), f.failOn) {
			return errors.New("request timeout (after 1 retries)")
		}
	}
	return nil
}

func (f *fakeConn) get(_ context.Context, oids []string) ([]pdu, error) {
	if err := f.check(oids); err != nil {
		return nil, err
	}
	out := make([]pdu, 0, len(oids))
	for i, o := range oids {
		p := f.m.get(o)
		if f.isV1 && p.Type == gosnmp.NoSuchObject {
			return nil, &snmpError{status: gosnmp.NoSuchName, index: i + 1}
		}
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeConn) getNext(_ context.Context, oids []string) ([]pdu, error) {
	if err := f.check(oids); err != nil {
		return nil, err
	}
	out := make([]pdu, 0, len(oids))
	for i, o := range oids {
		p := f.m.next(o)
		if f.isV1 && p.Type == gosnmp.EndOfMibView {
			return nil, &snmpError{status: gosnmp.NoSuchName, index: i + 1}
		}
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeConn) getBulk(_ context.Context, oids []string, maxRep uint32) ([]pdu, error) {
	if f.isV1 {
		return nil, errors.New("GETBULK unter v1")
	}
	if err := f.check(oids); err != nil {
		return nil, err
	}
	for _, o := range oids {
		if f.emptyOn != "" && strings.HasPrefix(normOID(o), f.emptyOn) {
			return nil, nil
		}
	}
	cur := append([]string(nil), oids...)
	var out []pdu
	for r := 0; r < int(maxRep); r++ {
		for i := range cur {
			p := f.m.next(cur[i])
			out = append(out, p)
			cur[i] = p.Name
			if f.maxResp > 0 && len(out) >= f.maxResp {
				return out, nil
			}
		}
	}
	return out, nil
}

// newTestCollector baut einen Sammler mit Fake-Verbindung und steuerbarer Zeit.
func newTestCollector(t testing.TB, m *mib, cfg Config) (*Collector, *fakeConn, *time.Time) {
	t.Helper()
	if cfg.Address == "" {
		cfg.Address = "192.0.2.10"
	}
	if cfg.Secret.Community == "" && cfg.Version != "3" {
		cfg.Secret.Community = "testcommunity"
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	fc := &fakeConn{m: m, isV1: cfg.Version == "1"}
	c.dial = func() (conn, error) { return fc, nil }
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	return c, fc, &now
}

// ---- UDP-Agent ueber gosnmp (v1/v2c) ----

type udpAgent struct {
	m         *mib
	community string
	pc        net.PacketConn
	done      chan struct{}
	routerOS  atomic.Int32 // > 0: wie RouterOS - GETBULK ueber so viele Varbinds still verwerfen, noSuchName ohne Index
}

func startAgent(t testing.TB, m *mib, community string) *udpAgent {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := &udpAgent{m: m, community: community, pc: pc, done: make(chan struct{})}
	go a.serve()
	t.Cleanup(func() { pc.Close(); <-a.done })
	return a
}

func (a *udpAgent) port() int { return a.pc.LocalAddr().(*net.UDPAddr).Port }

func (a *udpAgent) serve() {
	defer close(a.done)
	buf := make([]byte, 65535)
	dec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Logger: gosnmp.NewLogger(nil)}
	for {
		n, addr, err := a.pc.ReadFrom(buf)
		if err != nil {
			return
		}
		req, err := dec.SnmpDecodePacket(append([]byte(nil), buf[:n]...))
		if err != nil || req.Community != a.community {
			continue // falsche Community: keine Antwort (wie echte Agenten)
		}
		resp := &gosnmp.SnmpPacket{Version: req.Version, Community: req.Community, PDUType: gosnmp.GetResponse, RequestID: req.RequestID,
			Logger: gosnmp.NewLogger(nil)}
		v1 := req.Version == gosnmp.Version1
		for i, v := range req.Variables {
			var p pdu
			switch req.PDUType {
			case gosnmp.GetRequest:
				p = a.m.get(v.Name)
			case gosnmp.GetNextRequest:
				p = a.m.next(v.Name)
			}
			if a.routerOS.Load() > 0 && req.PDUType == gosnmp.GetRequest && p.Type == gosnmp.NoSuchObject {
				resp.Error, resp.ErrorIndex = gosnmp.NoSuchName, 0
				resp.Variables = req.Variables
				break
			}
			if v1 && (p.Type == gosnmp.NoSuchObject || p.Type == gosnmp.EndOfMibView) {
				resp.Error, resp.ErrorIndex = gosnmp.NoSuchName, uint8(i+1)
				resp.Variables = req.Variables
				break
			}
			if req.PDUType != gosnmp.GetBulkRequest {
				resp.Variables = append(resp.Variables, p)
			}
		}
		if req.PDUType == gosnmp.GetBulkRequest && a.routerOS.Load() > 0 && int(req.MaxRepetitions)*len(req.Variables) > int(a.routerOS.Load()) {
			continue // zu gross: keine Antwort statt tooBig
		}
		if req.PDUType == gosnmp.GetBulkRequest {
			cur := make([]string, len(req.Variables))
			for i, v := range req.Variables {
				cur[i] = v.Name
			}
			for r := 0; r < int(req.MaxRepetitions) && len(resp.Variables) < 200; r++ {
				for i := range cur {
					p := a.m.next(cur[i])
					resp.Variables = append(resp.Variables, p)
					cur[i] = p.Name
				}
			}
		}
		out, err := resp.MarshalMsg()
		if err != nil {
			panic(fmt.Sprintf("marshal: %v", err))
		}
		_, _ = a.pc.WriteTo(out, addr)
	}
}
