package snmp

import (
	"context"
	"testing"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
)

// FuzzParsers: OIDs, Zahlen und Texte vom Geraet sowie Profile duerfen keine Panics ausloesen.
func FuzzParsers(f *testing.F) {
	for _, s := range []string{".1.3.6.1.2.1.1.1.0", "1.3", "37 C/98 F", "-1,5", "\xff\x00abc", `{"id":"x","name":"X","match":{"probe":".1.3"}}`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if o, ok := parseOID(s); ok {
			if p, ok2 := parseOID(o.String()); !ok2 || cmpOID(o, p) != 0 {
				t.Fatalf("OID nicht stabil: %q", s)
			}
		}
		parseNumText(s, true)
		parseNumText(s, false)
		c := cleanText(s)
		if !utf8.ValidString(c) || utf8.RuneCountInString(c) > maxTextLen {
			t.Fatalf("cleanText: %q", c)
		}
		_, _ = ParseProfile([]byte(s))
	})
}

// FuzzWalk: feindliche Antworten (beliebige OIDs/Typen) enden ohne Panic und ohne Endlosschleife.
func FuzzWalk(f *testing.F) {
	f.Add(".1.3.6.1.2.1.2.2.1.2.1", byte(gosnmp.OctetString), ".1.3.6.1.2.1.2.2.1.3.1", byte(gosnmp.Integer))
	f.Add(".1.3.6.1.2.1.2.2.1.2", byte(gosnmp.EndOfMibView), ".1", byte(gosnmp.NoSuchObject))
	f.Fuzz(func(t *testing.T, o1 string, t1 byte, o2 string, t2 byte) {
		hc := &hostileConn{resp: []pdu{{Name: o1, Type: gosnmp.Asn1BER(t1), Value: []byte("x")}, {Name: o2, Type: gosnmp.Asn1BER(t2), Value: 7}}}
		_, _ = walkColumns(context.Background(), hc, []string{ifDescr, ifType}, 20)
		if hc.reqs > maxWalkReqs {
			t.Fatalf("zu viele Anfragen: %d", hc.reqs)
		}
		_, _ = getScalars(context.Background(), hc, []string{oidSysDescr, oidSysUpTime})
	})
}

type hostileConn struct {
	resp []pdu
	reqs int
}

func (h *hostileConn) v1() bool { return false }
func (h *hostileConn) close()   {}
func (h *hostileConn) get(context.Context, []string) ([]pdu, error) {
	h.reqs++
	return h.resp, nil
}
func (h *hostileConn) getNext(context.Context, []string) ([]pdu, error) {
	h.reqs++
	return h.resp, nil
}
func (h *hostileConn) getBulk(context.Context, []string, uint32) ([]pdu, error) {
	h.reqs++
	return h.resp, nil
}
