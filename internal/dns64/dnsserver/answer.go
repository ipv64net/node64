package dnsserver

import (
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// ReasonAnswer: Antwort eines eigenen Eintrags fuer das Abfrage-Log ("answer:10.0.0.5, 10.0.0.6"; nur "answer:" =
// NODATA, der Name existiert ohne Eintrag dieses Typs).
const ReasonAnswer = "answer:"

// answerShown: so viele Werte stehen im Log, der Rest als "+n".
const answerShown = 3

// answerReason fasst die Antwort auf eine Anfrage vom Typ qtype zusammen: Werte dieses Typs, sonst das Ziel eines
// CNAME, sonst leer (NODATA).
func answerReason(m *dns.Msg, qtype uint16) string {
	var vals []string
	cname := ""
	for _, rr := range m.Answer {
		if rr.Header().Rrtype == qtype || qtype == dns.TypeANY {
			vals = append(vals, rdata(rr))
		} else if c, ok := rr.(*dns.CNAME); ok && cname == "" {
			cname = "CNAME " + strings.TrimSuffix(c.Target, ".")
		}
	}
	if len(vals) == 0 {
		return ReasonAnswer + cname
	}
	more := ""
	if len(vals) > answerShown {
		more = " +" + strconv.Itoa(len(vals)-answerShown)
		vals = vals[:answerShown]
	}
	return ReasonAnswer + strings.Join(vals, ", ") + more
}

// rdata: Inhalt eines Eintrags ohne Kopf (Name, TTL, Klasse, Typ), Namen ohne Punkt am Ende, hoechstens 80 Zeichen.
func rdata(rr dns.RR) string {
	v := strings.TrimSpace(strings.TrimPrefix(rr.String(), rr.Header().String()))
	v = strings.TrimSuffix(v, ".")
	if r := []rune(v); len(r) > 80 {
		v = string(r[:77]) + "..."
	}
	return v
}
