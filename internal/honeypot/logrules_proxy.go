package honeypot

import (
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/hpbridge"
)

// Regeln fuer die Zugriffe von PROXY64 (bridge.go, Plan „PROXY64 und Honeypot64“). Die Zugriffe kommen als LogLine mit
// Origin SrcLog, Format und File "proxy64"; Message traegt nur Metadaten, durch Tabulatoren getrennt (proxyLine).
// Wie bei echten Logs gehen weder Pfad noch User-Agent ins Ereignis, nur IP, Art, Dienst, Port und Regel.
//
// Keine eigene Regel fuer Erfolg (Success): PROXY64 meldet nur abgelehnte Anmeldungen (AuthFail).

func init() {
	const exThr = 3 // wie die Webserver-Regeln (logrules_svc.go)
	reg := func(scen, kind string, thr int, win time.Duration, f func(r *proxyReq) (LogHit, bool)) {
		RegisterLogRule(&LogRule{ID: "proxy64/" + scen, Version: 1, Origins: []string{SrcLog}, Kind: kind, Service: SvcHTTP, Port: 80,
			Threshold: thr, Window: win, Match: proxyMatch(f)})
	}
	// bekannte Exploit-Pfade und OWASP-Muster im Pfad (sensor_classify.go). Auf eingerichteten Hosts nur, wenn die
	// Anwendung sie nicht ausliefert (400/403/404); auf nicht eingerichteten Hosts gibt es keine Anwendung.
	reg("exploit", KindHTTPExploit, exThr, 10*time.Minute, func(r *proxyReq) (LogHit, bool) {
		if r.known && r.status != 400 && r.status != 403 && r.status != 404 {
			return LogHit{}, false
		}
		switch {
		case r.cat >= 0 && webSofort[sensorOWASP[r.cat].kind], r.cat < 0 && r.expl == 2:
			return LogHit{Weight: exThr}, true
		case r.cat >= 0, r.expl == 1:
			return LogHit{}, true
		}
		return LogHit{}, false
	})
	// viele 404 je IP auf eingerichteten Hosts (Verzeichnis-Scan); nicht eingerichtete Hosts: unknown-host
	reg("scan", KindHTTPScan, 30, time.Minute, func(r *proxyReq) (LogHit, bool) {
		return LogHit{}, r.known && r.status == 404
	})
	reg("bad-useragent", KindBadUA, exThr, 10*time.Minute, func(r *proxyReq) (LogHit, bool) {
		return LogHit{}, r.badUA // nur die Art; der User-Agent selbst geht nicht ins Ereignis
	})
	reg("auth", KindHTTPBrute, 10, 5*time.Minute, func(r *proxyReq) (LogHit, bool) {
		return LogHit{}, r.authFail
	})
	// Anfragen auf nicht eingerichtete Hosts (nur IP, fremde Domain). Kommen nur an, solange PROXY64 den Koeder nicht
	// nutzt (bridgeAccess), sonst zaehlt der Koeder dieselbe Anfrage.
	reg("unknown-host", KindHTTPScan, 5, 10*time.Minute, func(r *proxyReq) (LogHit, bool) {
		return LogHit{}, !r.known
	})
}

// proxyReq ist ein zerlegter Zugriff von PROXY64.
type proxyReq struct {
	webReq
	known, authFail bool
}

// proxyLine macht aus einem Zugriff eine LogLine: Message = Quelle, Known, Status, Methode, TLS, AuthFail, Pfad,
// User-Agent (Tabulator-getrennt; Pfad und User-Agent ohne Tabulatoren/Zeilenumbrueche, gekuerzt).
func proxyLine(a hpbridge.Access) LogLine {
	var b strings.Builder
	b.Grow(64 + len(a.Path) + len(a.UA))
	b.WriteString(a.Src.Unmap().WithZone("").String())
	b.WriteByte('\t')
	b.WriteString(proxyBit(a.Known))
	b.WriteByte('\t')
	b.WriteString(itoa(a.Status))
	b.WriteByte('\t')
	b.WriteString(proxyField(a.Method, 16))
	b.WriteByte('\t')
	b.WriteString(proxyBit(a.TLS))
	b.WriteByte('\t')
	b.WriteString(proxyBit(a.AuthFail))
	b.WriteByte('\t')
	b.WriteString(proxyField(a.Path, MaxPath))
	b.WriteByte('\t')
	b.WriteString(proxyField(a.UA, MaxText))
	t := a.Time
	if !t.IsZero() {
		t = t.UTC()
	}
	return LogLine{Time: t, Origin: SrcLog, File: bridgeFormat, Format: bridgeFormat, Message: b.String()}
}

func proxyBit(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// proxyField kuerzt und ersetzt Tabulatoren und Zeilenumbrueche (Trenner der Message) durch Leerzeichen.
func proxyField(s string, n int) string {
	s = storeClip(s, n)
	if strings.ContainsAny(s, "\t\r\n") {
		s = strings.NewReplacer("\t", " ", "\r", " ", "\n", " ").Replace(s)
	}
	return s
}

// proxyCache haelt den zuletzt zerlegten Zugriff: alle proxy64-Regeln einer Zeile zerlegen so nur einmal.
var proxyCache struct {
	sync.Mutex
	msg string
	r   proxyReq
	ok  bool
}

func proxyParse(l *LogLine) (proxyReq, bool) {
	proxyCache.Lock()
	if proxyCache.msg == l.Message && proxyCache.msg != "" {
		r, ok := proxyCache.r, proxyCache.ok
		proxyCache.Unlock()
		return r, ok
	}
	proxyCache.Unlock()
	var r proxyReq
	f := strings.SplitN(l.Message, "\t", 8)
	ok := len(f) == 8
	if ok {
		a, err := netip.ParseAddr(f[0])
		ok = err == nil
		if ok {
			r.src = a.Unmap().WithZone("")
			r.known, r.status, r.method, r.tls, r.authFail = f[1] == "1", webAtoi(f[2]), f[3], f[4] == "1", f[5] == "1"
			webClassify(&r.webReq, f[6], f[7])
		}
	}
	proxyCache.Lock()
	proxyCache.msg, proxyCache.r, proxyCache.ok = l.Message, r, ok
	proxyCache.Unlock()
	return r, ok
}

// proxyMatch prueft zuerst Format und Datei (nur Zugriffe von PROXY64, nie echte Logs), zerlegt dann (geteilt) und
// setzt Quelle und Port.
func proxyMatch(f func(r *proxyReq) (LogHit, bool)) func(l *LogLine) (LogHit, bool) {
	return func(l *LogLine) (LogHit, bool) {
		if l.Format != bridgeFormat || l.File != bridgeFormat {
			return LogHit{}, false
		}
		r, ok := proxyParse(l)
		if !ok {
			return LogHit{}, false
		}
		h, ok := f(&r)
		if !ok {
			return LogHit{}, false
		}
		h.Src = r.src
		if r.tls {
			h.Port = 443
		}
		return h, true
	}
}
