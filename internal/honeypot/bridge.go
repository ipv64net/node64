package honeypot

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ipv64net/node64/internal/hpbridge"
	"github.com/ipv64net/node64/internal/metrics"
)

// Honeypot64-Seite der Verbindung zu PROXY64 (internal/hpbridge, Plan „PROXY64 und Honeypot64“). Aktiv nur, solange
// das Modul laeuft; ob PROXY64 die Wege nutzt, entscheidet PROXY64 selbst (eigener Opt-in je Weg).
//
//  1. Koeder: Anfragen ohne passenden Host beantwortet der vorhandene Web-Koeder (serveHTTP) ueber einen eigenen
//     Sensor ohne Ports; das Ereignis traegt zusaetzlich "via=proxy64" im Detail.
//  2. Zugriffe: jeder Zugriff wird als LogLine (Format "proxy64") an den Log-Sensor gegeben und dort mit den Regeln
//     proxy64/* (logrules_proxy.go) ausgewertet.
//  3. Sofort-Sperre: bridgeBlockSink meldet auffaellige IPs an PROXY64 (PublishBlock), je IP hoechstens einmal je
//     Stunde; private/reservierte Adressen nie.

const (
	bridgeFormat     = "proxy64"        // LogLine.Format und LogLine.File der Zugriffe
	bridgeDetail     = "via=proxy64"    // Zusatz im Detail der Koeder-Ereignisse
	bridgeBlockFor   = 24 * time.Hour   // Vorschlag fuer die Sperrdauer (die echte Dauer bestimmt PROXY64)
	bridgeBlockEvery = time.Hour        // je IP hoechstens eine Meldung in diesem Abstand
	bridgeBlockMax   = 10000            // gemerkte IPs der Drossel
	bridgeDecoyQuiet = 10 * time.Minute // so lange nach der letzten Koeder-Anfrage gilt der Koeder als genutzt
)

// bridgeCounts zaehlt prozessweit seit dem Start (wie metricCounts: hoechstens ein Honeypot je Prozess).
var bridgeCounts struct {
	decoy, access, dropped, blocks atomic.Int64
	lastDecoy                      atomic.Int64 // UnixNano der letzten Koeder-Anfrage (0 = keine)
}

// bridgeStart meldet Koeder und Auswertung der Zugriffe an. ls ist der Log-Sensor (Zugriffe nur, wenn er FeedLine
// kann), sink die Sink des Moduls, seed der Seed der Dienst-Profile (Sensor-Kennung).
func bridgeStart(log *slog.Logger, ls logSensorAPI, sink Sink, seed string) {
	hpbridge.SetDecoy(newBridgeDecoy(log, sink, seed))
	var feed func(LogLine) bool
	if f, ok := ls.(interface{ FeedLine(LogLine) bool }); ok {
		feed = f.FeedLine
	}
	hpbridge.SetAccessSink(func(a hpbridge.Access) { bridgeAccess(feed, a) })
}

// bridgeStop meldet beides ab (vor dem Stoppen der Sensoren).
func bridgeStop() {
	hpbridge.SetWanted(false)
	hpbridge.SetBlockWanted(false)
	hpbridge.SetDecoy(nil)
	hpbridge.SetAccessSink(nil)
}

// bridgeDecoy beantwortet Anfragen von PROXY64 mit dem Web-Koeder.
type bridgeDecoy struct{ s *Sensor }

// newBridgeDecoy legt den Sensor des Koeders an: keine Ports, eigene Zaehler, Ereignisse mit "via=proxy64" an sink.
// Profil immer nginx (PROXY64 antwortet auf jedem Port als Webserver, nicht je Port des Host-Kopfs als Anwendung).
func newBridgeDecoy(log *slog.Logger, sink Sink, seed string) *bridgeDecoy {
	s := NewSensor(log, "")
	s.Apply(context.Background(), Config{Seed: seed}, func(e Event) {
		if e.Detail == "" {
			e.Detail = bridgeDetail
		} else {
			e.Detail = storeClip(bridgeDetail+","+e.Detail, MaxText)
		}
		if sink != nil {
			sink(e)
		}
	})
	p := *s.personas()
	p.web = PersonaNginx
	s.persona.Store(&p)
	return &bridgeDecoy{s: s}
}

// ServeHTTP: Dienst https bzw. http nach r.TLS, Port aus r.Host (sonst 443/80), Quelle aus r.RemoteAddr (PROXY64
// setzt dort den echten Client nach Trusted Proxies; "IP" ohne Port geht auch). Body begrenzt wie beim Koeder.
func (d *bridgeDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	bridgeCounts.decoy.Add(1)
	bridgeCounts.lastDecoy.Store(time.Now().UnixNano())
	svc, port := SvcHTTP, 80
	if r.TLS != nil {
		svc, port = SvcHTTPS, 443
	}
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	r = r.WithContext(r.Context()) // flache Kopie: RemoteAddr und Body nicht beim Aufrufer aendern
	if _, err := netip.ParseAddrPort(r.RemoteAddr); err != nil {
		if a, err := netip.ParseAddr(strings.Trim(r.RemoteAddr, "[]")); err == nil {
			r.RemoteAddr = netip.AddrPortFrom(a.Unmap().WithZone(""), 0).String()
		}
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, sensorWebBudget)
	}
	d.s.serveHTTP(&trapService{key: sensorKey{Service: svc, Port: port}}, w, r)
}

// bridgeAccess gibt einen Zugriff an den Log-Sensor. Zugriffe auf nicht eingerichtete Hosts zaehlen nur, solange
// PROXY64 den Koeder nicht nutzt (sonst erfasst der Koeder dieselbe Anfrage schon, keine Doppelzaehlung).
func bridgeAccess(feed func(LogLine) bool, a hpbridge.Access) {
	bridgeCounts.access.Add(1)
	if feed == nil || !a.Src.IsValid() {
		return
	}
	if !a.Known && bridgeDecoyUsed(time.Now()) {
		return
	}
	if !feed(proxyLine(a)) {
		bridgeCounts.dropped.Add(1)
	}
}

// bridgeDecoyUsed: PROXY64 hat in den letzten bridgeDecoyQuiet eine Anfrage an den Koeder gegeben.
func bridgeDecoyUsed(now time.Time) bool {
	last := bridgeCounts.lastDecoy.Load()
	return last != 0 && now.Sub(time.Unix(0, last)) < bridgeDecoyQuiet
}

// bridgeBlockSink umhuellt die Sink des Moduls: nach jedem Ereignis wird eine auffaellige, oeffentliche IP an PROXY64
// gemeldet (hpbridge.PublishBlock), je IP hoechstens einmal je bridgeBlockEvery.
func bridgeBlockSink(next Sink) Sink {
	b := &bridgeBlocker{now: time.Now, sent: map[netip.Addr]time.Time{}}
	return func(e Event) {
		next(e)
		b.check(e)
	}
}

// bridgeBlocker ist die Drossel der Sofort-Sperre.
type bridgeBlocker struct {
	now  func() time.Time
	mu   sync.Mutex
	sent map[netip.Addr]time.Time
}

func (b *bridgeBlocker) check(e Event) {
	if !bridgeBlockKind(e) || !reportable(e.Src) {
		return
	}
	ip := e.Src.Unmap().WithZone("")
	now := b.now()
	b.mu.Lock()
	if t, ok := b.sent[ip]; ok && now.Sub(t) < bridgeBlockEvery {
		b.mu.Unlock()
		return
	}
	if len(b.sent) >= bridgeBlockMax { // voll: abgelaufene entfernen, notfalls alles vergessen
		for k, t := range b.sent {
			if now.Sub(t) >= bridgeBlockEvery {
				delete(b.sent, k)
			}
		}
		if len(b.sent) >= bridgeBlockMax {
			clear(b.sent)
		}
	}
	b.sent[ip] = now
	b.mu.Unlock()
	bridgeCounts.blocks.Add(1)
	hpbridge.PublishBlock(hpbridge.Block{IP: ip, Reason: e.Kind, Until: now.Add(bridgeBlockFor)})
}

// bridgeBlockKind: Arten, die sofort sperren (Login-Versuche, Exploits, Port-Scan, Scanner-UA) sowie alle Ereignisse
// der Regeln proxy64/* (die liegen schon ueber ihren Schwellen). generic:probe, http:scan und scanner:research einzeln
// sind zu schwach. Nie sperren die UDP-Fallen (SNMP, SIP): die Quelle eines UDP-Pakets ist ohne Handshake beliebig
// faelschbar, sonst koennte jeder fremde IPs sperren lassen (gemeldet werden sie weiter, ipv64 bewertet zentral).
func bridgeBlockKind(e Event) bool {
	k := e.Kind
	switch {
	case k == KindSNMPBrute, k == KindSIPBrute, k == KindSIPScan:
		return false
	case strings.HasSuffix(k, "bruteforce"), strings.HasPrefix(k, KindHTTPExploit), strings.HasPrefix(k, KindDBExploit),
		k == KindPortScan, k == KindBadUA:
		return true
	}
	return strings.HasPrefix(e.Rule, "proxy64/")
}

// bridgeView ist der Stand der Verbindung fuer die Uebersicht.
type bridgeView struct {
	Connected                      bool // PROXY64 hat schon etwas uebergeben
	Decoy, Access, Blocks, Dropped int64
}

// Proxy64 liefert den Stand der Verbindung zu PROXY64 fuer overview.html (Zaehler seit dem Start).
func (overviewData) Proxy64() bridgeView {
	v := bridgeView{Decoy: bridgeCounts.decoy.Load(), Access: bridgeCounts.access.Load(), Blocks: bridgeCounts.blocks.Load(),
		Dropped: bridgeCounts.dropped.Load()}
	v.Connected = v.Decoy > 0 || v.Access > 0
	return v
}

// writeBridgeMetrics schreibt die Zaehler der Verbindung zu PROXY64 (nur Modul).
func writeBridgeMetrics(w *metrics.Writer) {
	w.Counter("node64_honeypot_proxy_decoy_total", "Von PROXY64 an den Web-Koeder gegebene Anfragen seit dem Start.", float64(bridgeCounts.decoy.Load()))
	w.Counter("node64_honeypot_proxy_access_total", "Von PROXY64 gemeldete Zugriffe seit dem Start.", float64(bridgeCounts.access.Load()))
	w.Counter("node64_honeypot_proxy_access_dropped_total", "Wegen Ueberlast verworfene Zugriffe von PROXY64 seit dem Start.", float64(bridgeCounts.dropped.Load()))
	w.Counter("node64_honeypot_proxy_blocks_total", "An PROXY64 gemeldete Sofort-Sperren seit dem Start.", float64(bridgeCounts.blocks.Load()))
}
