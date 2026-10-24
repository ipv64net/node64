package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
)

// Docker-Bridge-Netz: Lauschen im Container reicht fuer PROXY64 nicht, HTTP- und HTTPS-Port muessen auf dem
// Docker-Host veroeffentlicht sein (-p 80:80 -p 443:443 bzw. ports: in compose). Die Pruefung schickt eine Anfrage mit
// Pruefwert ueber das Gateway (den Docker-Host) an denselben Port; kommt sie beim eigenen Listener an, ist der Port
// veroeffentlicht (Hairpin, siehe localnet.Gateway). Ein anderes Programm auf dem Host antwortet nicht mit dem
// Pruefwert und zaehlt deshalb nicht.

const (
	probePath   = "/.well-known/node64-probe/" // Port 80: Pfad mit Pruefwert
	probeSuffix = ".probe.node64.invalid"      // Port 443: Pruefwert als SNI-Name
	probeTTL    = time.Minute                  // Ergebnis so lange wiederverwenden (Seitenaufrufe)
	probeWait   = 3 * time.Second
)

// Tests: feste Werte statt der Erkennung im Container.
var (
	bridgeNet     = localnet.Bridge
	bridgeGateway = localnet.Gateway
)

// Published ist das Ergebnis der Pruefung.
type Published struct {
	Bridge  bool             `json:"bridge"`            // Container im Bridge-Netz (sonst ist nichts zu pruefen)
	Gateway string           `json:"gateway,omitempty"` // Docker-Host
	Missing []ListenerStatus `json:"missing,omitempty"` // laufende Dienste (http, https), deren Port auf dem Host fehlt
	H3Port  int              `json:"h3_port,omitempty"` // HTTP/3 laeuft (UDP, nicht pruefbar, aber fuer das Beispiel)
	At      time.Time        `json:"at"`
}

// MissingPort: der TCP-Port des Eingangs ist auf dem Host nicht veroeffentlicht.
func (p Published) MissingPort(port int) bool {
	for _, l := range p.Missing {
		if l.Port == port {
			return true
		}
	}
	return false
}

// PortList: die fehlenden Ports fuer den Text ("80 und 443" als "80, 443").
func (p Published) PortList() string {
	out := make([]string, len(p.Missing))
	for i, l := range p.Missing {
		out[i] = strconv.Itoa(l.Port)
	}
	return strings.Join(out, ", ")
}

// publish: die Portangaben fuer docker run bzw. compose (fehlende TCP-Ports, dazu HTTP/3 per UDP).
func (p Published) publish() []string {
	var out []string
	for _, l := range p.Missing {
		out = append(out, strconv.Itoa(l.Port)+":"+strconv.Itoa(l.Port))
	}
	if p.H3Port > 0 && len(p.Missing) > 0 {
		out = append(out, strconv.Itoa(p.H3Port)+":"+strconv.Itoa(p.H3Port)+"/udp")
	}
	return out
}

// RunArgs: "-p 80:80 -p 443:443 -p 443:443/udp" fuer docker run.
func (p Published) RunArgs() string {
	var b strings.Builder
	for i, a := range p.publish() {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString("-p " + a)
	}
	return b.String()
}

// Compose: der ports-Abschnitt fuer docker-compose.yml.
func (p Published) Compose() string {
	b := "    ports:\n"
	for _, a := range p.publish() {
		b += "      - \"" + a + "\"\n"
	}
	return strings.TrimSuffix(b, "\n")
}

type pubCache struct {
	key string
	res Published
}

// Published prueft (hoechstens einmal je Minute bei gleichen Ports), ob HTTP- und HTTPS-Port des Eingangs auf dem
// Docker-Host veroeffentlicht sind. Ausserhalb des Bridge-Netzes leer.
func (e *Edge) Published(ctx context.Context) Published {
	if !bridgeNet() {
		return Published{}
	}
	gw := bridgeGateway()
	st := e.Status()
	key := gw.String()
	var run []ListenerStatus
	h3 := 0
	for _, l := range st.Listeners {
		if !l.Running {
			continue
		}
		if l.Name == "http3" {
			h3 = l.Port
			continue
		}
		run = append(run, l)
		key += " " + l.Name + ":" + strconv.Itoa(l.Port)
	}
	pub := st.Config.publicPort()
	key += " " + strconv.Itoa(pub)
	if c := e.pub.Load(); c != nil && c.key == key && time.Since(c.res.At) < probeTTL {
		return c.res
	}
	res := Published{Bridge: true, H3Port: h3, At: time.Now()}
	if gw.IsValid() {
		res.Gateway = gw.String()
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, l := range run {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok := e.probe(ctx, gw, l.Name, l.Port)
				if !ok && l.Name == "https" && pub != l.Port { // anders veroeffentlicht (-p 8443:443, Einstellung Port nach aussen)
					ok = e.probe(ctx, gw, l.Name, pub)
				}
				if !ok {
					mu.Lock()
					res.Missing = append(res.Missing, l)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		sort.Slice(res.Missing, func(i, j int) bool { return res.Missing[i].Port < res.Missing[j].Port })
	}
	e.pub.Store(&pubCache{key: key, res: res})
	return res
}

// probe schickt eine Pruefanfrage an gw:port und meldet, ob sie beim eigenen Listener ankam.
func (e *Edge) probe(ctx context.Context, gw netip.Addr, name string, port int) bool {
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	e.probes.Store(nonce, false)
	defer e.probes.Delete(nonce)
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	addr := net.JoinHostPort(gw.String(), strconv.Itoa(port))
	if name == "http" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+probePath+nonce, nil)
		if err != nil {
			return false
		}
		req.Host = "probe" + probeSuffix
		cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		if resp, err := cl.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	} else {
		d := tls.Dialer{Config: &tls.Config{ServerName: nonce + probeSuffix, InsecureSkipVerify: true}} // nur der Name zaehlt
		if c, err := d.DialContext(ctx, "tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	v, _ := e.probes.Load(nonce)
	return v == true
}

// probeHit vermerkt eine angekommene Pruefanfrage (false = kein offener Pruefwert).
func (e *Edge) probeHit(nonce string) bool {
	return e.probes.CompareAndSwap(nonce, false, true)
}

// BridgeForTest setzt Erkennung und Gateway fuer Tests anderer Pakete; restore stellt beides wieder her.
func BridgeForTest(bridge bool, gw netip.Addr) (restore func()) {
	oldNet, oldGw := bridgeNet, bridgeGateway
	bridgeNet, bridgeGateway = func() bool { return bridge }, func() netip.Addr { return gw }
	return func() { bridgeNet, bridgeGateway = oldNet, oldGw }
}
