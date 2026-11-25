package edge

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker-Bridge-Netz: Lauschen im Container reicht fuer PROXY64 nicht, HTTP- und HTTPS-Port muessen auf dem
// Docker-Host veroeffentlicht sein (-p 80:80 -p 443:443 bzw. ports: in compose). Die Pruefung schickt eine Anfrage mit
// Pruefwert ueber das Gateway (den Docker-Host) an denselben Port; kommt sie beim eigenen Listener an, ist der Port
// veroeffentlicht (Hairpin, siehe localnet.Gateway). Ein anderes Programm auf dem Host antwortet nicht mit dem
// Pruefwert und zaehlt deshalb nicht.
// Nicht jeder Docker-Host leitet Anfragen aus dem Bridge-Netz ueber das Gateway zurueck (UFW auf dem Host, DNAT nur
// fuer fremde Schnittstellen, #243). Kommt die Pruefanfrage nicht an, entscheiden die Port-Bindings des eigenen
// Containers (Docker-API, falls erreichbar). Ohne Docker-API fehlt ein Port nur, wenn der Host die Verbindung abgelehnt
// oder ein anderes Programm geantwortet hat; eine Zeitueberschreitung beweist nichts - der Port gilt dann als nicht
// pruefbar (Unknown, keine Warnung).

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
	Unknown []ListenerStatus `json:"unknown,omitempty"` // laufende Dienste ohne eindeutiges Ergebnis (keine Warnung)
	Found   []int            `json:"found,omitempty"`   // TCP-Ports, die nachweislich veroeffentlicht sind
	H3Port  int              `json:"h3_port,omitempty"` // HTTP/3 laeuft (UDP, nicht pruefbar, aber fuer das Beispiel)
	At      time.Time        `json:"at"`
}

// PortState: Ergebnis fuer einen TCP-Port des Eingangs - "yes" (veroeffentlicht), "no" (fehlt), "unknown" (nicht
// eindeutig pruefbar) oder "" (nicht geprueft).
func (p Published) PortState(port int) string {
	if p.MissingPort(port) {
		return "no"
	}
	for _, l := range p.Unknown {
		if l.Port == port {
			return "unknown"
		}
	}
	for _, f := range p.Found {
		if f == port {
			return "yes"
		}
	}
	return ""
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

// probeResult: Ausgang einer Pruefanfrage ueber das Gateway.
type probeResult int

const (
	probeVague probeResult = iota // keine Aussage (Zeitueberschreitung, Netz nicht erreichbar, Abbruch)
	probeHit                      // kam beim eigenen Listener an: veroeffentlicht
	probeOther                    // vom Host abgelehnt oder ein anderes Programm hat geantwortet: fuehrt nicht hierher
)

// Tests: Docker-API und Name des eigenen Containers (Docker setzt den Hostnamen auf die kurze Kennung).
var (
	pubDockerHost = proxmox.DefaultDockerHost
	pubSelf       = os.Hostname
)

// pubBinding ist ein Port-Binding des eigenen Containers (/containers/{id}/json, NetworkSettings.Ports).
type pubBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// pubBindings liest die Port-Bindings des eigenen Containers ("443/tcp" -> Bindings, wie DNS64); nil, wenn die
// Docker-API nicht erreichbar ist (kein Socket eingebunden, Container nicht gefunden) - dann zaehlt nur die Pruefanfrage.
func pubBindings(ctx context.Context) map[string][]pubBinding {
	self, err := pubSelf()
	if err != nil || self == "" {
		return nil
	}
	hc, base, err := proxmox.DockerClient(pubDockerHost())
	if err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/containers/"+url.PathEscape(self)+"/json", nil)
	if err != nil {
		return nil
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var in struct {
		NetworkSettings struct {
			Ports map[string][]pubBinding `json:"Ports"`
		} `json:"NetworkSettings"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&in) != nil {
		return nil
	}
	if in.NetworkSettings.Ports == nil { // Container ohne Ports: erreichbar, aber leer
		return map[string][]pubBinding{}
	}
	return in.NetworkSettings.Ports
}

// pubBound: der TCP-Port des Containers ist laut Binding unter einer der Nummern hostPorts auf dem Host veroeffentlicht
// (auch nur an eine Host-Adresse gebunden; 127.0.0.1 erreicht von aussen nichts).
func pubBound(b map[string][]pubBinding, port int, hostPorts ...int) bool {
	for _, x := range b[strconv.Itoa(port)+"/tcp"] {
		if a, err := netip.ParseAddr(x.HostIP); err == nil && a.Unmap().IsLoopback() {
			continue
		}
		for _, hp := range hostPorts {
			if x.HostPort == strconv.Itoa(hp) {
				return true
			}
		}
	}
	return false
}

// Published liefert, ob HTTP- und HTTPS-Port des Eingangs auf dem Docker-Host veroeffentlicht sind. Ausserhalb des
// Bridge-Netzes leer. Die Pruefung laeuft im Hintergrund (hoechstens eine zugleich, #276): ein gemerktes Ergebnis
// kommt sofort zurueck, nach einer Minute (probeTTL) wird es beim naechsten Aufruf im Hintergrund erneuert. Ohne
// Ergebnis (erster Aufruf, Ports geaendert) wartet der Aufruf hoechstens pubFirstWait; reicht das nicht, ist das
// Ergebnis leer (nicht geprueft, keine Warnung) und steht beim naechsten Seitenaufruf bereit.
func (e *Edge) Published(ctx context.Context) Published {
	in, ok := e.pubInput()
	if !ok {
		return Published{}
	}
	if c := e.pub.Load(); c != nil && c.key == in.key {
		if time.Since(c.res.At) >= probeTTL {
			e.refreshPublished(in)
		}
		return c.res
	}
	done := e.refreshPublished(in)
	t := time.NewTimer(pubFirstWait)
	defer t.Stop()
	select {
	case <-done:
		if c := e.pub.Load(); c != nil && c.key == in.key {
			return c.res
		}
	case <-t.C:
	case <-ctx.Done():
	}
	return in.empty()
}

// pubFirstWait: so lange wartet ein Seitenaufruf ohne gemerktes Ergebnis auf die Pruefung (Tests: laenger).
var pubFirstWait = 500 * time.Millisecond

// pubIn: die zu pruefenden Dienste des Eingangs; key aendert sich mit Gateway und Ports (dann neu pruefen).
type pubIn struct {
	key string
	gw  netip.Addr
	run []ListenerStatus
	h3  int
	pub int // HTTPS-Port nach aussen (Einstellung)
}

// pubInput: false ausserhalb des Bridge-Netzes (nichts zu pruefen).
func (e *Edge) pubInput() (pubIn, bool) {
	if !bridgeNet() {
		return pubIn{}, false
	}
	in := pubIn{gw: bridgeGateway()}
	st := e.Status()
	in.key = in.gw.String()
	for _, l := range st.Listeners {
		if !l.Running {
			continue
		}
		if l.Name == "http3" {
			in.h3 = l.Port
			continue
		}
		in.run = append(in.run, l)
		in.key += " " + l.Name + ":" + strconv.Itoa(l.Port)
	}
	in.pub = st.Config.publicPort()
	in.key += " " + strconv.Itoa(in.pub)
	return in, true
}

// empty: Ergebnis ohne Pruefung (Bridge-Netz erkannt, Ports noch nicht geprueft).
func (in pubIn) empty() Published {
	res := Published{Bridge: true, H3Port: in.h3, At: time.Now()}
	if in.gw.IsValid() {
		res.Gateway = in.gw.String()
	}
	return res
}

// refreshPublished startet die Pruefung im Hintergrund, falls keine laeuft, und liefert einen Kanal, der nach ihrem
// Ende geschlossen ist (auch den einer schon laufenden Pruefung). Die Pruefung haengt nicht am Seitenaufruf.
func (e *Edge) refreshPublished(in pubIn) <-chan struct{} {
	e.pubMu.Lock()
	defer e.pubMu.Unlock()
	if e.pubRun != nil {
		return e.pubRun
	}
	done := make(chan struct{})
	e.pubRun = done
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		res := e.checkPublished(ctx, in)
		if ctx.Err() == nil {
			e.pub.Store(&pubCache{key: in.key, res: res})
		}
		e.pubMu.Lock()
		e.pubRun = nil
		close(done)
		e.pubMu.Unlock()
	}()
	return done
}

// checkPublished prueft die Ports (Pruefanfrage ueber das Gateway, sonst Docker-API) und wartet auf das Ergebnis.
func (e *Edge) checkPublished(ctx context.Context, in pubIn) Published {
	gw, run, pub := in.gw, in.run, in.pub
	res := in.empty()
	out := make([]probeResult, len(run))
	var wg sync.WaitGroup
	for i, l := range run {
		if !gw.IsValid() {
			continue // ohne Gateway nur die Docker-API
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = e.probe(ctx, gw, l.Name, l.Port)
			if out[i] != probeHit && l.Name == "https" && pub != l.Port { // anders veroeffentlicht (-p 8443:443, Einstellung Port nach aussen)
				if r := e.probe(ctx, gw, l.Name, pub); r != probeOther {
					out[i] = r // fehlend nur, wenn beide Wege eindeutig nicht hierher fuehren
				}
			}
		}()
	}
	wg.Wait()
	var binds map[string][]pubBinding
	loaded := false
	for i, l := range run {
		if out[i] != probeHit {
			if !loaded { // Docker-API nur fragen, wenn die Pruefanfrage nicht reicht
				binds, loaded = pubBindings(ctx), true
			}
			switch {
			case pubBound(binds, l.Port, l.Port, pub):
				out[i] = probeHit
			case binds != nil: // Docker-API erreichbar, aber kein passendes Binding: fehlt sicher
				out[i] = probeOther
			}
		}
		switch out[i] {
		case probeHit:
			res.Found = append(res.Found, l.Port)
		case probeOther:
			res.Missing = append(res.Missing, l)
		default:
			res.Unknown = append(res.Unknown, l)
		}
	}
	sort.Slice(res.Missing, func(i, j int) bool { return res.Missing[i].Port < res.Missing[j].Port })
	return res
}

// probe schickt eine Pruefanfrage an gw:port und meldet, ob sie beim eigenen Listener ankam (probeHit), eindeutig
// woanders endete (probeOther: abgelehnt bzw. fremde Antwort) oder offen blieb (probeVague).
func (e *Edge) probe(ctx context.Context, gw netip.Addr, name string, port int) probeResult {
	var b [8]byte
	_, _ = rand.Read(b[:])
	nonce := hex.EncodeToString(b[:])
	e.probes.Store(nonce, false)
	defer e.probes.Delete(nonce)
	ctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	addr := net.JoinHostPort(gw.String(), strconv.Itoa(port))
	var err error
	if name == "http" {
		req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+probePath+nonce, nil)
		if rerr != nil {
			return probeVague
		}
		req.Host = "probe" + probeSuffix
		cl := &http.Client{Transport: &http.Transport{DisableKeepAlives: true},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		var resp *http.Response
		if resp, err = cl.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	} else {
		d := tls.Dialer{Config: &tls.Config{ServerName: nonce + probeSuffix, InsecureSkipVerify: true}} // nur der Name zaehlt
		var c net.Conn
		if c, err = d.DialContext(ctx, "tcp", addr); err == nil {
			_ = c.Close()
		}
	}
	if v, _ := e.probes.Load(nonce); v == true {
		return probeHit
	}
	// Antwort ohne Pruefwert (anderes Programm) oder vom Host abgelehnt (dort lauscht nichts): fuehrt nicht hierher.
	// Alles andere (Zeitueberschreitung, z. B. Firewall auf dem Host ohne Hairpin) bleibt offen.
	if err == nil || errors.Is(err, syscall.ECONNREFUSED) {
		return probeOther
	}
	return probeVague
}

// probeHit vermerkt eine angekommene Pruefanfrage (false = kein offener Pruefwert).
func (e *Edge) probeHit(nonce string) bool {
	return e.probes.CompareAndSwap(nonce, false, true)
}

// BridgeForTest setzt Erkennung und Gateway fuer Tests anderer Pakete; restore stellt beides wieder her. Solange
// wartet Published ohne gemerktes Ergebnis auf die Pruefung (Tests erwarten das Ergebnis sofort).
func BridgeForTest(bridge bool, gw netip.Addr) (restore func()) {
	oldNet, oldGw, oldWait := bridgeNet, bridgeGateway, pubFirstWait
	bridgeNet, bridgeGateway, pubFirstWait = func() bool { return bridge }, func() netip.Addr { return gw }, time.Minute
	return func() { bridgeNet, bridgeGateway, pubFirstWait = oldNet, oldGw, oldWait }
}
