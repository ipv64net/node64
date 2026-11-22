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
	}
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
	if ctx.Err() != nil { // abgebrochener Seitenaufruf: Ergebnis nicht merken
		return res
	}
	e.pub.Store(&pubCache{key: key, res: res})
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

// BridgeForTest setzt Erkennung und Gateway fuer Tests anderer Pakete; restore stellt beides wieder her.
func BridgeForTest(bridge bool, gw netip.Addr) (restore func()) {
	oldNet, oldGw := bridgeNet, bridgeGateway
	bridgeNet, bridgeGateway = func() bool { return bridge }, func() netip.Addr { return gw }
	return func() { bridgeNet, bridgeGateway = oldNet, oldGw }
}
