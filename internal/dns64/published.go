package dns64

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
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
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/ports"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Docker-Bridge-Netz: Lauscht DNS64 im Container, heisst das noch nicht, dass das Heimnetz den Port erreicht - er
// muss auf dem Docker-Host veroeffentlicht sein. DNS64 prueft das ueber das Docker-Gateway: ein veroeffentlichter
// Port fuehrt von dort zurueck in den Container, ein Pruefname (localnet.Probe) kommt dann beim eigenen Dienst an.
// Ist der Port nur an eine Host-Adresse gebunden (192.168.2.8:53:53/udp, Issue #137), fuehrt das Gateway nicht
// hin. Dann gilt er trotzdem als veroeffentlicht, wenn die Port-Bindings des eigenen Containers (Docker-API, falls
// erreichbar) ihn unter derselben Nummer zeigen oder Anfragen ueber dieses Protokoll von Adressen ausserhalb der
// Container-Netze ankommen (dann erreicht das LAN den Port offensichtlich). Sonst: Warnung in der Port-Uebersicht
// und auf den Seiten, mit Beispiel fuer docker run und compose.

// pubState ist das Ergebnis der letzten Pruefung.
type pubState struct {
	Bridge   bool              // Container im Bridge-Netz
	Gateway  string            // Docker-Host aus Sicht des Containers
	Checked  time.Time         // letzte Pruefung
	Missing  []string          // nicht veroeffentlicht, z. B. "53/udp"
	Verified []string          // veroeffentlicht (ueber das Gateway oder laut Port-Binding)
	Proto    map[string]string // Port -> Protokoll im Abfrage-Log (udp, tcp, dot, doq, doh) fuer die Ankuenfte
}

const pubEvery = 30 * time.Minute

// pubSelf: Name bzw. Kennung des eigenen Containers fuer die Docker-API (Docker setzt den Hostnamen auf die kurze
// Kennung; Variable fuer Tests).
var pubSelf = os.Hostname

// pubBinding ist ein Port-Binding des eigenen Containers (/containers/{id}/json, NetworkSettings.Ports).
type pubBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// pubBindings liest die Port-Bindings des eigenen Containers ("53/udp" -> Bindings); nil, wenn die Docker-API nicht
// erreichbar ist (kein Socket eingebunden) - dann zaehlen nur Gateway und Ankuenfte.
func pubBindings(ctx context.Context) map[string][]pubBinding {
	self, err := pubSelf()
	if err != nil || self == "" {
		return nil
	}
	hc, base, err := proxmox.DockerClient(dockerDNSHost())
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
	return in.NetworkSettings.Ports
}

// pubBound: key ("53/udp") ist laut Binding unter derselben Nummer auf dem Host veroeffentlicht (auch nur an eine
// Host-Adresse gebunden; 127.0.0.1 erreicht das LAN nicht).
func pubBound(b map[string][]pubBinding, key string) bool {
	p, _, _ := strings.Cut(key, "/")
	for _, x := range b[key] {
		if a, err := netip.ParseAddr(x.HostIP); err == nil && a.IsLoopback() {
			continue
		}
		if x.HostPort == p {
			return true
		}
	}
	return false
}

// pubProto: Protokoll im Abfrage-Log zu einem Port der Pruefung.
func pubProto(c config, key string) string {
	switch key {
	case strconv.Itoa(c.Port) + "/udp":
		return "udp"
	case strconv.Itoa(c.Port) + "/tcp":
		return "tcp"
	case strconv.Itoa(c.DoTPort) + "/udp":
		return "doq"
	case strconv.Itoa(c.DoTPort) + "/tcp":
		return "dot"
	case strconv.Itoa(c.DoHPort) + "/tcp":
		return "doh"
	}
	return ""
}

// ownNets: Netze der eigenen Schnittstellen (im Bridge-Netz das Docker-Netz samt Gateway). Absender darin kamen
// nicht ueber einen veroeffentlichten Port (Variable fuer Tests).
var ownNets = sync.OnceValue(func() []netip.Prefix {
	var out []netip.Prefix
	ifs, _ := net.Interfaces()
	for _, ifc := range ifs {
		list, _ := ifc.Addrs()
		for _, x := range list {
			if n, ok := x.(*net.IPNet); ok {
				if p, err := netip.ParsePrefix(n.String()); err == nil {
					out = append(out, p.Masked())
				}
			}
		}
	}
	return out
})

// pubArrived merkt (nur solange ein Port fehlt), dass eine Anfrage ueber proto von ausserhalb der Container-Netze
// ankam: dann ist der Port auf dem Host veroeffentlicht, auch wenn das Gateway nicht hinfuehrt (dnsserver.Server.Seen,
// je Anfrage - daher zuerst die billigen Pruefungen).
func (m *Module) pubArrived(ip netip.Addr, proto string) {
	st := m.pub.Load()
	if st == nil || len(st.Missing) == 0 {
		return
	}
	if _, ok := m.pubSeen.Load(proto); ok {
		return
	}
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
		return
	}
	for _, p := range ownNets() {
		if p.Contains(ip) {
			return
		}
	}
	if _, dup := m.pubSeen.LoadOrStore(proto, time.Now()); !dup {
		m.log.Info("dns64 port reachable from outside the container networks, notice cleared", "proto", proto, "client", ip.String())
	}
}

// pubMissingNow: fehlende Ports der letzten Pruefung ohne die, ueber die inzwischen Anfragen von aussen ankamen.
func (m *Module) pubMissingNow() []string {
	st := m.pub.Load()
	if st == nil {
		return nil
	}
	var out []string
	for _, k := range st.Missing {
		if p := st.Proto[k]; p != "" {
			if _, ok := m.pubSeen.Load(p); ok {
				continue
			}
		}
		out = append(out, k)
	}
	return out
}

// probeTargets: die Ports des laufenden DNS64 mit dem Weg, auf dem der Pruefname hingeschickt wird.
func (m *Module) probeTargets(c config, gw netip.Addr) map[string]func(context.Context, string) error {
	host := func(port int) string { return net.JoinHostPort(gw.String(), strconv.Itoa(port)) }
	query := func(name string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion(name, dns.TypeTXT)
		return q
	}
	insecure := &tls.Config{InsecureSkipVerify: true} //nolint:gosec // nur Pruefname an die eigene Node
	out := map[string]func(context.Context, string) error{}
	for _, nw := range []string{"udp", "tcp"} {
		out[strconv.Itoa(c.Port)+"/"+nw] = func(ctx context.Context, name string) error {
			_, _, err := (&dns.Client{Net: nw, Timeout: 2 * time.Second}).ExchangeContext(ctx, query(name), host(c.Port))
			return err
		}
	}
	if c.DoT {
		out[strconv.Itoa(c.DoTPort)+"/tcp"] = func(ctx context.Context, name string) error {
			cfg := insecure.Clone()
			cfg.NextProtos = []string{"dot"}
			_, _, err := (&dns.Client{Net: "tcp-tls", Timeout: 3 * time.Second, TLSConfig: cfg}).ExchangeContext(ctx, query(name), host(c.DoTPort))
			return err
		}
	}
	if c.DoQ {
		out[strconv.Itoa(c.DoTPort)+"/udp"] = func(ctx context.Context, name string) error {
			cfg := insecure.Clone()
			cfg.NextProtos = []string{"doq"}
			ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			conn, err := quic.DialAddr(ctx, host(c.DoTPort), cfg, nil)
			if err != nil {
				return err
			}
			defer conn.CloseWithError(0, "")
			st, err := conn.OpenStreamSync(ctx)
			if err != nil {
				return err
			}
			wire, _ := query(name).Pack()
			var n [2]byte
			binary.BigEndian.PutUint16(n[:], uint16(len(wire)))
			if _, err := st.Write(append(n[:], wire...)); err != nil {
				return err
			}
			_ = st.Close()
			_, err = io.ReadAll(io.LimitReader(st, 65537))
			return err
		}
	}
	if c.DoH && !m.dohViaEdge(c) { // ueber den Eingang prueft dessen Besitzer 80/443
		out[strconv.Itoa(c.DoHPort)+"/tcp"] = func(ctx context.Context, name string) error {
			wire, _ := query(name).Pack()
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host(c.DoHPort)+"/dns-query", bytes.NewReader(wire))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/dns-message")
			cl := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: insecure}}
			resp, err := cl.Do(req)
			if err == nil {
				resp.Body.Close()
			}
			return err
		}
	}
	return out
}

// checkPublished prueft im Bridge-Netz, ob die Ports des laufenden DNS-Dienstes auf dem Docker-Host veroeffentlicht
// sind (sonst nur Bridge=false merken).
func (m *Module) checkPublished(ctx context.Context, e *engine, c config) {
	m.checkPublishedAt(ctx, e, c, pubBridge(), localnet.Gateway())
}

// pubBridge: Container im Bridge-Netz (Variable fuer Tests).
var pubBridge = localnet.Bridge

// checkPublishedAt prueft ueber gw (Tests: eigene Adresse).
func (m *Module) checkPublishedAt(ctx context.Context, e *engine, c config, bridge bool, gw netip.Addr) {
	st := &pubState{Bridge: bridge, Checked: time.Now(), Proto: map[string]string{}}
	if st.Bridge && gw.IsValid() {
		st.Gateway = gw.String()
		targets := m.probeTargets(c, gw)
		keys := make([]string, 0, len(targets))
		for k := range targets {
			keys = append(keys, k)
			st.Proto[k] = pubProto(c, k)
		}
		sort.Strings(keys)
		var binds map[string][]pubBinding
		loaded := false
		for _, key := range keys {
			if e.local.Probe(ctx, targets[key]) {
				st.Verified = append(st.Verified, key)
				continue
			}
			if !loaded { // Docker-API nur fragen, wenn das Gateway nicht reicht
				binds, loaded = pubBindings(ctx), true
			}
			if pubBound(binds, key) { // z. B. nur an die LAN-Adresse gebunden (#137)
				st.Verified = append(st.Verified, key)
			} else {
				st.Missing = append(st.Missing, key)
			}
		}
		if len(st.Missing) > 0 {
			m.log.Warn("dns64 ports not published on the docker host", "missing", st.Missing, "gateway", st.Gateway)
		}
	}
	m.pub.Store(st)
}

// runPublished prueft kurz nach dem Start und dann alle 30 Minuten.
func (m *Module) runPublished(ctx context.Context, e *engine, c config) {
	m.pubSeen.Clear() // neuer Start (auch mit anderen Ports): Ankuenfte neu sammeln
	t := time.NewTimer(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkPublished(ctx, e, c)
			t.Reset(pubEvery)
		}
	}
}

// pubMissing: Port fehlt laut letzter Pruefung auf dem Docker-Host (fuer die Port-Uebersicht).
func (m *Module) pubMissing(port int, proto ports.Proto) bool {
	key := strconv.Itoa(port) + "/" + string(proto)
	for _, x := range m.pubMissingNow() {
		if x == key {
			return true
		}
	}
	return false
}

// pubView: Hinweise fuer die Seiten (Bridge-Netz, fehlende Veroeffentlichung, Gateway als Client).
type pubView struct {
	Bridge      bool
	Gateway     string
	Missing     []string
	Publish     string // -p 53:53/udp -p 53:53/tcp …
	Compose     string // "53:53/udp", "53:53/tcp" …
	GatewaySeen bool   // das Gateway steht in den Clients der letzten 24 Stunden (Absender von Docker ersetzt)
}

func (m *Module) pubView(ctx context.Context, e *engine) pubView {
	st := m.pub.Load()
	if st == nil || !st.Bridge {
		return pubView{}
	}
	v := pubView{Bridge: true, Gateway: st.Gateway, Missing: m.pubMissingNow()}
	for i, k := range v.Missing {
		p, proto, _ := strings.Cut(k, "/")
		if i > 0 {
			v.Publish += " "
			v.Compose += ", "
		}
		v.Publish += "-p " + p + ":" + p + "/" + proto
		v.Compose += `"` + p + ":" + p + "/" + proto + `"`
	}
	if e != nil && st.Gateway != "" {
		if rows, err := e.store.RecentClients(ctx, time.Now().Add(-24*time.Hour), 500); err == nil {
			for _, r := range rows {
				if r.Client == st.Gateway {
					v.GatewaySeen = true
				}
			}
		}
	}
	return v
}
