package dns64

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/ipv64net/node64/internal/dns64/localnet"
	"github.com/ipv64net/node64/internal/ports"
)

// Docker-Bridge-Netz: Lauscht DNS64 im Container, heisst das noch nicht, dass das Heimnetz den Port erreicht - er
// muss auf dem Docker-Host veroeffentlicht sein. DNS64 prueft das ueber das Docker-Gateway: ein veroeffentlichter
// Port fuehrt von dort zurueck in den Container, ein Pruefname (localnet.Probe) kommt dann beim eigenen Dienst an.
// Ohne Ankunft: Warnung in der Port-Uebersicht und auf den Seiten, mit Beispiel fuer docker run und compose.

// pubState ist das Ergebnis der letzten Pruefung.
type pubState struct {
	Bridge   bool      // Container im Bridge-Netz
	Gateway  string    // Docker-Host aus Sicht des Containers
	Checked  time.Time // letzte Pruefung
	Missing  []string  // nicht veroeffentlicht, z. B. "53/udp"
	Verified []string  // veroeffentlicht
}

const pubEvery = 30 * time.Minute

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
	st := &pubState{Bridge: localnet.Bridge(), Checked: time.Now()}
	gw := localnet.Gateway()
	if st.Bridge && gw.IsValid() {
		st.Gateway = gw.String()
		targets := m.probeTargets(c, gw)
		keys := make([]string, 0, len(targets))
		for k := range targets {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if e.local.Probe(ctx, targets[key]) {
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
	st := m.pub.Load()
	if st == nil {
		return false
	}
	key := strconv.Itoa(port) + "/" + string(proto)
	for _, x := range st.Missing {
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
	v := pubView{Bridge: true, Gateway: st.Gateway, Missing: st.Missing}
	for i, k := range st.Missing {
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
