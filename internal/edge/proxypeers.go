package edge

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Zum PROXY protocol (proxyproto.go): Auf Wunsch (Config.ProxyProtocolPeers) gelten auch die Adressen der eigenen
// Cluster-Nodes als vertraut (SetProxyPeers); sie werden jede Minute neu bestimmt und ziehen so bei einem Adresswechsel
// mit (#138). Schickt eine nicht vertraute Quelle trotzdem einen Kopf, scheitert TLS daran - das steht dann gebremst im
// Log und im Zugriffs-Log von PROXY64, damit die fehlende Freigabe auffaellt statt still die Verbindung zu schliessen.

const (
	ppLogEvery  = 10 * time.Minute // je Quelle hoechstens ein Log-Eintrag in diesem Abstand
	ppLogMax    = 1000             // gemerkte Quellen (danach wird die Liste geleert)
	ppPeerEvery = time.Minute      // Adressen der Cluster-Nodes neu bestimmen
)

// proxyListen des Eingangs: eingetragene Adressen und, wenn eingeschaltet, die der Cluster-Nodes (zur Laufzeit).
func (e *Edge) proxyListen(ln net.Listener, cfg Config) net.Listener {
	nets, err := parseTrustedNets(cfg.ProxyProtocol)
	if err != nil || (len(nets) == 0 && !cfg.ProxyProtocolPeers) {
		return ln
	}
	peers := cfg.ProxyProtocolPeers
	return newPPListener(ln, func(a net.Addr) bool { return trustedAddr(nets, a) || (peers && e.clusterAddr(addrIP(a))) }, e.proxyBadHeader)
}

// isProxyHeader: die ersten Bytes einer Verbindung sind ein PROXY-Kopf (v1 oder v2), auch wenn nur ein Teil gelesen ist.
func isProxyHeader(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	if bytes.HasPrefix(b, []byte("PROXY ")) || string(b) == "PROXY" {
		return true
	}
	n := min(len(b), len(ppV2Sig))
	return bytes.Equal(b[:n], ppV2Sig[:n])
}

// ppLimiter bremst die Log-Eintraege zu abgewiesenen bzw. kaputten PROXY-Koepfen (je Quelle einer je ppLogEvery).
type ppLimiter struct {
	mu   sync.Mutex
	last map[netip.Addr]time.Time
}

func (l *ppLimiter) allow(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == nil || len(l.last) >= ppLogMax {
		l.last = map[netip.Addr]time.Time{}
	}
	if t, ok := l.last[ip]; ok && now.Sub(t) < ppLogEvery {
		return false
	}
	l.last[ip] = now
	return true
}

// proxyUntrusted: Verbindung mit PROXY-Kopf von einer Quelle, die ihn nicht schicken darf (wird geschlossen). Ins Log
// (gebremst) mit dem Hinweis, wo die Quelle freizugeben ist, und an den Beobachter (Zugriffs-Log von PROXY64).
func (e *Edge) proxyUntrusted(ip netip.Addr) {
	if e.ppLog.allow(ip, time.Now()) {
		hint := "add the address under Settings > Ports > Accept PROXY protocol from"
		if e.knownPeer(ip) {
			hint = "address of a cluster node: switch on Accept PROXY protocol from cluster nodes (Settings > Ports) or add the address"
		}
		e.log.Warn("PROXY protocol header from untrusted source, connection closed", "ip", ip.String(), "hint", hint)
	}
	e.watched(ip, "", "-", "", 0, WatchProxyUntrusted)
}

// proxyBadHeader: vertraute Quelle mit unlesbarem PROXY-Kopf (gebremst ins Log).
func (e *Edge) proxyBadHeader(a net.Addr, err error) {
	if ip := addrIP(a); e.ppLog.allow(ip, time.Now()) {
		e.log.Warn("PROXY protocol header not readable, connection closed", "ip", ip.String(), "err", err)
	}
}

// SetProxyPeers setzt die Quelle der Cluster-Nodes (URLs bzw. Adressen der anderen Nodes, z. B.
// "https://192.168.1.5:8443"). Mit Config.ProxyProtocolPeers nimmt der Eingang von deren Adressen einen PROXY-Kopf an;
// Namen werden aufgeloest, die Liste jede Minute neu bestimmt.
func (e *Edge) SetProxyPeers(f func(ctx context.Context) []string) {
	if f == nil {
		e.ppSrc.Store(nil)
		return
	}
	e.ppSrc.Store(&f)
	e.ppOnce.Do(func() { go e.peerLoop() })
	e.kickPeers()
}

func (e *Edge) kickPeers() {
	select {
	case e.ppKick <- struct{}{}:
	default:
	}
}

// ProxyPeers: die Adressen der Cluster-Nodes, die gerade als vertraut gelten (leer = Schalter aus bzw. keine).
func (e *Edge) ProxyPeers() []netip.Addr {
	if !e.Config().ProxyProtocolPeers {
		return nil
	}
	if p := e.ppPeers.Load(); p != nil {
		return slices.Clone(*p)
	}
	return nil
}

// knownPeer: Adresse einer Cluster-Node (unabhaengig vom Schalter, fuer den Hinweis im Log).
func (e *Edge) knownPeer(ip netip.Addr) bool {
	p := e.ppPeers.Load()
	return p != nil && slices.Contains(*p, ip.Unmap())
}

// clusterAddr: Adresse einer Cluster-Node, von der ein PROXY-Kopf angenommen wird (Schalter an).
func (e *Edge) clusterAddr(ip netip.Addr) bool {
	return e.Config().ProxyProtocolPeers && e.knownPeer(ip)
}

// peerLoop bestimmt die Adressen der Cluster-Nodes, bis der Eingang endet. Auch bei ausgeschaltetem Schalter, damit
// das Log bei einem abgewiesenen Kopf einer Cluster-Node auf den Schalter hinweisen kann.
func (e *Edge) peerLoop() {
	t := time.NewTicker(ppPeerEvery)
	defer t.Stop()
	for {
		e.mu.Lock()
		closed := e.closed
		e.mu.Unlock()
		if closed {
			return
		}
		e.refreshPeers()
		select {
		case <-t.C:
		case <-e.ppKick:
		}
	}
}

func (e *Edge) refreshPeers() {
	src := e.ppSrc.Load()
	if src == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := resolvePeers(ctx, (*src)(ctx), e.lookupIP)
	if old := e.ppPeers.Load(); old != nil && slices.Equal(*old, out) {
		return
	}
	e.ppPeers.Store(&out)
	if e.Config().ProxyProtocolPeers {
		e.log.Info("PROXY protocol accepted from cluster nodes", "addrs", out)
	}
}

func (e *Edge) lookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// resolvePeers: Adressen aus URLs bzw. Adressen (Namen ueber lookup), ohne Doppelte, sortiert.
func resolvePeers(ctx context.Context, list []string, lookup func(context.Context, string) ([]netip.Addr, error)) []netip.Addr {
	out := []netip.Addr{}
	add := func(a netip.Addr) {
		if a = a.Unmap(); a.IsValid() && !a.IsUnspecified() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, raw := range list {
		host := strings.TrimSpace(raw)
		if u, err := url.Parse(host); err == nil && u.Host != "" {
			host = u.Hostname()
		}
		host = strings.Trim(host, "[]")
		if host == "" {
			continue
		}
		if a, err := netip.ParseAddr(host); err == nil {
			add(a)
			continue
		}
		addrs, err := lookup(ctx, host)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			add(a)
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return out
}
