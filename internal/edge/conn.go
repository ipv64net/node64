package edge

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"
)

// Fertige Verbindungen von aussen annehmen (CDN64 online: Streams aus dem Tunnel zu srv07/srv08). Sie laufen durch
// dieselben Wege wie Verbindungen auf Port 443/80 - Sperrliste, Limits, SNI, TLS, Routen -, aber ueber eigene
// interne Server, damit es auch ohne offene Ports geht.

type virtualKey struct{}

// virtual sind die internen Server fuer angenommene Verbindungen (einmal angelegt, bis Close).
type virtual struct {
	tls  *chanListener
	http *chanListener
	term *chanListener // HTTP, dessen TLS schon auf dem CDN64-Server endete (Modus 2)
	srvs []*http.Server
}

func (e *Edge) virtualServers() *virtual {
	e.vonce.Do(func() {
		errLog := e.errLog()
		mark := func(ctx context.Context, c net.Conn) context.Context {
			if rc, ok := c.(*routedConn); ok && rc.host != "" {
				ctx = context.WithValue(ctx, routedKey{}, rc.host)
			}
			return context.WithValue(ctx, virtualKey{}, true)
		}
		v := &virtual{tls: newChanListener(&net.TCPAddr{}), http: newChanListener(&net.TCPAddr{}), term: newChanListener(&net.TCPAddr{})}
		hs := &http.Server{Handler: http.HandlerFunc(e.serveHTTPS), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10, ErrorLog: errLog, ConnContext: mark,
			TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetConfigForClient: e.tcpConfig}}
		h80 := &http.Server{Handler: http.HandlerFunc(e.serveHTTP), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10, ErrorLog: errLog, ConnContext: mark}
		ht := &http.Server{Handler: http.HandlerFunc(e.serveTerminated), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second,
			MaxHeaderBytes: 64 << 10, ErrorLog: errLog, ConnContext: mark}
		go func() { _ = hs.ServeTLS(v.tls, "", "") }()
		go func() { _ = h80.Serve(v.http) }()
		go func() { _ = ht.Serve(v.term) }()
		v.srvs = []*http.Server{hs, h80, ht}
		e.virt = v
	})
	return e.virt
}

// ServeConn nimmt eine fertige Verbindung an wie eine auf Port 443 (port 443: TLS bzw. Durchreichen nach SNI) oder
// Port 80. RemoteAddr der Verbindung muss die echte Gegenstelle sein. Kehrt sofort zurueck.
func (e *Edge) ServeConn(c net.Conn, port int) { e.ServeConnFor(c, port, "") }

// ServeConnFor wie ServeConn fuer eine Verbindung, die der CDN64-Server fuer einen Namen durchreicht (SNI bzw.
// Host-Kopf, "" = beliebig): Sie gilt nur fuer diesen Namen - anderes SNI wird getrennt, Anfragen fuer einen anderen
// Host (auch per absoluter URL oder spaeter auf derselben Verbindung) bekommen 421.
func (e *Edge) ServeConnFor(c net.Conn, port int, host string) {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		_ = c.Close()
		return
	}
	if port == PortTerminated { // je Anfrage ein Stream: Verbindungs-Limits wuerden Anfragen zaehlen (die Anfrage-Limits gelten)
		if e.blocked(c.RemoteAddr()) {
			_ = c.Close()
			return
		}
	} else if c = e.admit(c); c == nil {
		return
	}
	if host != "" {
		c = &routedConn{Conn: c, host: routedName(host)}
	}
	v := e.virtualServers()
	if v == nil { // Edge wird gerade beendet
		_ = c.Close()
		return
	}
	switch port {
	case 80:
		go v.http.push(c)
		return
	case PortTerminated:
		go v.term.push(c)
		return
	}
	go e.dispatch(c, v.tls)
}

// PortTerminated: ServeConn fuer HTTP, dessen TLS schon vorher endete (CDN64 online Modus 2). Die Anfragen gelten
// als HTTPS fuer den Namen im Host-Kopf (Routen mit Zertifikat, keine Umleitung auf HTTPS).
const PortTerminated = -443

// serveTerminated: wie HTTPS, mit dem Host-Kopf als Namen der Verbindung.
func (e *Edge) serveTerminated(w http.ResponseWriter, r *http.Request) {
	if !routedOK(r) {
		misdirected(w)
		return
	}
	r = r.WithContext(context.WithValue(r.Context(), terminatedKey{}, true))
	r.TLS = &tls.ConnectionState{Version: tls.VersionTLS13, HandshakeComplete: true, ServerName: hostOf(r.Host)}
	if _, routes := e.table.Load().lookup(hostOf(r.Host)); pick(routes, r.URL.Path, true) == nil {
		e.serveHTTP(w, r) // Host nur mit HTTP (ohne Zertifikat in der Node)
		return
	}
	e.serveHTTPS(w, r)
}

type terminatedKey struct{}

type routedKey struct{}

// routedConn: Verbindung aus dem Tunnel mit dem Namen, fuer den der CDN64-Server sie durchreicht (normalisiert).
type routedConn struct {
	net.Conn
	host string
}

// CloseWrite: halb schliessen wie die Verbindung darunter (TLS durchreichen).
func (c *routedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}

// routedName: Name aus dem Tunnel-Kopf wie die Namen der Routen; nicht gueltig = passt zu keiner Anfrage.
func routedName(h string) string {
	if n, err := NormalizeName(h); err == nil {
		return n
	}
	return "!" + h // kein gueltiger Name
}

// routedHost: Name der Verbindung aus dem Tunnel ("" = keine Vorgabe).
func routedHost(c net.Conn) string {
	if rc, ok := c.(*routedConn); ok {
		return rc.host
	}
	return ""
}

// routedOK: Anfrage passt zum Namen, fuer den der CDN64-Server die Verbindung durchreicht. r.Host enthaelt bei
// absoluter URL schon deren Host; URL.Host wird zusaetzlich geprueft.
func routedOK(r *http.Request) bool {
	want, _ := r.Context().Value(routedKey{}).(string)
	if want == "" {
		return true
	}
	return hostOf(r.Host) == want && (r.URL.Host == "" || hostOf(r.URL.Host) == want)
}

// misdirected: Anfrage gehoert nicht zu dieser Verbindung; danach wird die Verbindung geschlossen.
func misdirected(w http.ResponseWriter) {
	w.Header().Set("Connection", "close")
	http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
}

// terminatedReq: TLS endete schon auf dem CDN64-Server (Modus 2) - dort gibt es eigenes HTTP/3.
func terminatedReq(r *http.Request) bool {
	v, _ := r.Context().Value(terminatedKey{}).(bool)
	return v
}

// viaTunnel: Anfrage kam ueber ServeConn (dann kein Alt-Svc fuer HTTP/3 - der Besucher erreicht hier nur TCP).
func viaTunnel(r *http.Request) bool {
	v, _ := r.Context().Value(virtualKey{}).(bool)
	return v
}

func (e *Edge) closeVirtual(ctx context.Context) {
	var v *virtual
	e.vonce.Do(func() {}) // danach legt niemand mehr welche an
	v = e.virt
	if v == nil {
		return
	}
	var wg sync.WaitGroup
	for _, s := range v.srvs {
		wg.Add(1)
		go func() { defer wg.Done(); _ = s.Shutdown(ctx) }()
	}
	_ = v.tls.Close()
	_ = v.http.Close()
	_ = v.term.Close()
	wg.Wait()
}
