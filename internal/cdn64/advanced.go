package cdn64

import (
	"compress/gzip"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

// Erweitert: feste Felder statt freier nginx-Konfiguration.

// Header ist eine Kopfzeile zum Setzen.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Advanced sind die weiteren Optionen eines Hosts.
type Advanced struct {
	RequestHeaders  []Header `json:"request_headers,omitempty"`  // an das Ziel setzen
	RequestRemove   []string `json:"request_remove,omitempty"`   // vor dem Ziel entfernen
	ResponseHeaders []Header `json:"response_headers,omitempty"` // an den Besucher setzen
	ResponseRemove  []string `json:"response_remove,omitempty"`  // vor dem Besucher entfernen
	HostHeader      string   `json:"host_header,omitempty"`      // "" = Name des Besuchers, "target" = Ziel, sonst fester Wert
	TimeoutSeconds  int      `json:"timeout_seconds,omitempty"`  // bis zur Antwort des Ziels, 0 = ohne
	MaxBodyMB       int      `json:"max_body_mb,omitempty"`      // hoechstens so viel hochladen, 0 = unbegrenzt
	NoBuffering     bool     `json:"no_buffering,omitempty"`     // sofort weiterreichen (Streaming, SSE)
	Gzip            bool     `json:"gzip,omitempty"`             // Text-Antworten komprimieren
	TrustedProxies  []string `json:"trusted_proxies,omitempty"`  // echte Client-IP aus diesen Proxys (z. B. Cloudflare)
	AccessLog       bool     `json:"access_log,omitempty"`       // jede Anfrage protokollieren
	NoLimits        bool     `json:"no_limits,omitempty"`        // ohne Anfrage-Limit je IP und ohne Platzgrenze beim Ziel
	trusted         []netip.Prefix

	// Laendersperre (geo.go): "" = aus, block = diese Laender sperren, allow = nur diese Laender zulassen
	GeoMode      string   `json:"geo_mode,omitempty"`
	GeoCountries []string `json:"geo_countries,omitempty"` // ISO-Laendercodes, z. B. DE
}

// Location ist ein Pfad mit eigenem Ziel (Custom Location).
type Location struct {
	Path         string `json:"path"`         // Praefix, z. B. /api
	Scheme       string `json:"scheme"`       // http | https
	TargetHost   string `json:"target_host"`  // Name oder IP
	TargetPort   int    `json:"target_port"`  // Port
	ForwardPath  string `json:"forward_path"` // ersetzt den Praefix beim Ziel ("" = unveraendert)
	WebSockets   bool   `json:"websockets"`
	AccessListID int64  `json:"access_list_id"` // 0 = wie der Host
}

// Cloudflare-Netze (Stand 2026, https://www.cloudflare.com/ips/) als Vorlage fuer vertrauenswuerdige Proxys.
var CloudflareNets = []string{"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
	"190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14",
	"172.64.0.0/13", "131.0.72.0/22", "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
	"2c0f:f248::/32"}

func validHeaderName(n string) bool {
	if n == "" || len(n) > 100 {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// hop-by-hop und Kopfzeilen, die Node64 selbst setzt: nicht ueberschreibbar
var fixedHeaders = map[string]bool{"connection": true, "upgrade": true, "transfer-encoding": true, "content-length": true, "te": true,
	"trailer": true, "keep-alive": true, "proxy-connection": true, strings.ToLower(loopHeader): true}

// normalize prueft die weiteren Optionen.
func (a *Advanced) normalize() error {
	for _, list := range [][]Header{a.RequestHeaders, a.ResponseHeaders} {
		for i := range list {
			list[i].Name = strings.TrimSpace(list[i].Name)
			if !validHeaderName(list[i].Name) || fixedHeaders[strings.ToLower(list[i].Name)] || strings.ContainsAny(list[i].Value, "\r\n") || len(list[i].Value) > 1000 {
				return &FieldError{Field: "advanced", Key: "cdn64.err.header", Name: list[i].Name}
			}
		}
	}
	for _, list := range [][]string{a.RequestRemove, a.ResponseRemove} {
		for i := range list {
			list[i] = strings.TrimSpace(list[i])
			if !validHeaderName(list[i]) {
				return &FieldError{Field: "advanced", Key: "cdn64.err.header", Name: list[i]}
			}
		}
	}
	a.HostHeader = strings.TrimSpace(a.HostHeader)
	if strings.ContainsAny(a.HostHeader, " \r\n/") || len(a.HostHeader) > 253 {
		return &FieldError{Field: "advanced", Key: "cdn64.err.host_header", Name: a.HostHeader}
	}
	if a.TimeoutSeconds < 0 || a.TimeoutSeconds > 86400 || a.MaxBodyMB < 0 || a.MaxBodyMB > 1<<20 {
		return &FieldError{Field: "advanced", Key: "cdn64.err.limits"}
	}
	var nets []string
	for _, n := range a.TrustedProxies {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		p, err := parsePrefix(n)
		if err != nil || p.Bits() == 0 {
			return &FieldError{Field: "advanced", Key: "cdn64.err.trusted", Name: n}
		}
		nets = append(nets, p.String())
	}
	a.TrustedProxies = nets
	return nil
}

func (a *Advanced) prepare() {
	a.trusted = a.trusted[:0]
	for _, n := range a.TrustedProxies {
		if p, err := parsePrefix(n); err == nil {
			a.trusted = append(a.trusted, p)
		}
	}
}

func (a *Advanced) isTrusted(ip netip.Addr) bool {
	for _, p := range a.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP: echte Gegenstelle; kommt sie von einem vertrauenswuerdigen Proxy, die Adresse aus CF-Connecting-IP
// bzw. der letzte nicht vertrauenswuerdige Eintrag in X-Forwarded-For.
func (a *Advanced) clientIP(r *http.Request) netip.Addr {
	peer := peerIP(r)
	if !peer.IsValid() || !a.isTrusted(peer) {
		return peer
	}
	if v := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); v != "" {
		if ip, err := netip.ParseAddr(v); err == nil {
			return ip.Unmap()
		}
	}
	parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			break
		}
		ip = ip.Unmap()
		if !a.isTrusted(ip) {
			return ip
		}
	}
	return peer
}

// ---------------------------------------------------------------- gzip

var gzPool = sync.Pool{New: func() any { w, _ := gzip.NewWriterLevel(nil, gzip.DefaultCompression); return w }}

func compressible(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.HasPrefix(ct, "text/") || strings.Contains(ct, "json") || strings.Contains(ct, "javascript") || strings.Contains(ct, "xml") ||
		strings.Contains(ct, "svg") || strings.Contains(ct, "wasm")
}

// gzipWriter komprimiert, wenn die Antwort dafuer taugt (entschieden beim ersten WriteHeader).
type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
}

func (w *gzipWriter) WriteHeader(code int) {
	if !w.decided {
		w.decided = true
		h := w.Header()
		cl, _ := strconv.Atoi(h.Get("Content-Length"))
		if code == http.StatusOK && h.Get("Content-Encoding") == "" && compressible(h.Get("Content-Type")) && (cl == 0 || cl >= 512) {
			h.Del("Content-Length")
			h.Set("Content-Encoding", "gzip")
			h.Add("Vary", "Accept-Encoding")
			w.gz = gzPool.Get().(*gzip.Writer)
			w.gz.Reset(w.ResponseWriter)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *gzipWriter) Write(b []byte) (int, error) {
	if !w.decided {
		w.WriteHeader(http.StatusOK)
	}
	if w.gz != nil {
		return w.gz.Write(b)
	}
	return w.ResponseWriter.Write(b)
}

func (w *gzipWriter) Flush() {
	if w.gz != nil {
		_ = w.gz.Flush()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *gzipWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *gzipWriter) close() {
	if w.gz != nil {
		_ = w.gz.Close()
		gzPool.Put(w.gz)
		w.gz = nil
	}
}

// withGzip komprimiert Antworten fuer Browser, die gzip koennen (nicht bei Range, HEAD und WebSockets).
func withGzip(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead || r.Header.Get("Range") != "" || r.Header.Get("Upgrade") != "" ||
			!strings.Contains(strings.ToLower(r.Header.Get("Accept-Encoding")), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		gw := &gzipWriter{ResponseWriter: w}
		defer gw.close()
		next.ServeHTTP(gw, r)
	})
}
