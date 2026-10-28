package proxmox

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Client spricht die Proxmox-API eines Systems an – nur GET. Er kennt die eingerichteten Adressen und die aus
// cluster/status gelernten Node-Adressen und nimmt zuerst die zuletzt funktionierende (Failover).
//
// TLS: ist PinSHA256 gesetzt, wird nur ein Zertifikat mit genau diesem Fingerabdruck (SHA-256 ueber das DER des
// Leaf-Zertifikats) angenommen – InsecureSkipVerify gibt es nur zusammen mit dieser Pruefung. Ohne Pin gilt die
// System-CA (mit Pruefung des Hostnamens). Gelernte Adressen: mit Pin des Systems gelten die Fingerabdruecke, die der
// Poller ueber die vertrauenswuerdige Verbindung aus /nodes/{node}/certificates/info lernt (SetLearnedPins, nur im
// Speicher); fehlen sie (z. B. keine Rechte), gilt der Pin des Systems. Ohne Pin gilt auch hier die System-CA.
// Passt ein Zertifikat nicht, wird die gelernte Adresse eine Weile ausgelassen.

const (
	pveDialTimeout    = 5 * time.Second  // Verbindungsaufbau inkl. TLS
	pveRequestTimeout = 10 * time.Second // ganze Anfrage
	pveMaxBody        = 16 << 20         // groesste Antwort (cluster/resources grosser Cluster)
	pveCertBadPause   = 30 * time.Minute // gelernte Adresse mit unpassendem Zertifikat so lange auslassen
)

// Fehlerarten (errors.Is auf einen Fehler des Clients).
var (
	ErrToken        = errors.New("token invalid")
	ErrPermission   = errors.New("permission denied")
	ErrCertMismatch = errors.New("certificate mismatch")
	ErrCertInvalid  = errors.New("certificate not trusted")
	ErrUnreachable  = errors.New("not reachable")
	ErrTimeout      = errors.New("timeout")
	ErrResponse     = errors.New("bad response")
)

// Error ist ein Fehler einer Anfrage an eine Adresse.
type Error struct {
	Kind    error  // eine der Fehlerarten oben
	Address string // https://host:port
	Status  int    // HTTP-Status (0 = keine Antwort)
	Detail  string // Text von Proxmox bzw. aus dem Netz
	Others  int    // so viele weitere Adressen wurden ohne Erfolg versucht
}

func (e *Error) Unwrap() error { return e.Kind }

func (e *Error) Error() string {
	var b strings.Builder
	switch {
	case errors.Is(e.Kind, ErrToken):
		b.WriteString("401 token invalid – check token ID (user@realm!tokenid) and secret")
	case errors.Is(e.Kind, ErrPermission):
		b.WriteString("403 permission denied – the token lacks rights: grant role PVEAuditor on path / to the token")
	case errors.Is(e.Kind, ErrCertMismatch):
		b.WriteString("certificate mismatch – the fingerprint differs from the pinned one")
	case errors.Is(e.Kind, ErrCertInvalid):
		b.WriteString("certificate not trusted – pin its fingerprint or use a certificate signed by a public CA")
	case errors.Is(e.Kind, ErrTimeout):
		b.WriteString("timeout – no answer in time")
	case errors.Is(e.Kind, ErrUnreachable):
		b.WriteString("not reachable")
	case e.Status != 0:
		fmt.Fprintf(&b, "HTTP %d", e.Status)
	default:
		b.WriteString(e.Kind.Error())
	}
	if e.Detail != "" {
		b.WriteString(" (" + e.Detail + ")")
	}
	if e.Address != "" {
		b.WriteString(" at " + e.Address)
	}
	if e.Others > 0 {
		fmt.Fprintf(&b, ", %d more address(es) tried", e.Others)
	}
	return b.String()
}

// errPinMismatch kommt aus VerifyPeerCertificate und wird zu ErrCertMismatch.
type errPinMismatch struct{ got string }

func (e *errPinMismatch) Error() string {
	return "certificate fingerprint " + e.got + " does not match the pin"
}

// CertFingerprint ist der SHA-256 des DER-Zertifikats als Kleinbuchstaben-Hex ohne Doppelpunkte.
func CertFingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}

// Client ist der API-Client eines Systems (sicher fuer gleichzeitige Anfragen).
type Client struct {
	auth   string
	http   *http.Client // eingerichtete Adressen (Pin des Systems bzw. System-CA)
	pin    string       // Pin des Systems ("" = System-CA)
	roots  *x509.CertPool
	dialTO time.Duration
	reqTO  time.Duration
	now    func() time.Time
	mu     sync.Mutex
	addrs  []string             // eingerichtete Adressen (normalisiert)
	learn  []string             // aus cluster/status gelernt
	last   string               // zuletzt funktionierende Adresse
	badTLS map[string]time.Time // gelernte Adresse -> Zertifikat passte nicht (seit)
	// Pins je gelernter Adresse (aus /nodes/{node}/certificates/info, nur im Speicher) und die zugehoerigen Clients.
	lpins map[string][]string
	lhttp map[string]*http.Client
}

// NewClient baut den Client fuer ein System (Adressen normalisiert, Pin geprueft).
func NewClient(sys System) (*Client, error) {
	return newClient(sys, nil, pveDialTimeout, pveRequestTimeout)
}

// newClient: roots nil = System-CA (Tests geben eigene Wurzeln und kuerzere Zeitlimits).
func newClient(sys System, roots *x509.CertPool, dialTO, reqTO time.Duration) (*Client, error) {
	if strings.TrimSpace(sys.TokenID) == "" || sys.Secret == "" {
		return nil, errors.New("token ID and secret are required")
	}
	if !strings.Contains(sys.TokenID, "!") || !strings.Contains(sys.TokenID, "@") {
		return nil, fmt.Errorf("token ID %q must look like user@realm!tokenid", sys.TokenID)
	}
	pin, ok := NormalizePin(sys.PinSHA256)
	if !ok {
		return nil, fmt.Errorf("fingerprint must be 64 hex digits (SHA-256), got %q", sys.PinSHA256)
	}
	c := &Client{
		auth:   "PVEAPIToken=" + strings.TrimSpace(sys.TokenID) + "=" + sys.Secret,
		pin:    pin,
		roots:  roots,
		dialTO: dialTO,
		reqTO:  reqTO,
		now:    time.Now,
		badTLS: map[string]time.Time{},
		lpins:  map[string][]string{},
		lhttp:  map[string]*http.Client{},
	}
	for _, a := range sys.Addresses {
		if strings.TrimSpace(a) == "" {
			continue
		}
		n, ok := NormalizeAddress(a)
		if !ok {
			return nil, fmt.Errorf("invalid address %q (use https://host:8006)", a)
		}
		if !slices.Contains(c.addrs, n) {
			c.addrs = append(c.addrs, n)
		}
	}
	if len(c.addrs) == 0 {
		return nil, errors.New("no address configured")
	}
	var pins []string
	if pin != "" {
		pins = []string{pin}
	}
	c.http = c.buildHTTP(pins)
	return c, nil
}

// buildHTTP baut einen HTTP-Client: pins leer = System-CA, sonst nur Leaf-Zertifikate mit einem dieser Fingerabdruecke.
func (c *Client) buildHTTP(pins []string) *http.Client {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots}
	if len(pins) > 0 {
		// Nur zusammen mit der Pin-Pruefung: die Kette zaehlt nicht, allein der Fingerabdruck des Leaf-Zertifikats.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return &errPinMismatch{got: "(none)"}
			}
			got := CertFingerprint(raw[0])
			if !slices.Contains(pins, got) {
				return &errPinMismatch{got: got}
			}
			return nil
		}
	}
	d := &net.Dialer{Timeout: c.dialTO, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil, // Proxmox steht im LAN, nie ueber einen Proxy
		DialContext:           d.DialContext,
		TLSClientConfig:       tc,
		TLSHandshakeTimeout:   c.dialTO,
		ResponseHeaderTimeout: c.reqTO,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		// Keine Weiterleitungen folgen (der Token-Header gehoert nur an die eingerichtete Adresse).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// httpFor waehlt den HTTP-Client einer Adresse: gelernte Adressen mit eigenen Pins bekommen einen eigenen Client,
// alle anderen den des Systems (Pin des Systems bzw. System-CA).
func (c *Client) httpFor(addr string) *http.Client {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h, ok := c.lhttp[addr]; ok {
		return h
	}
	return c.http
}

// Address ist die zuletzt funktionierende Adresse ("" vor dem ersten Erfolg).
func (c *Client) Address() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// learnedAddr macht aus einer Node-IP eine Adresse mit dem Port der ersten eingerichteten ("" = keine IP).
func (c *Client) learnedAddr(ip string) string {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return ""
	}
	port := DefaultPort
	if u, err := url.Parse(c.addrs[0]); err == nil && u.Port() != "" {
		port = u.Port()
	}
	return "https://" + net.JoinHostPort(ip, port)
}

// SetLearned uebernimmt Node-IPs aus cluster/status als weitere Adressen (Port wie die erste eingerichtete).
func (c *Client) SetLearned(ips []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var l []string
	for _, ip := range ips {
		a := c.learnedAddr(ip)
		if a != "" && !slices.Contains(c.addrs, a) && !slices.Contains(l, a) {
			l = append(l, a)
		}
	}
	c.learn = l
	for a := range c.lpins {
		if !slices.Contains(l, a) {
			c.dropPinsLocked(a)
		}
	}
	for a := range c.badTLS {
		if !slices.Contains(l, a) {
			delete(c.badTLS, a)
		}
	}
	if c.last != "" && !slices.Contains(c.addrs, c.last) && !slices.Contains(l, c.last) {
		c.last = ""
	}
}

// SetLearnedPins setzt die Fingerabdruecke je Node-IP (aus /nodes/{node}/certificates/info, Format egal) fuer die
// gelernten Adressen. Nur im Speicher, nie im System. IPs ohne Eintrag behalten ihren bisherigen Stand; eine leere
// Liste loescht die Pins der IP (dann gilt wieder der Pin des Systems bzw. die System-CA).
func (c *Client) SetLearnedPins(pins map[string][]string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for ip, raw := range pins {
		a := c.learnedAddr(ip)
		if a == "" || slices.Contains(c.addrs, a) {
			continue
		}
		var l []string
		for _, p := range raw {
			if n, ok := NormalizePin(p); ok && n != "" && !slices.Contains(l, n) {
				l = append(l, n)
			}
		}
		if len(l) == 0 {
			c.dropPinsLocked(a)
			continue
		}
		if strings.Join(l, ",") == strings.Join(c.lpins[a], ",") {
			continue
		}
		c.dropPinsLocked(a)
		c.lpins[a] = l
		c.lhttp[a] = c.buildHTTP(l)
		delete(c.badTLS, a) // neues Zertifikat bekannt: sofort wieder versuchen
	}
}

func (c *Client) dropPinsLocked(a string) {
	if h, ok := c.lhttp[a]; ok {
		h.CloseIdleConnections()
	}
	delete(c.lhttp, a)
	delete(c.lpins, a)
}

// order: zuletzt funktionierende zuerst, dann eingerichtete, dann gelernte (ohne solche mit unpassendem Zertifikat).
func (c *Client) order() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	var out []string
	if c.last != "" {
		out = append(out, c.last)
	}
	for _, a := range c.addrs {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	for _, a := range c.learn {
		if t, bad := c.badTLS[a]; bad && now.Sub(t) < pveCertBadPause {
			continue
		}
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

func (c *Client) isConfigured(a string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Contains(c.addrs, a)
}

// Get fragt path (relativ zu /api2/json, z. B. "/cluster/resources") ab und legt "data" in v ab.
// Netz-, Zeit-, Zertifikats- und Serverfehler (5xx) fuehren zur naechsten Adresse; 401/403/4xx nicht
// (der Token gilt im ganzen Cluster gleich).
func (c *Client) Get(ctx context.Context, path string, v any) error {
	var first, firstCfg *Error
	tried := 0
	for _, a := range c.order() {
		if ctx.Err() != nil {
			break
		}
		tried++
		err := c.getOne(ctx, a, path, v)
		if err == nil {
			c.mu.Lock()
			c.last = a
			delete(c.badTLS, a)
			c.mu.Unlock()
			return nil
		}
		cfg := c.isConfigured(a)
		if errors.Is(err.Kind, ErrCertMismatch) || errors.Is(err.Kind, ErrCertInvalid) {
			if !cfg {
				c.mu.Lock()
				c.badTLS[a] = c.now()
				c.mu.Unlock()
			}
		}
		if first == nil {
			first = err
		}
		if cfg && firstCfg == nil {
			firstCfg = err
		}
		if !pveFailover(err) {
			err.Others = tried - 1
			return err
		}
	}
	e := firstCfg
	if e == nil {
		e = first
	}
	if e == nil {
		if err := ctx.Err(); err != nil {
			return &Error{Kind: ErrTimeout, Detail: err.Error()}
		}
		return &Error{Kind: ErrUnreachable, Detail: "no address"}
	}
	e.Others = tried - 1
	return e
}

// getFirst fragt nur die zuletzt funktionierende Adresse (ohne Failover): fuer Anfragen, deren Fehler auf jedem Node
// gleich ausfallen (z. B. Gast-Agent nicht aktiv: 500).
func (c *Client) getFirst(ctx context.Context, path string, v any) error {
	o := c.order()
	if len(o) == 0 {
		return &Error{Kind: ErrUnreachable, Detail: "no address"}
	}
	if err := c.getOne(ctx, o[0], path, v); err != nil {
		return err
	}
	return nil
}

// failover: lohnt sich eine andere Adresse?
func pveFailover(e *Error) bool {
	switch {
	case errors.Is(e.Kind, ErrToken), errors.Is(e.Kind, ErrPermission):
		return false
	case e.Status >= 400 && e.Status < 500:
		return false
	}
	return true
}

// getOne ist eine Anfrage an genau eine Adresse.
func (c *Client) getOne(ctx context.Context, addr, path string, v any) *Error {
	ctx, cancel := context.WithTimeout(ctx, c.reqTO)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr+"/api2/json"+path, nil)
	if err != nil {
		return &Error{Kind: ErrResponse, Address: addr, Detail: err.Error()}
	}
	req.Header.Set("Authorization", c.auth)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "node64-proxmox")
	resp, err := c.httpFor(addr).Do(req)
	if err != nil {
		return pveClassify(addr, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, pveMaxBody+1))
	if err != nil {
		return pveClassify(addr, err)
	}
	if len(b) > pveMaxBody {
		return &Error{Kind: ErrResponse, Address: addr, Status: resp.StatusCode, Detail: "response too large"}
	}
	if resp.StatusCode != http.StatusOK {
		return pveStatusError(addr, resp, b)
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		return &Error{Kind: ErrResponse, Address: addr, Status: resp.StatusCode, Detail: "no JSON from proxmox api: " + pveShort(err.Error())}
	}
	if v != nil {
		if len(env.Data) == 0 || string(env.Data) == "null" {
			return &Error{Kind: ErrResponse, Address: addr, Status: resp.StatusCode, Detail: "answer without data"}
		}
		if err := json.Unmarshal(env.Data, v); err != nil {
			return &Error{Kind: ErrResponse, Address: addr, Status: resp.StatusCode, Detail: "unexpected data: " + pveShort(err.Error())}
		}
	}
	return nil
}

// statusError: Proxmox schreibt den Grund in die Statuszeile ("401 invalid token value!") und ggf. "errors" in den Body.
func pveStatusError(addr string, resp *http.Response, body []byte) *Error {
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)))
	if reason == http.StatusText(resp.StatusCode) {
		reason = ""
	}
	var env struct {
		Message string            `json:"message"`
		Errors  map[string]string `json:"errors"`
	}
	if json.Unmarshal(body, &env) == nil {
		if m := strings.TrimSpace(env.Message); m != "" && reason == "" {
			reason = m
		}
		for k, v := range env.Errors {
			reason = strings.TrimSpace(reason + " " + k + ": " + strings.TrimSpace(v))
		}
	}
	e := &Error{Kind: ErrResponse, Address: addr, Status: resp.StatusCode, Detail: pveShort(reason)}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		e.Kind = ErrToken
	case resp.StatusCode == http.StatusForbidden:
		e.Kind = ErrPermission
	case resp.StatusCode == 595 || resp.StatusCode == 596:
		// Proxmox erreicht einen Node nicht (Weiterleitung innerhalb des Clusters). Andere 5xx bleiben "HTTP 5xx";
		// beide fuehren zur naechsten Adresse.
		e.Kind = ErrUnreachable
	}
	return e
}

// classify ordnet Netz- und TLS-Fehler ein.
func pveClassify(addr string, err error) *Error {
	var pm *errPinMismatch
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &pm):
		return &Error{Kind: ErrCertMismatch, Address: addr, Detail: "got " + pm.got}
	case errors.As(err, &he):
		return &Error{Kind: ErrCertInvalid, Address: addr, Detail: "name does not match: " + pveShort(he.Error())}
	case errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &cv):
		return &Error{Kind: ErrCertInvalid, Address: addr, Detail: pveShort(pveUnwrapURL(err).Error())}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return &Error{Kind: ErrTimeout, Address: addr}
	case errors.Is(err, context.Canceled):
		return &Error{Kind: ErrUnreachable, Address: addr, Detail: "canceled"}
	}
	return &Error{Kind: ErrUnreachable, Address: addr, Detail: pveShort(pveUnwrapURL(err).Error())}
}

func pveUnwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

func pveShort(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200] + "…"
	}
	return s
}
