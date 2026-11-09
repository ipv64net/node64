package apis

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/proxmox"
)

// Gemeinsamer HTTP(S)-Client der JSON-APIs ohne eigenen Client (TrueNAS, Unraid, Redfish): nur die eingerichtete
// Adresse, keine Weiterleitungen (die Zugangsdaten gehoeren nur an sie), kein Proxy, Zeitlimits, Antwortgroesse
// begrenzt. TLS wie internal/proxmox: mit Pin zaehlt allein der Fingerabdruck des Leaf-Zertifikats (SHA-256 ueber
// das DER), ohne Pin gilt die System-CA mit Pruefung des Hostnamens.
//
// "Verbindung testen" (probeCert): erst das Zertifikat holen (auch ein ungueltiges); ohne Pin und ohne Vertrauen
// werden keine Zugangsdaten gesendet (NeedConfirm), nach der Bestaetigung testet der Assistent mit dem Fingerabdruck
// als Pin erneut.

const (
	webDialTimeout = 5 * time.Second  // Verbindungsaufbau inkl. TLS
	webReqTimeout  = 15 * time.Second // eine Anfrage (BMCs antworten oft langsam)
	webMaxBody     = 16 << 20         // groesste Antwort
	webMaxErrBody  = 64 << 10         // Fehlertext hoechstens so viel lesen
)

// Fehlerarten des Web-Clients (errors.Is).
var (
	errWebAuth    = errors.New("Anmeldung abgelehnt")
	errWebPerm    = errors.New("keine Berechtigung")
	errWebCert    = errors.New("Zertifikat passt nicht")
	errWebTrust   = errors.New("Zertifikat nicht vertrauenswürdig")
	errWebNet     = errors.New("nicht erreichbar")
	errWebTimeout = errors.New("Zeitlimit")
	errWebResp    = errors.New("unerwartete Antwort")
)

// webError ist der Fehler einer Anfrage (ohne Zugangsdaten: die stehen nur in Kopfzeilen).
type webError struct {
	Kind   error
	Status int    // HTTP-Status (0 = keine Antwort)
	Detail string // Text des Geraets bzw. aus dem Netz (gekuerzt)
	Where  string // Methode und Pfad
}

func (e *webError) Unwrap() error { return e.Kind }

func (e *webError) Error() string {
	var b strings.Builder
	switch {
	case e.Status != 0 && (errors.Is(e.Kind, errWebResp) || errors.Is(e.Kind, errWebAuth) || errors.Is(e.Kind, errWebPerm)):
		fmt.Fprintf(&b, "HTTP %d", e.Status)
		if !errors.Is(e.Kind, errWebResp) {
			b.WriteString(" " + e.Kind.Error())
		}
	default:
		b.WriteString(e.Kind.Error())
	}
	if e.Detail != "" {
		b.WriteString(" (" + e.Detail + ")")
	}
	if e.Where != "" {
		b.WriteString(" bei " + e.Where)
	}
	return b.String()
}

// webAbsent: die Abfrage gibt es auf diesem Geraet nicht (aeltere Version, Funktion fehlt) – kein Fehler.
func webAbsent(err error) bool {
	var we *webError
	if !errors.As(err, &we) {
		return false
	}
	switch we.Status {
	case 404, 405, 501:
		return true
	}
	return false
}

// webAuthErr: Zugangsdaten bzw. Rechte – liegt nicht an einer einzelnen Abfrage.
func webAuthErr(err error) bool { return errors.Is(err, errWebAuth) || errors.Is(err, errWebPerm) }

// webPinMismatch kommt aus VerifyPeerCertificate.
type webPinMismatch struct{ got string }

func (e *webPinMismatch) Error() string { return "Fingerabdruck " + e.got + " passt nicht zum Pin" }

// webTarget ist eine geprueft Adresse (scheme://host:port ohne Pfad).
type webTarget struct {
	base   string // https://host:port
	host   string // Hostname bzw. IP (ServerName, Zertifikat)
	hostPt string // host:port fuers Wählen
	https  bool
}

// parseWebAddr prueft eine Adresse: ohne Schema gilt defScheme, ohne Port der Standard des Schemas (bzw. defPort).
// Pfad, Abfrage und Benutzerangaben werden nicht angenommen (die Pfade kennt der Sammler).
func parseWebAddr(raw, defScheme, defPort string, allowHTTP bool) (webTarget, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return webTarget{}, errors.New("keine Adresse angegeben")
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is6() {
		s = "[" + a.String() + "]" // IPv6 ohne Klammern
	}
	if !strings.Contains(s, "://") {
		s = defScheme + "://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return webTarget{}, fmt.Errorf("ungültige Adresse %q", raw)
	}
	if p := strings.TrimRight(u.Path, "/"); p != "" {
		return webTarget{}, fmt.Errorf("ungültige Adresse %q (ohne Pfad angeben)", raw)
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https":
	case scheme == "http" && allowHTTP:
	default:
		if allowHTTP {
			return webTarget{}, fmt.Errorf("ungültige Adresse %q (http:// oder https://)", raw)
		}
		return webTarget{}, fmt.Errorf("ungültige Adresse %q (nur https://)", raw)
	}
	port := u.Port()
	if port == "" {
		port = defPort
		if port == "" {
			port = "443"
			if scheme == "http" {
				port = "80"
			}
		}
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return webTarget{}, fmt.Errorf("ungültiger Port in %q", raw)
	}
	host := strings.ToLower(u.Hostname())
	hp := net.JoinHostPort(host, port)
	return webTarget{base: scheme + "://" + hp, host: host, hostPt: hp, https: scheme == "https"}, nil
}

// pinnedTLS baut die TLS-Einstellung: pin leer = System-CA (roots nil) mit Hostname, sonst nur genau dieses
// Leaf-Zertifikat.
func pinnedTLS(serverName, pin string, roots *x509.CertPool) *tls.Config {
	tc := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: serverName}
	if pin != "" {
		// Nur zusammen mit der Pin-Pruefung: die Kette zaehlt nicht, allein der Fingerabdruck des Leaf-Zertifikats.
		tc.InsecureSkipVerify = true
		tc.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return &webPinMismatch{got: "(keins)"}
			}
			if got := proxmox.CertFingerprint(raw[0]); got != pin {
				return &webPinMismatch{got: got}
			}
			return nil
		}
	}
	return tc
}

// webClient spricht eine JSON-API an einer Adresse an (sicher fuer gleichzeitige Anfragen).
type webClient struct {
	t      webTarget
	pin    string
	roots  *x509.CertPool
	hc     *http.Client
	reqTO  time.Duration
	header func(h http.Header) // Zugangsdaten bzw. feste Kopfzeilen (nil = keine)
}

// newWebClient prueft den Pin und baut den Client (roots nil = System-CA; Tests geben eigene Wurzeln).
func newWebClient(t webTarget, pin string, roots *x509.CertPool) (*webClient, error) {
	p, ok := proxmox.NormalizePin(pin)
	if !ok {
		return nil, errors.New("Fingerabdruck muss 64 Hex-Zeichen haben (SHA-256)")
	}
	if p != "" && !t.https {
		return nil, errors.New("Fingerabdruck nur mit https://")
	}
	c := &webClient{t: t, pin: p, roots: roots, reqTO: webReqTimeout}
	d := &net.Dialer{Timeout: webDialTimeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 nil, // Geraete stehen im LAN, nie ueber einen Proxy
		DialContext:           d.DialContext,
		TLSClientConfig:       pinnedTLS(t.host, p, roots),
		TLSHandshakeTimeout:   webDialTimeout,
		ResponseHeaderTimeout: webReqTimeout,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     false,
	}
	c.hc = &http.Client{Transport: tr,
		// Keine Weiterleitungen folgen (Zugangsdaten gehoeren nur an die eingerichtete Adresse).
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return c, nil
}

// close gibt Leerlauf-Verbindungen frei.
func (c *webClient) close() { c.hc.CloseIdleConnections() }

// do sendet eine Anfrage (body nil = ohne Inhalt, sonst JSON) und legt die JSON-Antwort in out ab (nil = Antwort
// verwerfen). extra sind zusaetzliche Kopfzeilen dieser Anfrage. Liefert die Kopfzeilen der Antwort.
func (c *webClient) do(ctx context.Context, method, path string, extra http.Header, body any, out any) (http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, c.reqTO)
	defer cancel()
	where := method + " " + path
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, &webError{Kind: errWebResp, Detail: err.Error(), Where: where}
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.t.base+path, rd)
	if err != nil {
		return nil, &webError{Kind: errWebResp, Detail: shortText(err.Error()), Where: where}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "node64-monitor64")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.header != nil {
		c.header(req.Header)
	}
	for k, v := range extra {
		req.Header[k] = v
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, webClassify(err, where)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return resp.Header, &webError{Kind: errWebResp, Status: resp.StatusCode, Where: where,
			Detail: "Weiterleitung nach " + shortText(resp.Header.Get("Location")) + " – diese Adresse eintragen"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, webMaxErrBody))
		return resp.Header, webStatusError(resp.StatusCode, b, where)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, webMaxBody+1))
	if err != nil {
		return resp.Header, webClassify(err, where)
	}
	if len(b) > webMaxBody {
		return resp.Header, &webError{Kind: errWebResp, Status: resp.StatusCode, Detail: "Antwort zu groß", Where: where}
	}
	if out != nil {
		if len(bytes.TrimSpace(b)) == 0 {
			return resp.Header, &webError{Kind: errWebResp, Status: resp.StatusCode, Detail: "leere Antwort", Where: where}
		}
		if err := json.Unmarshal(b, out); err != nil {
			return resp.Header, &webError{Kind: errWebResp, Status: resp.StatusCode, Detail: "kein passendes JSON: " + shortText(err.Error()), Where: where}
		}
	}
	return resp.Header, nil
}

// get ist do mit GET.
func (c *webClient) get(ctx context.Context, path string, out any) error {
	_, err := c.do(ctx, http.MethodGet, path, nil, nil, out)
	return err
}

// webStatusError: Status mit dem Fehlertext des Geraets (JSON-Felder message/error bzw. Redfish error.message).
func webStatusError(status int, body []byte, where string) *webError {
	e := &webError{Kind: errWebResp, Status: status, Where: where}
	switch status {
	case http.StatusUnauthorized:
		e.Kind = errWebAuth
	case http.StatusForbidden:
		e.Kind = errWebPerm
	}
	var env struct {
		Message any `json:"message"`
		Error   any `json:"error"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"` // GraphQL
	}
	if json.Unmarshal(body, &env) == nil {
		gql := ""
		if len(env.Errors) > 0 {
			gql = env.Errors[0].Message
		}
		e.Detail = shortText(firstNonEmpty(jsonMsg(env.Message), jsonMsg(env.Error), gql))
	}
	return e
}

// jsonMsg holt einen Text aus einem Fehlerfeld (String oder Objekt mit message/@Message.ExtendedInfo).
func jsonMsg(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case map[string]any:
		if m, ok := x["message"].(string); ok && strings.TrimSpace(m) != "" {
			return strings.TrimSpace(m)
		}
		if l, ok := x["@Message.ExtendedInfo"].([]any); ok && len(l) > 0 {
			if mi, ok := l[0].(map[string]any); ok {
				if m, ok := mi["Message"].(string); ok {
					return strings.TrimSpace(m)
				}
			}
		}
	}
	return ""
}

// webClassify ordnet Netz- und TLS-Fehler ein.
func webClassify(err error, where string) *webError {
	var pm *webPinMismatch
	var ua x509.UnknownAuthorityError
	var he x509.HostnameError
	var ci x509.CertificateInvalidError
	var cv *tls.CertificateVerificationError
	var ne net.Error
	switch {
	case errors.As(err, &pm):
		return &webError{Kind: errWebCert, Detail: "erhalten " + pm.got, Where: where}
	case errors.As(err, &he), errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &cv):
		return &webError{Kind: errWebTrust, Detail: shortText(unwrapURL(err).Error()), Where: where}
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return &webError{Kind: errWebTimeout, Where: where}
	case errors.Is(err, context.Canceled):
		return &webError{Kind: errWebNet, Detail: "abgebrochen", Where: where}
	}
	return &webError{Kind: errWebNet, Detail: shortText(unwrapURL(err).Error()), Where: where}
}

func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err
	}
	return err
}

// shortText kuerzt Texte von Geraeten (Fehlermeldungen) auf eine Zeile und 200 Zeichen.
func shortText(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 200 {
		return string(r[:200]) + "…"
	}
	return s
}

// probeCert holt das Zertifikat fuer "Verbindung testen" und fuellt Fingerabdruck, Subject, Vertrauen. proceed false:
// keine Zugangsdaten senden (Fehler bzw. NeedConfirm in res). http:// ohne Zertifikat: weiter mit Hinweis.
func probeCert(ctx context.Context, t webTarget, pin string, roots *x509.CertPool) (res TestResult, proceed bool) {
	if !t.https {
		res.Warning = "unverschlüsselt (http://) – Zugangsdaten gehen im Klartext durchs Netz, https:// empfohlen"
		return res, true
	}
	leaf, trusted, err := fetchLeaf(ctx, t.hostPt, t.host, roots)
	if err != nil {
		res.Error = err.Error()
		return res, false
	}
	return certResult(leaf, trusted, pin)
}

// certResult bewertet ein geholtes Zertifikat gegen Pin und Vertrauen.
func certResult(leaf *x509.Certificate, trusted bool, pin string) (res TestResult, proceed bool) {
	res.Fingerprint = proxmox.CertFingerprint(leaf.Raw)
	res.CertSubject = leaf.Subject.String()
	res.Trusted = trusted
	p, _ := proxmox.NormalizePin(pin)
	switch {
	case p != "" && p != res.Fingerprint:
		res.Error = "Zertifikat passt nicht – Fingerabdruck " + res.Fingerprint + " statt des gemerkten (neues Zertifikat bestätigen?)"
		return res, false
	case p == "" && !trusted:
		res.NeedConfirm = true // Zugangsdaten nie an ein unbestaetigtes Zertifikat
		return res, false
	}
	return res, true
}

// fetchLeaf holt das Leaf-Zertifikat ohne Pruefung (nur zum Anzeigen; ueber diese Verbindung geht nichts) und prueft
// es danach selbst gegen die CA.
func fetchLeaf(ctx context.Context, hostPort, serverName string, roots *x509.CertPool) (*x509.Certificate, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, webDialTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: webDialTimeout},
		Config: &tls.Config{InsecureSkipVerify: true, ServerName: serverName, MinVersion: tls.VersionTLS12}}
	c, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, false, webClassify(err, hostPort)
	}
	defer c.Close()
	return leafOf(c.(*tls.Conn).ConnectionState(), serverName, roots, hostPort)
}

// leafOf liefert das Leaf-Zertifikat einer TLS-Verbindung und ob die CA (roots nil = System) es bestaetigt.
func leafOf(st tls.ConnectionState, serverName string, roots *x509.CertPool, where string) (*x509.Certificate, bool, error) {
	if len(st.PeerCertificates) == 0 {
		return nil, false, &webError{Kind: errWebTrust, Detail: "kein Zertifikat", Where: where}
	}
	leaf := st.PeerCertificates[0]
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: serverName, Roots: roots, Intermediates: inter})
	return leaf, verr == nil, nil
}

// finite: Zahl von einem Geraet nur, wenn endlich (NaN/Inf verwerfen).
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// optF ist eine Zahl aus JSON, die fehlen, null oder ein String sein darf (Set false = nicht vorhanden).
type optF struct {
	V   float64
	Set bool
}

func (n *optF) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(strings.Trim(strings.TrimSpace(string(b)), `"`))
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || !finite(f) {
		*n = optF{}
		return nil
	}
	*n = optF{V: f, Set: true}
	return nil
}

// ptr liefert einen Zeiger auf v, wenn gesetzt (fuer Ausgaben).
func (n optF) ptr() *float64 {
	if !n.Set {
		return nil
	}
	v := n.V
	return &v
}

// stripTags entfernt HTML-Markup aus Texten von Geraeten (TrueNAS-Alarme enthalten Links) und kuerzt sie.
func stripTags(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>' && in:
			in = false
			b.WriteByte(' ')
		case !in:
			b.WriteRune(r)
		}
	}
	return shortText(strings.NewReplacer("&nbsp;", " ", "&amp;", "&", "&lt;", "<", "&gt;", ">", "&quot;", `"`, "&#39;", "'").Replace(b.String()))
}

// hintPartial sammelt Teilfehler und ergaenzt sie um Hinweise des Sammlers (z. B. noetige Rolle).
type hintPartial struct {
	*partial
	hint func(error) error
}

func (h hintPartial) add(what string, err error, prefixes ...string) {
	if err == nil {
		return
	}
	h.partial.add(what, h.hint(err), prefixes...)
}
