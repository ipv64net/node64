package promscrape

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/apis"
	"github.com/ipv64net/node64/internal/proxmox"
)

// Abfrage per HTTP(S). TLS wie bei den API-Zugaengen (internal/proxmox): mit Pin zaehlt allein der Fingerabdruck
// (SHA-256 des Leaf-Zertifikats); ohne Pin muss das Zertifikat der System-CA samt Hostname passen. Ein unbekanntes
// Zertifikat bricht den Handshake ab, bevor Zugangsdaten gesendet werden (Test zeigt den Fingerabdruck zur
// Bestaetigung). Keine Weiterleitungen, kein Proxy, gzip mit Grenze nach dem Entpacken.

const (
	userAgent = "node64-monitor64"
	acceptHdr = "text/plain;version=0.0.4;q=1,application/openmetrics-text;version=1.0.0;q=0.5,*/*;q=0.1"
)

// Fehler der Abfrage.
var (
	// ErrUnconfirmed: Zertifikat nicht vertrauenswuerdig und kein Pin – erst Fingerabdruck bestaetigen.
	ErrUnconfirmed = errors.New("Zertifikat nicht bestätigt – Fingerabdruck prüfen und übernehmen")
	ErrPinMismatch = errors.New("Zertifikat geändert – Fingerabdruck passt nicht zum gespeicherten")
	ErrAuth        = errors.New("Anmeldung abgelehnt – Benutzer/Passwort bzw. Token prüfen")
	ErrNoMetrics   = errors.New("keine Prometheus-Metriken in der Antwort – Adresse/Pfad prüfen (Standard /metrics)")
)

// certInfo ist das zuletzt gesehene Zertifikat (fuer Test).
type certInfo struct {
	fp, subject string
	trusted     bool
}

// fetcher fragt eine Adresse ab (sicher fuer gleichzeitige Aufrufe).
type fetcher struct {
	url     string
	auth    string // Wert des Authorization-Headers ("" = keiner)
	hc      *http.Client
	maxBody int

	mu   sync.Mutex
	cert certInfo
}

// NormalizeURL macht aus einer Eingabe eine Abfrage-Adresse: ohne Schema http:// und Port defPort, ohne Pfad
// /metrics. Zugangsdaten in der Adresse sind nicht erlaubt (gehoeren ins Geheimnis).
func NormalizeURL(s string, defPort int) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("Adresse fehlt")
	}
	bare := !strings.Contains(s, "://")
	if bare {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("ungültige Adresse %q", clip(s, 200))
	}
	if u.User != nil {
		return "", errors.New("Zugangsdaten nicht in die Adresse schreiben (Benutzer und Passwort bzw. Token gehören in die Zugangsdaten)")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("nur http:// oder https:// (nicht %q)", u.Scheme)
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("ungültiger Port %q", p)
		}
	} else if bare && defPort > 0 {
		u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(defPort))
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/metrics"
	}
	u.Fragment = ""
	return u.String(), nil
}

// newFetcher baut den HTTP-Client. roots nil = System-CA (Tests geben eigene Wurzeln).
func newFetcher(rawURL, user, secret, pin string, timeout time.Duration, maxBody int, roots *x509.CertPool) (*fetcher, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	pin, ok := proxmox.NormalizePin(pin)
	if !ok {
		return nil, errors.New("Fingerabdruck muss 64 Hex-Zeichen haben (SHA-256)")
	}
	f := &fetcher{url: rawURL, maxBody: maxBody}
	switch {
	case user != "":
		f.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+secret))
	case secret != "":
		f.auth = "Bearer " + secret
	}
	host := u.Hostname()
	tc := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, //nolint:gosec // eigene Pruefung unten
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPinMismatch
			}
			fp := proxmox.CertFingerprint(raw[0])
			ci := certInfo{fp: fp}
			if leaf, err := x509.ParseCertificate(raw[0]); err == nil {
				ci.subject = clip(leaf.Subject.String(), 200)
				var inter []*x509.Certificate
				for _, r := range raw[1:] {
					if c, err := x509.ParseCertificate(r); err == nil {
						inter = append(inter, c)
					}
				}
				ci.trusted = apis.CertTrusted(leaf, inter, host, roots)
			}
			f.mu.Lock()
			f.cert = ci
			f.mu.Unlock()
			switch {
			case pin != "" && fp != pin:
				return ErrPinMismatch
			case pin == "" && !ci.trusted:
				return ErrUnconfirmed
			}
			return nil
		}}
	// gemeinsamer Client der Zugaenge (kein Proxy, keine Weiterleitungen); gzip selbst entpacken (mit Grenze)
	f.hc = apis.HTTPClient(tc, timeout, 1, true)
	return f, nil
}

// lastCert liefert das zuletzt gesehene Zertifikat.
func (f *fetcher) lastCert() certInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cert
}

func (f *fetcher) close() { f.hc.CloseIdleConnections() }

// fetch holt die Antwort (entpackt, hoechstens maxBody Bytes).
func (f *fetcher) fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", acceptHdr)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", userAgent)
	if d, ok := ctx.Deadline(); ok {
		if s := time.Until(d).Seconds(); s > 0 {
			req.Header.Set("X-Prometheus-Scrape-Timeout-Seconds", strconv.FormatFloat(s, 'f', 1, 64))
		}
	}
	if f.auth != "" {
		req.Header.Set("Authorization", f.auth)
	}
	resp, err := f.hc.Do(req)
	if err != nil {
		return nil, netError(ctx, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, fmt.Errorf("%w (HTTP %d)", ErrAuth, resp.StatusCode)
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, fmt.Errorf("HTTP %d – Weiterleitungen werden nicht verfolgt, Adresse direkt eintragen", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return nil, errors.New("HTTP 404 – Pfad prüfen (Standard /metrics)")
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "protobuf") {
		return nil, errors.New("Antwort im Protobuf-Format – nur das Textformat wird unterstützt")
	}
	var r io.Reader = io.LimitReader(resp.Body, int64(f.maxBody)+1)
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %v", err)
		}
		defer gz.Close()
		r = io.LimitReader(gz, int64(f.maxBody)+1) // Grenze nach dem Entpacken (gzip-Bombe)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, netError(ctx, err)
	}
	if len(b) > f.maxBody {
		return nil, fmt.Errorf("%w (mehr als %d MB)", ErrTooLarge, f.maxBody>>20)
	}
	return b, nil
}

// netError macht aus Netz- und TLS-Fehlern kurze Texte (ohne URL mit Abfrage-Parametern).
func netError(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, ErrUnconfirmed):
		return ErrUnconfirmed
	case errors.Is(err, ErrPinMismatch):
		return ErrPinMismatch
	case errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded:
		return errors.New("Zeitlimit – keine Antwort")
	case errors.Is(err, context.Canceled):
		return context.Canceled
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errors.New("Zeitlimit – keine Antwort")
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Op == "dial" && oe.Err != nil {
		return fmt.Errorf("nicht erreichbar (%s)", clip(oe.Err.Error(), 120))
	}
	return errors.New(clip(err.Error(), 200))
}
