package checks

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HTTPParams gelten fuer die Typen http und keyword.
type HTTPParams struct {
	Method          string            `json:"method,omitempty"` // Standard GET
	Headers         map[string]string `json:"headers,omitempty"`
	Body            string            `json:"body,omitempty"`
	BasicUser       string            `json:"basic_user,omitempty"`
	BasicPassword   string            `json:"basic_password,omitempty"`
	AcceptStatus    string            `json:"accept_status,omitempty"`    // "200-299,301" Standard 200-299
	FollowRedirects *bool             `json:"follow_redirects,omitempty"` // Standard true
	MaxRedirects    int               `json:"max_redirects,omitempty"`    // Standard 5
	InsecureTLS     bool              `json:"insecure_tls,omitempty"`     // Zertifikatsfehler ignorieren
	Keyword         string            `json:"keyword,omitempty"`          // nur keyword
	KeywordAbsent   bool              `json:"keyword_absent,omitempty"`   // true = Begriff darf NICHT vorkommen
	CertMinDays     int               `json:"cert_min_days,omitempty"`    // HTTPS: gestoert, wenn das Zertifikat in weniger Tagen ablaeuft (0 = aus)
}

type httpChecker struct{ keyword bool }

func (c *httpChecker) Type() Type {
	if c.keyword {
		return TypeKeyword
	}
	return TypeHTTP
}

func parseURL(s string) (*url.URL, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "://") {
		s = "http://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, errors.New("url scheme must be http or https")
	}
	return u, nil
}

func (c *httpChecker) Check(ctx context.Context, def Definition, ip net.IP) Result {
	var p HTTPParams
	if err := decode(def.Params, &p); err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	u, err := parseURL(def.Target)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	ranges, err := parseStatusRanges(p.AcceptStatus)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		method = http.MethodGet
	}
	maxRedirects := p.MaxRedirects
	if maxRedirects <= 0 {
		maxRedirects = 5
	}
	follow := p.FollowRedirects == nil || *p.FollowRedirects

	origHost := u.Hostname()
	family := "tcp4"
	if ip.To4() == nil {
		family = "tcp6"
	}
	dialer := &net.Dialer{Timeout: def.Timeouts.Connect}
	transport := &http.Transport{
		Proxy: nil,
		// Der Ursprungs-Host wird an die aufgeloeste Adresse gebunden, Redirect-
		// Ziele werden in derselben Adressfamilie aufgeloest.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			if strings.EqualFold(host, origHost) {
				return dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
			}
			return dialer.DialContext(ctx, family, addr)
		},
		TLSClientConfig:        &tls.Config{InsecureSkipVerify: p.InsecureTLS, MinVersion: tls.VersionTLS12}, //nolint:gosec // bewusst per Option
		TLSHandshakeTimeout:    def.Timeouts.Connect,
		ResponseHeaderTimeout:  def.Timeouts.Total,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !follow {
				return http.ErrUseLastResponse
			}
			if len(via) >= maxRedirects {
				return errTooManyRedirects
			}
			return nil
		},
	}
	var body io.Reader
	if p.Body != "" {
		body = strings.NewReader(p.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fail(ReasonInvalid, err.Error(), 0, nil)
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "*/*")
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	if p.BasicUser != "" || p.BasicPassword != "" {
		req.SetBasicAuth(p.BasicUser, p.BasicPassword)
	}

	details := map[string]any{"url": u.String(), "method": method}
	start := time.Now()
	resp, err := client.Do(req)
	lat := time.Since(start)
	if err != nil {
		if errors.Is(err, errTooManyRedirects) {
			return fail(ReasonTooManyRedirect, fmt.Sprintf("more than %d redirects", maxRedirects), lat, details)
		}
		if isTimeout(err) {
			return fail(ReasonTimeout, "timeout after "+lat.Round(time.Millisecond).String(), lat, details)
		}
		var tlsErr *tls.CertificateVerificationError
		if errors.As(err, &tlsErr) || strings.Contains(err.Error(), "tls:") || strings.Contains(err.Error(), "x509:") {
			return fail(ReasonTLSFailed, shortErr(err), lat, details)
		}
		return fail(ReasonConnectFailed, shortErr(err), lat, details)
	}
	defer resp.Body.Close()
	details["status"] = resp.StatusCode
	details["final_url"] = resp.Request.URL.String()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		details["tls_version"] = tls.VersionName(resp.TLS.Version)
		crt := resp.TLS.PeerCertificates[0]
		details["cert_not_after"] = crt.NotAfter.UTC().Format(time.RFC3339)
		details["cert_days_left"] = int(time.Until(crt.NotAfter).Hours() / 24)
		details["cert_issuer"] = crt.Issuer.CommonName
	}
	// Body nur lesen, wenn er gebraucht wird (Keyword), sonst nur Kopf
	var text string
	if c.keyword {
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
		lat = time.Since(start)
		if err != nil && !isTimeout(err) {
			return fail(ReasonConnectFailed, "reading body: "+shortErr(err), lat, details)
		}
		if err != nil {
			return fail(ReasonTimeout, "timeout while reading body", lat, details)
		}
		text = string(b)
		details["body_bytes"] = len(b)
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	}
	if !statusAccepted(resp.StatusCode, ranges) {
		return fail(ReasonStatusMismatch, fmt.Sprintf("HTTP %d not in accepted %s", resp.StatusCode, orDefault(p.AcceptStatus, "200-299")), lat, details)
	}
	if c.keyword {
		found := strings.Contains(text, p.Keyword)
		details["keyword_found"] = found
		if p.KeywordAbsent && found {
			return fail(ReasonKeywordPresent, fmt.Sprintf("keyword %q found but must be absent", p.Keyword), lat, details)
		}
		if !p.KeywordAbsent && !found {
			return fail(ReasonKeywordMissing, fmt.Sprintf("keyword %q not found", p.Keyword), lat, details)
		}
	}
	msg := "HTTP " + strconv.Itoa(resp.StatusCode)
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		na := resp.TLS.PeerCertificates[0].NotAfter
		days := int(time.Until(na).Hours() / 24)
		if p.CertMinDays > 0 && days < p.CertMinDays {
			return fail(ReasonCertExpiring, fmt.Sprintf("certificate expires in %d days (%s)", days, na.UTC().Format("2006-01-02")), lat, details)
		}
		// Datum in der Meldung: so kommt es auch bei Online-Checks (nur Meldung) an Node und Portal
		msg += fmt.Sprintf(", cert valid until %s (%d days)", na.UTC().Format("2006-01-02"), days)
	}
	return ok(msg, lat, details)
}

var errTooManyRedirects = errors.New("too many redirects")

func orDefault(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

// shortErr kuerzt die oft verschachtelten Go-Netzfehler auf den Kern.
func shortErr(err error) string {
	s := err.Error()
	for _, sep := range []string{": dial tcp", ": Get \"", ": Head \"", ": Post \""} {
		if i := strings.Index(s, sep); i > 0 {
			s = s[i+2:]
		}
	}
	if i := strings.LastIndex(s, ": "); i >= 0 && strings.Count(s, ": ") > 1 {
		s = s[i+2:]
	}
	return s
}
