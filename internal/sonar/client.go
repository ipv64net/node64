package sonar

// HTTP zur API v2 von ipv64 (Vertrag Abschnitt 3). Antworten werden nur bis zu einer festen Groesse gelesen,
// Anfragen haben ein Zeitlimit, Weiterleitungen werden nicht verfolgt (Token bleibt beim Ziel).
// ipv64 kennt die IP eines Knotens nur aus der Verbindung, je Familie getrennt. Mit dem eingebauten HTTP-Client gehen
// die Anfragen deshalb abwechselnd ueber IPv4 und IPv6; klappt der Verbindungsaufbau in einer Familie nicht, wird die
// Anfrage normal (ohne feste Familie) wiederholt. Sonst kaeme ein Knoten mit IPv4 und IPv6 nur mit IPv6 in die Plaene.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
)

// Lesegrenzen fuer Antworten.
const (
	smallLimit      = 64 << 10 // me, register, tokens, results
	listLimit       = 2 << 20  // inbound (500 Zeilen)
	planLimitNode   = 1 << 20
	planLimitAnchor = 8 << 20 // Anker: bis 2.000 Ziele je Runde
	maxBody         = 250 << 10
	requestTimeout  = 30 * time.Second
	famDialTimeout  = 5 * time.Second // Verbindungsaufbau mit fester Familie, danach ohne
)

// APIError ist eine Fehlerantwort (RFC 9457) oder ein unerwarteter HTTP-Status.
type APIError struct {
	Status     int
	Code       string
	Detail     string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("ipv64: %s (%d)", e.Detail, e.Status)
	}
	return fmt.Sprintf("ipv64: HTTP %d", e.Status)
}

// client spricht die API v2 an.
type client struct {
	base string
	http HTTPDoer
	fam  [2]HTTPDoer // nur mit dem eingebauten Client: nur IPv4, nur IPv6 (sonst nil)
	n    atomic.Uint32
	ua   string
}

func defaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout:       requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// familyHTTPClients sind zwei Clients, die nur ueber IPv4 bzw. nur ueber IPv6 verbinden.
func familyHTTPClients() [2]HTTPDoer {
	var out [2]HTTPDoer
	for i, network := range []string{"tcp4", "tcp6"} {
		d := &net.Dialer{Timeout: famDialTimeout}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = func(ctx context.Context, _, addr string) (net.Conn, error) { return d.DialContext(ctx, network, addr) }
		c := defaultHTTPClient()
		c.Transport = tr
		out[i] = c
	}
	return out
}

// do schickt req abwechselnd ueber IPv4 und IPv6 (falls eingerichtet). Scheitert nur der Verbindungsaufbau, geht die
// Anfrage noch einmal ohne feste Familie (sie wurde dann nicht gesendet, auch ein POST ist also nicht doppelt).
func (c *client) do(req *http.Request, body []byte) (*http.Response, error) {
	f := c.fam[c.n.Add(1)%2]
	if f == nil {
		return c.http.Do(req)
	}
	resp, err := f.Do(req)
	var op *net.OpError
	if err == nil || !errors.As(err, &op) || op.Op != "dial" || req.Context().Err() != nil {
		return resp, err
	}
	req = req.Clone(req.Context())
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	return c.http.Do(req)
}

// checkBase prueft die API-Adresse: https, oder http nur zu Loopback (Tests). Leer = DefaultAPIBase.
func checkBase(base string) (string, error) {
	if base == "" {
		return DefaultAPIBase, nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("sonar: invalid API base")
	}
	switch u.Scheme {
	case "https":
	case "http":
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("sonar: API base must use https")
		}
	default:
		return "", errors.New("sonar: API base must use https")
	}
	return strings.TrimRight(base, "/"), nil
}

// response ist eine gelesene Antwort.
type response struct {
	status int
	header http.Header
	body   []byte
}

// send schickt eine Anfrage (body nil = ohne) und liest hoechstens limit Byte Antwort.
func (c *client) send(ctx context.Context, method, path, token string, hdr http.Header, body []byte, limit int64) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	resp, err := c.do(req, body)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, errors.New("ipv64: timeout")
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("ipv64 not reachable")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, errors.New("ipv64: read error")
	}
	if int64(len(b)) > limit {
		return nil, errors.New("ipv64: answer too large")
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: b}, nil
}

// apiError baut den Fehler aus einer Nicht-2xx-Antwort.
func apiError(r *response) *APIError {
	e := &APIError{Status: r.status}
	var p struct {
		Code   string `json:"code"`
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(r.body, &p) == nil {
		e.Code = cleanText(p.Code, 40)
		e.Detail = cleanText(p.Detail, 160)
		if e.Detail == "" {
			e.Detail = cleanText(p.Title, 160)
		}
	}
	if s := r.header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
			e.RetryAfter = time.Duration(min(n, 86400)) * time.Second
		}
	}
	return e
}

// unwrap liest data aus { "data": … } in out.
func unwrap(b []byte, out any) error {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err != nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return errors.New("ipv64: unexpected answer")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return errors.New("ipv64: unexpected answer")
	}
	return nil
}

// call schickt in als JSON (nil = ohne Body) und liest data in out (nil = egal).
func (c *client) call(ctx context.Context, method, path, token string, in any, limit int64, out any) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	r, err := c.send(ctx, method, path, token, nil, body, limit)
	if err != nil {
		return err
	}
	if r.status < 200 || r.status > 299 {
		return apiError(r)
	}
	if out == nil {
		return nil
	}
	return unwrap(r.body, out)
}

// cleanText kuerzt Server-Text fuer Log und Status und entfernt Steuerzeichen.
func cleanText(s string, n int) string {
	var b strings.Builder
	for _, c := range s {
		if b.Len() >= n {
			break
		}
		if unicode.IsPrint(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// errText ist ein Fehler als kurzer Text fuer Status.LastError.
func errText(err error) string { return cleanText(err.Error(), 200) }
