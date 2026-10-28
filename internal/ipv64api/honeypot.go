package ipv64api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Honeypot64 (Phase H2): Meldung eines Sensors an ipv64, POST /honeypot/reports. Das Format (schema 1) steht in
// internal/honeypot/report_types.go; dieses Paket kennt es nicht (sonst Importzyklus) und schickt den fertigen,
// gzip-gepackten JSON-Body.

// HoneypotResult ist die Antwort auf eine Meldung: 202 angenommen oder 200 schon bekannt (Duplicate).
type HoneypotResult struct {
	Status          int            `json:"-"`
	Accepted        int            `json:"accepted"`
	Rejected        int            `json:"rejected"`         // einzeln verworfene Quellen (Meldung trotzdem 202)
	RejectedReasons map[string]int `json:"rejected_reasons"` // Grund -> Anzahl (z. B. not_public)
	Duplicate       bool           `json:"duplicate"`
	ReportID        string         `json:"report_id"`
	PeriodEnd       int64          `json:"period_end,omitempty"` // bei Duplicate: Ende des bei ipv64 gespeicherten Zeitraums (Unix)
}

// maxRetryAfter begrenzt eine Wartezeit aus Retry-After (Schutz vor unsinnigen Werten).
const maxRetryAfter = 24 * time.Hour

// HoneypotReport schickt eine Meldung (gz: gzip-gepacktes JSON). 200/202 liefern das Ergebnis; jede andere Antwort
// kommt als *APIError mit Status (und RetryAfter bei 429/503), Netzfehler als gewoehnlicher Fehler.
func (c *Client) HoneypotReport(ctx context.Context, key string, gz []byte) (*HoneypotResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/honeypot/reports", bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	c.setNode(req)
	resp, err := c.http.Do(req)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, errors.New("ipv64: timeout")
		}
		return nil, fmt.Errorf("ipv64 not reachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		e := &APIError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
		var p struct {
			Detail string `json:"detail"`
			Code   string `json:"code"`
			Error  any    `json:"error"`
		}
		if json.Unmarshal(body, &p) == nil {
			e.Detail, e.Code = p.Detail, p.Code
			if e.Detail == "" {
				switch v := p.Error.(type) {
				case string:
					e.Detail = v
				case map[string]any: // {"error": {"code": ..., "message": ...}}
					if s, ok := v["message"].(string); ok {
						e.Detail = s
					}
					if s, ok := v["code"].(string); ok && e.Code == "" {
						e.Code = s
					}
				}
			}
		}
		return nil, e
	}
	out := &HoneypotResult{Status: resp.StatusCode}
	// API v2 packt Antworten in {"data": ...}; ohne Huelle auch direkt lesbar
	env := struct {
		Data json.RawMessage `json:"data"`
	}{}
	raw := body
	if json.Unmarshal(body, &env) == nil && len(env.Data) > 0 && env.Data[0] == '{' {
		raw = env.Data
	}
	_ = json.Unmarshal(raw, out) // Inhalt nur zur Anzeige; der Status entscheidet
	out.Status = resp.StatusCode
	if resp.StatusCode == http.StatusOK {
		out.Duplicate = true // 200 = report_id schon bekannt (Vertrag)
	}
	return out, nil
}

// parseRetryAfter liest Retry-After (Sekunden oder HTTP-Datum); 0 = keine Angabe.
func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	var d time.Duration
	if n, err := strconv.Atoi(v); err == nil {
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		return 0
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d
}
