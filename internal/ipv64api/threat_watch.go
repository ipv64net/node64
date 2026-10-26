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
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Fruehwarnung fuer eigene Netze (Honeypot64, Phase H5): die Netze liegen bei ipv64 und werden dort nach jeder
// Bewertung geprueft; die Node verwaltet sie und holt Treffer ab (GET/POST/DELETE /threat/watch,
// GET /threat/watch/alerts). Fehler kommen immer als *APIError (auch 401, errors.Is(err, ErrUnauthorized) gilt
// trotzdem), Netzfehler als gewoehnlicher Fehler.

// threatWatchTimeout begrenzt jeden Aufruf (zusaetzlich zum Zeitlimit des HTTP-Clients).
const threatWatchTimeout = 20 * time.Second

// ThreatWatchLimits sind die Grenzen des Accounts (Anzahl Netze, kleinstes erlaubtes Praefix je Familie).
type ThreatWatchLimits struct {
	Max         int `json:"max"`
	MinPrefixV4 int `json:"min_prefix_v4"` // z. B. 16 = hoechstens /16
	MinPrefixV6 int `json:"min_prefix_v6"`
}

// ThreatWatchNetwork ist ein eingetragenes Netz. Ohne Nachweis (Verified false) meldet ipv64 nur gelistete IPs.
type ThreatWatchNetwork struct {
	ID        int64  `json:"id"`
	CIDR      string `json:"cidr"`
	Label     string `json:"label"`
	Verified  bool   `json:"verified"`
	CreatedAt string `json:"created_at"` // RFC 3339 (als Text, damit ein abweichendes Format nicht alles bricht)
}

// ThreatWatchDynDNS ist eine automatisch ueberwachte (nachgewiesene) DynDNS-IP des Accounts.
type ThreatWatchDynDNS struct {
	IP     string `json:"ip"`
	Domain string `json:"domain"`
}

// ThreatWatch ist die Antwort auf GET /threat/watch.
type ThreatWatch struct {
	Limits   ThreatWatchLimits    `json:"limits"`
	Networks []ThreatWatchNetwork `json:"networks"`
	DynDNS   []ThreatWatchDynDNS  `json:"dyndns"`
}

// ThreatWatchAlert ist ein Treffer: eine IP eines eigenen Netzes bzw. einer DynDNS-IP ist als Angreifer aufgefallen.
type ThreatWatchAlert struct {
	ID        int64    `json:"id"`
	IP        string   `json:"ip"`
	CIDR      string   `json:"cidr"`
	NetworkID *int64   `json:"network_id"` // nil bei DynDNS
	Source    string   `json:"source"`     // network oder dyndns
	Listed    bool     `json:"listed"`     // auf der v64 Blocklist
	Score     int      `json:"score"`      // 0–100
	Kinds     []string `json:"kinds"`      // z. B. ssh:bruteforce
	FirstSeen string   `json:"first_seen"`
	LastSeen  string   `json:"last_seen"`
	CreatedAt string   `json:"created_at"`
	// Details: warum die IP aufgefallen ist (nil bei aelteren Treffern bzw. aelterem Server)
	Details *ThreatWatchDetails `json:"details,omitempty"`
}

// ThreatWatchDetails: Anzahlen und je Herkunft, Dienst, Port, Art und Regel (letzte 14 Tage, nie Sensoren oder Inhalte).
type ThreatWatchDetails struct {
	Accounts int               `json:"accounts"`
	Sensors  int               `json:"sensors"`
	Events   int64             `json:"events"`
	Lists    []string          `json:"lists,omitempty"`
	Reason   string            `json:"reason,omitempty"`
	Seen     []ThreatWatchSeen `json:"seen,omitempty"`
}

// ThreatWatchSeen ist eine Zeile der Details (die haeufigsten zuerst).
type ThreatWatchSeen struct {
	Origin  string `json:"origin"` // honeypot, log, syslog
	Service string `json:"service"`
	Port    int    `json:"port"`
	Kind    string `json:"kind"`
	Rule    string `json:"rule,omitempty"`
	Count   int64  `json:"count"`
	Sensors int    `json:"sensors"`
	Last    string `json:"last,omitempty"`
}

// ThreatWatchAlerts ist eine Seite Treffer (aelteste zuerst, hoechstens ThreatWatchPage); Next ist der Stand fuer
// den naechsten Abruf (unveraendert als since zurueckgeben).
type ThreatWatchAlerts struct {
	Alerts []ThreatWatchAlert `json:"alerts"`
	Next   string             `json:"next"`
}

// ThreatWatchPage ist die groesste Seite der Treffer laut Vertrag.
const ThreatWatchPage = 100

// ThreatWatchList liefert Grenzen, eigene Netze und automatisch ueberwachte DynDNS-IPs.
func (c *Client) ThreatWatchList(ctx context.Context, key string) (*ThreatWatch, error) {
	out := &ThreatWatch{}
	if err := c.watchDo(ctx, http.MethodGet, key, "/threat/watch", nil, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ThreatWatchAdd traegt ein Netz ein (201). Fehler laut Vertrag: 422 invalid_cidr, prefix_too_large, not_public;
// 409 duplicate; 403 limit_reached.
func (c *Client) ThreatWatchAdd(ctx context.Context, key, cidr, label string) (*ThreatWatchNetwork, error) {
	out := &ThreatWatchNetwork{}
	in := map[string]string{"cidr": cidr, "label": label}
	if err := c.watchDo(ctx, http.MethodPost, key, "/threat/watch", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

// ThreatWatchDelete entfernt ein Netz (204; 404 = nicht vorhanden).
func (c *Client) ThreatWatchDelete(ctx context.Context, key string, id int64) error {
	return c.watchDo(ctx, http.MethodDelete, key, "/threat/watch/"+strconv.FormatInt(id, 10), nil, nil)
}

// ThreatWatchAlerts liefert die Treffer seit since (leer = von Anfang an).
func (c *Client) ThreatWatchAlerts(ctx context.Context, key, since string) (*ThreatWatchAlerts, error) {
	path := "/threat/watch/alerts"
	if since != "" {
		path += "?since=" + url.QueryEscape(since)
	}
	out := &ThreatWatchAlerts{}
	if err := c.watchDo(ctx, http.MethodGet, key, path, nil, out); err != nil {
		return nil, err
	}
	if out.Alerts == nil {
		out.Alerts = []ThreatWatchAlert{}
	}
	return out, nil
}

// watchDo schickt eine Anfrage und liest data aus der Antwort (2xx). Anders als do kommt jede Fehlerantwort als
// *APIError mit Status, Code und RetryAfter (Seite und Abruf brauchen 401/403/429 unterscheidbar).
func (c *Client) watchDo(ctx context.Context, method, key, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, threatWatchTimeout)
	defer cancel()
	var rd io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	c.setNode(req)
	resp, err := c.http.Do(req)
	if err != nil {
		var ne net.Error
		if (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
			return errors.New("ipv64: timeout")
		}
		return fmt.Errorf("ipv64 not reachable: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return watchError(resp, body)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	env := struct {
		Data json.RawMessage `json:"data"`
	}{}
	if err := json.Unmarshal(body, &env); err != nil || len(env.Data) == 0 || string(env.Data) == "null" {
		return errors.New("ipv64: unexpected answer")
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("ipv64: unexpected answer: %w", err)
	}
	return nil
}

// watchError liest eine Fehlerantwort: {"error": {"code", "message"}} (v2), auch {"code", "detail"} bzw.
// {"error": "text"}.
func watchError(resp *http.Response, body []byte) *APIError {
	e := &APIError{Status: resp.StatusCode, RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())}
	var p struct {
		Detail string          `json:"detail"`
		Code   string          `json:"code"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &p) != nil {
		return e
	}
	e.Detail, e.Code = p.Detail, p.Code
	if len(p.Error) > 0 {
		var obj struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		var s string
		if json.Unmarshal(p.Error, &obj) == nil {
			if e.Code == "" {
				e.Code = obj.Code
			}
			if e.Detail == "" {
				e.Detail = obj.Message
			}
		} else if json.Unmarshal(p.Error, &s) == nil && e.Detail == "" {
			e.Detail = s
		}
	}
	e.Code = strings.TrimSpace(e.Code)
	return e
}
