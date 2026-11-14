package certs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// netcup CloudDNS (REST-API v1, https://api.netcup.com/v1; #108): Domains auf den neuen Nameservern
// (netcup.firstns.cc, netcup.secondns.at …) nehmen TXT-Records ueber die alte CCP-API zwar an, legen sie aber nicht in
// der aktiven Zone an. Die neue API hat eigene Endpunkte fuer ACME-Pruefungen und braucht nur einen API-Key (Bearer).
// lego bringt den Anbieter erst ab v5.6 (netcupv1); bis zum Wechsel auf lego v5 diese kleine Fassung mit denselben
// Endpunkten: GET /domain?fqdn=, POST /domain/{id}/acme/challenge {scope, value}, DELETE
// /domain/{id}/acme/challenge/{scope}/{value}. scope ist der Name unter der Domain ("@" = die Domain selbst), netcup
// setzt _acme-challenge davor.

const netcupV1URL = "https://api.netcup.com/v1"

type netcupV1 struct {
	key     string
	baseURL string
	client  *http.Client
}

func newNetcupV1(key string) (*netcupV1, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil, errors.New("api key missing")
	}
	return &netcupV1{key: key, baseURL: netcupV1URL, client: &http.Client{Timeout: 30 * time.Second}}, nil
}

var _ challenge.ProviderTimeout = (*netcupV1)(nil)

// Timeout: netcup veroeffentlicht langsam (wie lego: 15 Minuten, alle 30 Sekunden).
func (p *netcupV1) Timeout() (timeout, interval time.Duration) {
	return 15 * time.Minute, 30 * time.Second
}

type netcupV1Domain struct {
	ID         int64  `json:"id"`
	FQDN       string `json:"fqdn"`
	DNSManaged *bool  `json:"isDnsManaged"`
}

type netcupV1Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type netcupV1Answer struct {
	Success bool            `json:"success"`
	Errors  []netcupV1Error `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

func (p *netcupV1) do(method, path string, query url.Values, body any, out any) error {
	u := strings.TrimSuffix(p.baseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+p.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "node64")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var a netcupV1Answer
	jerr := json.Unmarshal(raw, &a)
	if resp.StatusCode/100 != 2 {
		if jerr == nil && len(a.Errors) > 0 {
			var msgs []string
			for _, e := range a.Errors {
				msgs = append(msgs, e.Code+": "+e.Message)
			}
			return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.Join(msgs, "; "))
		}
		return fmt.Errorf("%s %s: status %d", method, path, resp.StatusCode)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if jerr != nil {
		return fmt.Errorf("%s %s: %w", method, path, jerr)
	}
	if len(a.Result) == 0 || string(a.Result) == "null" {
		return nil
	}
	return json.Unmarshal(a.Result, out)
}

// target liefert Domain (Zone bei netcup) und scope fuer die Pruefung von domain.
func (p *netcupV1) target(domain, keyAuth string) (*netcupV1Domain, string, string, error) {
	info := dns01.GetChallengeInfo(domain, keyAuth) // folgt wie bei den anderen Anbietern einem CNAME
	host, ok := strings.CutPrefix(strings.ToLower(dns01.UnFqdn(info.EffectiveFQDN)), "_acme-challenge.")
	if !ok {
		return nil, "", "", fmt.Errorf("%s: netcup sets only _acme-challenge records (CNAME target not supported)", dns01.UnFqdn(info.EffectiveFQDN))
	}
	var lastErr error
	for name := range dns01.UnFqdnDomainsSeq(host) {
		var list []netcupV1Domain
		if err := p.do(http.MethodGet, "/domain", url.Values{"fqdn": {name}}, nil, &list); err != nil {
			// nicht in diesem Account: weiter nach oben; anderes (z. B. falscher API-Key) sofort melden
			if !strings.Contains(err.Error(), "resourceDoesNotExist") && !strings.Contains(err.Error(), "status 404") {
				return nil, "", "", err
			}
			lastErr = err
			continue
		}
		for i := range list {
			if strings.EqualFold(strings.TrimSuffix(list[i].FQDN, "."), name) {
				if list[i].DNSManaged != nil && !*list[i].DNSManaged {
					return nil, "", "", fmt.Errorf("%s: dns is not managed by netcup CloudDNS (other name servers or the classic netcup DNS: use the provider netcup (CCP-API))", name)
				}
				scope := "@"
				if host != name {
					scope = strings.TrimSuffix(host, "."+name)
				}
				return &list[i], scope, info.Value, nil
			}
		}
	}
	if lastErr != nil {
		return nil, "", "", fmt.Errorf("no domain found for %s: %w", host, lastErr)
	}
	return nil, "", "", fmt.Errorf("no domain found for %s in this netcup account", host)
}

// Present legt den TXT-Record an.
func (p *netcupV1) Present(domain, _, keyAuth string) error {
	d, scope, value, err := p.target(domain, keyAuth)
	if err != nil {
		return err
	}
	return p.do(http.MethodPost, "/domain/"+strconv.FormatInt(d.ID, 10)+"/acme/challenge", nil,
		map[string]string{"scope": scope, "value": value}, nil)
}

// CleanUp entfernt den TXT-Record wieder.
func (p *netcupV1) CleanUp(domain, _, keyAuth string) error {
	d, scope, value, err := p.target(domain, keyAuth)
	if err != nil {
		return err
	}
	return p.do(http.MethodDelete, "/domain/"+strconv.FormatInt(d.ID, 10)+"/acme/challenge/"+url.PathEscape(scope)+"/"+url.PathEscape(value), nil, nil, nil)
}

func init() {
	register(ProviderInfo{ID: "netcupv1", Name: "netcup CloudDNS (REST-API)",
		Docs:   "Domains mit Nameservern netcup.firstns.cc …: API-Key der netcup-REST-API (api.netcup.com)",
		Fields: []Field{{Key: "key", Label: "API-Key", Secret: true}}},
		func(v map[string]string) (challenge.Provider, error) {
			p, err := newNetcupV1(v["key"])
			if err != nil {
				return nil, err
			}
			return p, nil
		})
}
