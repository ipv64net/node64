package ipv64api

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return b.Bytes()
}

func TestHoneypotReport(t *testing.T) {
	var status int
	var answer string
	var hdr http.Header
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v2/honeypot/reports" {
			http.NotFound(w, r)
			return
		}
		hdr = r.Header.Clone()
		zr, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Errorf("body not gzip: %v", err)
			return
		}
		b, _ := io.ReadAll(zr)
		got = string(b)
		w.Header().Set("Content-Type", "application/json")
		if status == http.StatusTooManyRequests {
			w.Header().Set("Retry-After", "120")
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, answer)
	}))
	defer srv.Close()
	c := NewClient(srv.URL+"/api/v2", "node64/test")
	ctx := context.Background()
	body := gzipBytes(t, `{"schema":1}`)

	status, answer = http.StatusAccepted, `{"data":{"accepted":3,"rejected":2,"rejected_reasons":{"not_public":2},"report_id":"s-1"}}`
	res, err := c.HoneypotReport(ctx, "KEY0123456789abcdef", body)
	if err != nil || res.Status != 202 || res.Accepted != 3 || res.ReportID != "s-1" || res.Duplicate || res.Rejected != 2 || res.RejectedReasons["not_public"] != 2 {
		t.Fatalf("202: %+v %v", res, err)
	}
	if got != `{"schema":1}` || hdr.Get("Authorization") != "Bearer KEY0123456789abcdef" || hdr.Get("Content-Encoding") != "gzip" ||
		hdr.Get("Content-Type") != "application/json" || hdr.Get("User-Agent") != "node64/test" {
		t.Fatalf("request: %q %v", got, hdr)
	}

	status, answer = http.StatusOK, `{"duplicate":true,"report_id":"s-1"}` // ohne Huelle
	if res, err = c.HoneypotReport(ctx, "k", body); err != nil || !res.Duplicate || res.ReportID != "s-1" {
		t.Fatalf("200: %+v %v", res, err)
	}

	status, answer = http.StatusUnprocessableEntity, `{"error":"sources[0].ip invalid"}`
	_, err = c.HoneypotReport(ctx, "k", body)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 422 || ae.Detail != "sources[0].ip invalid" {
		t.Fatalf("422: %v", err)
	}

	status, answer = http.StatusTooManyRequests, `{"detail":"too many","code":"rate_limited"}`
	_, err = c.HoneypotReport(ctx, "k", body)
	if !errors.As(err, &ae) || ae.Status != 429 || ae.RetryAfter != 2*time.Minute || ae.Code != "rate_limited" {
		t.Fatalf("429: %v %+v", err, ae)
	}

	status, answer = http.StatusUnauthorized, `{}`
	if _, err = c.HoneypotReport(ctx, "k", body); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("401: %v", err)
	}

	srv.Close()
	if _, err = c.HoneypotReport(ctx, "k", body); err == nil || errors.As(err, &ae) {
		t.Fatalf("network error expected: %v", err)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for in, want := range map[string]time.Duration{"": 0, "30": 30 * time.Second, "-5": 0, "x": 0, "999999": maxRetryAfter,
		now.Add(90 * time.Second).Format(http.TimeFormat): 90 * time.Second} {
		if got := parseRetryAfter(in, now); got != want {
			t.Errorf("%q: %v, want %v", in, got, want)
		}
	}
}
