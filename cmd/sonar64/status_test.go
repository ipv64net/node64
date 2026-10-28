package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/sonar"
)

// fakeSource ist ein Runner-Ersatz fuer den Mini-Status.
type fakeSource struct {
	st  sonar.Status
	res []sonar.Result
	in  []sonar.Inbound
	n   int
}

func (f *fakeSource) Status() sonar.Status { return f.st }
func (f *fakeSource) Recent(n int) ([]sonar.Result, []sonar.Inbound) {
	f.n = n
	return f.res, f.in
}

func get(t *testing.T, h http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func TestStatusJSON(t *testing.T) {
	at := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	src := &fakeSource{
		st:  sonar.Status{NodeID: "nabc123def45", Registered: true, Mode: "headless", Budget: "sparsam", SentToday: 42},
		res: []sonar.Result{{Round: at, Target: "a_fsn", Family: 4, Method: "icmp", Sent: 3, Recv: 3, AvgMs: 9.5, At: at}},
		in:  []sonar.Inbound{{From: "0a1b2c3d", Family: 6, At: at, Count: 3}},
	}
	h := statusHandler(src, func() bool { return true })
	w := get(t, h, "GET", "/status")
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("code %d type %q", w.Code, w.Header().Get("Content-Type"))
	}
	if src.n != recentN {
		t.Fatalf("Recent(%d), want %d", src.n, recentN)
	}
	var d statusDoc
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if !d.Running || d.Status.NodeID != "nabc123def45" || len(d.Recent) != 1 || d.Recent[0].Target != "a_fsn" ||
		len(d.Inbound) != 1 || d.Inbound[0].From != "0a1b2c3d" || d.Version != Version {
		t.Fatalf("doc: %+v", d)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff")
	}
}

func TestStatusEmptyLists(t *testing.T) {
	h := statusHandler(&fakeSource{}, func() bool { return true })
	body := get(t, h, "GET", "/status").Body.String()
	if !strings.Contains(body, `"recent":[]`) || !strings.Contains(body, `"inbound":[]`) {
		t.Fatalf("lists must be [] not null: %s", body)
	}
}

func TestHealth(t *testing.T) {
	src := &fakeSource{st: sonar.Status{Registered: true}}
	running := true
	h := statusHandler(src, func() bool { return running })
	if w := get(t, h, "GET", "/health"); w.Code != 200 {
		t.Fatalf("healthy: %d", w.Code)
	}
	src.st.Registered = false
	if w := get(t, h, "GET", "/health"); w.Code != 503 {
		t.Fatalf("not registered: %d", w.Code)
	}
	src.st.Registered = true
	running = false
	if w := get(t, h, "GET", "/health"); w.Code != 503 {
		t.Fatalf("stopped: %d", w.Code)
	}
}

func TestPageAndMethods(t *testing.T) {
	h := statusHandler(&fakeSource{}, func() bool { return true })
	w := get(t, h, "GET", "/")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<script>"+pageScript+"</script>") {
		t.Fatalf("page: %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'sha256-"+scriptHash()+"'") || strings.Contains(csp, "unsafe-eval") ||
		strings.Contains(csp, "script-src 'unsafe-inline'") {
		t.Fatalf("csp: %q", csp)
	}
	if strings.Contains(pageScript, "innerHTML") {
		t.Fatal("page script must not use innerHTML")
	}
	if w := get(t, h, "POST", "/status"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
	if w := get(t, h, "GET", "/other"); w.Code != 404 {
		t.Fatalf("other: %d", w.Code)
	}
	if w := get(t, h, "HEAD", "/health"); w.Code != 200 && w.Code != 503 {
		t.Fatalf("HEAD: %d", w.Code)
	}
}

func TestStatusServerAndHealthcheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	addr := ln.Addr().String()
	src := &fakeSource{st: sonar.Status{Registered: true}}
	srv := newStatusServer(addr, src, func() bool { return true })
	go srv.Serve(ln)
	defer srv.Close()

	resp, err := http.Get("http://" + addr + "/status")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"registered":true`) {
		t.Fatalf("status over tcp: %d %s", resp.StatusCode, b)
	}

	_, port, _ := net.SplitHostPort(addr)
	if code := healthcheck(env(map[string]string{"SONAR64_STATUS": ":" + port})); code != 0 {
		t.Fatalf("healthcheck healthy: %d", code)
	}
	src.st.Registered = false
	if code := healthcheck(env(map[string]string{"SONAR64_STATUS": addr})); code != 1 {
		t.Fatalf("healthcheck unhealthy: %d", code)
	}
	if code := healthcheck(env(map[string]string{})); code != 0 {
		t.Fatalf("healthcheck without status: %d", code)
	}
	if code := healthcheck(env(map[string]string{"SONAR64_STATUS": "nonsense"})); code != 1 {
		t.Fatalf("healthcheck bad addr: %d", code)
	}
}
