package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLeave(t *testing.T) {
	const tok = "s64_0123456789abcdefghijABCDEFGHIJ0123456789"
	var mu sync.Mutex
	code, calls := http.StatusNoContent, []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		w.WriteHeader(code)
	}))
	defer srv.Close()
	dir := t.TempDir()
	env := map[string]string{"SONAR64_TOKEN": tok, "SONAR64_DATA": dir, "SONAR64_API": srv.URL}
	getenv := func(k string) string { return env[k] }
	exists := func(name string) bool { _, err := os.Stat(filepath.Join(dir, name)); return err == nil }

	// ipv64 meldet einen Fehler: Exit 1, Schluessel bleibt, kein Token in der Meldung
	code = http.StatusBadGateway
	var out, errOut bytes.Buffer
	if rc := leave(getenv, &out, &errOut); rc != 1 || !exists("sonar64.key") || strings.Contains(errOut.String(), tok) {
		t.Fatalf("502: rc %d, stderr %q", rc, errOut.String())
	}
	code = http.StatusNoContent
	out.Reset()
	errOut.Reset()
	if rc := leave(getenv, &out, &errOut); rc != 0 || exists("sonar64.key") || exists("sonar64.json") || !strings.Contains(out.String(), "signed off") {
		t.Fatalf("204: rc %d, out %q, stderr %q", rc, out.String(), errOut.String())
	}
	mu.Lock()
	last := calls[len(calls)-1]
	mu.Unlock()
	if last != "DELETE /sonar/me Bearer "+tok {
		t.Fatalf("calls %v", calls)
	}
	if strings.Contains(out.String()+errOut.String(), tok) {
		t.Fatal("token in output")
	}
	// ohne Token: Exit 2
	delete(env, "SONAR64_TOKEN")
	if rc := leave(getenv, &out, &errOut); rc != 2 {
		t.Fatalf("no token: rc %d", rc)
	}
}
