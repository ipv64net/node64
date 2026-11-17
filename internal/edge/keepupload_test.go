package edge

import (
	"bufio"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Live-Verbindungen hinter KeepUpload (Forum 5202, Dockhand): HTTP/2 liefert auch einem GET ohne Inhalt einen Body.
// Die Antwort darf trotzdem nicht zurueckgehalten werden - das erste Ereignis muss sofort ankommen, nicht erst am Ende.
// Dazu ein Event-Stream als Antwort auf einen Upload: er laeuft neben dem Upload (z. B. Fortschritt).
func TestKeepUploadLiveResponses(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		out, done := KeepUpload(w, r)
		defer done()
		if r.URL.Path == "/sse-upload" {
			_, _ = io.ReadFull(r.Body, make([]byte, 10)) // Anfang des Uploads, der Rest kommt spaeter
		}
		out.Header().Set("Content-Type", "text/event-stream")
		if r.URL.Path == "/plain" {
			out.Header().Set("Content-Type", "application/json")
		}
		out.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(out, "data: first\n\n")
		http.NewResponseController(out).Flush()
		time.Sleep(1500 * time.Millisecond) // Live-Verbindung bleibt offen
		_, _ = io.WriteString(out, "data: second\n\n")
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	c := &http.Client{Transport: &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // Test
	for _, tc := range []struct {
		path   string
		method string
	}{{"/sse", http.MethodGet}, {"/plain", http.MethodGet}, {"/sse-upload", http.MethodPost}} {
		var body io.Reader
		if tc.method == http.MethodPost {
			pr, pw := io.Pipe()
			go func() { _, _ = pw.Write(make([]byte, 10)); time.Sleep(3 * time.Second); _ = pw.Close() }()
			body = pr
		}
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, body)
		t0 := time.Now()
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", tc.path, err)
		}
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		el := time.Since(t0)
		resp.Body.Close()
		if resp.ProtoMajor != 2 || err != nil || !strings.HasPrefix(line, "data: first") || el > time.Second {
			t.Fatalf("%s (%s): first event after %v: %q %v", tc.path, resp.Proto, el.Round(time.Millisecond), line, err)
		}
	}
}
