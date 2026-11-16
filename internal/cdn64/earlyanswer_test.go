package cdn64

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// zeroBody: Upload aus Nullen, zaehlt, was der Client wirklich losgeworden ist.
type zeroBody struct {
	left int64
	sent atomic.Int64
}

func (z *zeroBody) Read(p []byte) (int, error) {
	if z.left <= 0 {
		return 0, io.EOF
	}
	n := int64(len(p))
	if n > z.left {
		n = z.left
	}
	clear(p[:n])
	z.left -= n
	z.sent.Add(n)
	return int(n), nil
}

// Ziel antwortet, bevor es den Upload gelesen hat (nginx bei OpenSpeedTest: POST auf eine Datei = sofort 200, den Rest
// verwirft nginx still): Der Besucher muss seinen Upload trotzdem zu Ende schicken koennen. Vorher brach PROXY64 den
// Upload ab, sobald die Antwort durch war (HTTP/2/3: Stream zu, HTTP/1.1: Verbindung zu) - der Speedtest zeigte
// einen Upload, der bis auf fast null einbrach.
func TestUploadAfterEarlyAnswer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok")) // Body nicht lesen
	}))
	defer backend.Close()
	bu, _ := url.Parse(backend.URL)
	bport, _ := strconv.Atoi(bu.Port())
	certPEM, keyPEM := selfSigned(t, "up.test")
	if _, err := e.crt.Upload(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	e.enable(t)
	h := newHost()
	h.Names, h.TargetHost, h.TargetPort = []string{"up.test"}, "127.0.0.1", bport
	if err := e.m.saveHost(ctx, h); err != nil {
		t.Fatal(err)
	}
	const size = 20 << 20
	for _, h2 := range []bool{true, false} {
		c := e.client(h2)
		body := &zeroBody{left: size}
		req, _ := http.NewRequest(http.MethodPost, "https://up.test/upload", body)
		req.ContentLength = size
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("h2=%v: %v", h2, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		for last, still := int64(-1), 0; body.sent.Load() < size && still < 40; { // der Client schickt nach der Antwort weiter (unter Last langsam)
			time.Sleep(50 * time.Millisecond)
			if n := body.sent.Load(); n == last {
				still++
			} else {
				last, still = n, 0
			}
		}
		if resp.StatusCode != 200 || body.sent.Load() != size {
			t.Fatalf("h2=%v (%s): status %d, upload sent %d of %d bytes", h2, resp.Proto, resp.StatusCode, body.sent.Load(), size)
		}
	}
}
