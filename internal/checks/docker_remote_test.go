package checks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Docker-Check fuer einen Host mit Zugangsdaten nimmt die Verbindung der Docker-Ueberwachung (Runner.Docker).
func TestDockerCheckRemote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/web/json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"State":{"Status":"running","Running":true}}`))
	}))
	defer srv.Close()
	host := "ssh://node64@10.0.0.9:22"
	def := Definition{Type: TypeDocker, Target: "web", Params: []byte(`{"host":"` + host + `"}`)}
	if err := Validate(def); err != nil {
		t.Fatal(err)
	}
	r := NewRunner()
	if res := r.Run(context.Background(), def); len(res) != 1 || res[0].Status != Down {
		t.Fatalf("ohne Ueberwachung: %+v", res)
	}
	r.Docker = func(h string) (*http.Client, string, bool) {
		if h != host {
			return nil, "", false
		}
		return srv.Client(), srv.URL, true
	}
	if res := r.Run(context.Background(), def); len(res) != 1 || res[0].Status != Up {
		t.Fatalf("ueber Runner.Docker: %+v", res)
	}
}

// Ein Transport je Socket: Check-Laeufe lassen keine Keep-Alive-Verbindungen liegen.
func TestDockerUnixTransportShared(t *testing.T) {
	a, _, _ := dockerClient("unix:///run/x.sock", time.Second)
	b, _, _ := dockerClient("unix:///run/x.sock", 2*time.Second)
	c, _, _ := dockerClient("unix:///run/y.sock", time.Second)
	if a.Transport != b.Transport || a.Transport == c.Transport {
		t.Fatal("transport je socket")
	}
}
