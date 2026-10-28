package checks

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDockerCheck(t *testing.T) {
	states := map[string]any{
		"web":       map[string]any{"Status": "running", "Running": true, "StartedAt": time.Now().Add(-time.Hour).Format(time.RFC3339Nano)},
		"db":        map[string]any{"Status": "running", "Running": true, "Health": map[string]any{"Status": "healthy"}},
		"starting":  map[string]any{"Status": "running", "Running": true, "Health": map[string]any{"Status": "starting"}},
		"sick":      map[string]any{"Status": "running", "Running": true, "Health": map[string]any{"Status": "unhealthy", "Log": []map[string]any{{"Output": "curl: connection refused"}}}},
		"stopped":   map[string]any{"Status": "exited", "ExitCode": 137, "OOMKilled": true},
		"paused":    map[string]any{"Status": "paused", "Running": true, "Paused": true},
		"restarter": map[string]any{"Status": "restarting", "Running": true, "Restarting": true},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/containers/json" {
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "abcdef1234567890", "Names": []string{"/web"}, "Image": "nginx", "State": "running", "Status": "Up 1 hour",
				"Ports": []map[string]any{{"IP": "0.0.0.0", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"IP": "::", "PrivatePort": 80, "PublicPort": 8080, "Type": "tcp"}, {"PrivatePort": 443, "Type": "tcp"}}}})
			return
		}
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		st, ok := states[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container: ` + name + `"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "abcdef1234567890", "Name": "/" + name, "Config": map[string]any{"Image": "img"}, "State": st})
	}))
	defer srv.Close()
	params, _ := json.Marshal(DockerParams{Host: srv.URL})
	want := map[string]struct {
		status Status
		reason Reason
	}{
		"web": {Up, ReasonOK}, "db": {Up, ReasonOK}, "starting": {Up, ReasonOK}, "sick": {Down, ReasonContainerUnhealthy},
		"stopped": {Down, ReasonContainerStopped}, "paused": {Down, ReasonContainerPaused}, "restarter": {Down, ReasonContainerRestarting},
		"gone": {Down, ReasonContainerMissing},
	}
	r := NewRunner()
	for name, w := range want {
		def := Definition{Type: TypeDocker, Target: name, Params: params}
		if err := Validate(def); err != nil {
			t.Fatalf("%s: validate: %v", name, err)
		}
		res := r.Run(context.Background(), def)
		if len(res) != 1 || res[0].Status != w.status || res[0].Reason != w.reason {
			t.Errorf("%s: got %+v, want %s/%s", name, res, w.status, w.reason)
		}
	}
	list, err := ListContainers(context.Background(), srv.URL)
	if err != nil || len(list) != 1 || list[0].Name != "web" {
		t.Fatalf("list: %v %+v", err, list)
	}
	if strings.Join(list[0].Ports, ",") != "443/tcp,8080->80/tcp" { // Ports ohne IPv4/IPv6-Doppel
		t.Fatalf("ports: %v", list[0].Ports)
	}
	if !IsPrivateTarget("docker", "web") {
		t.Fatal("docker must never run online")
	}
	if err := Validate(Definition{Type: TypeDocker, Target: "bad name!"}); err == nil {
		t.Fatal("invalid container name accepted")
	}
}

// Latenz: Ping zur Adresse des laufenden Containers, sonst die Antwortzeit der Docker-API; Status unveraendert.
func TestDockerLatency(t *testing.T) {
	nets := map[string]any{
		"web":   map[string]any{"IPAddress": "", "Networks": map[string]any{"zz": map[string]any{"IPAddress": "172.18.0.9"}, "app": map[string]any{"IPAddress": "172.18.0.3"}}},
		"host":  map[string]any{"IPAddress": "", "Networks": map[string]any{"host": map[string]any{"IPAddress": ""}}},
		"v6":    map[string]any{"Networks": map[string]any{"app": map[string]any{"GlobalIPv6Address": "2001:db8::3"}}},
		"lost":  map[string]any{"IPAddress": "172.17.0.7"},
		"sick":  map[string]any{"IPAddress": "172.17.0.8"},
		"pause": map[string]any{"IPAddress": "172.17.0.4"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/containers/"), "/json")
		st := map[string]any{"Status": "running", "Running": true}
		switch name {
		case "sick":
			st["Health"] = map[string]any{"Status": "unhealthy"}
		case "pause":
			st["Paused"] = true
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Id": "abcdef1234567890", "Name": "/" + name, "State": st, "NetworkSettings": nets[name]})
	}))
	defer srv.Close()
	params, _ := json.Marshal(DockerParams{Host: srv.URL})
	r := NewRunner()
	var pinged []string
	r.ping = func(_ context.Context, ip net.IP, _ time.Duration) (time.Duration, bool) {
		pinged = append(pinged, ip.String())
		return 2 * time.Millisecond, ip.String() != "172.17.0.7"
	}
	want := map[string]struct {
		status Status
		source string
		ip     string
	}{
		"web": {Up, "ping", "172.18.0.3"}, "host": {Up, "api", ""}, "v6": {Up, "ping", "2001:db8::3"}, "lost": {Up, "api", "172.17.0.7"},
		"sick": {Down, "ping", "172.17.0.8"}, "pause": {Down, "api", ""},
	}
	for name, w := range want {
		pinged = nil
		res := r.Run(context.Background(), Definition{Type: TypeDocker, Target: name, Params: params})
		if len(res) != 1 || res[0].Status != w.status || res[0].Details["latency_source"] != w.source {
			t.Fatalf("%s: %+v", name, res)
		}
		if w.source == "ping" && res[0].Latency != 2*time.Millisecond {
			t.Fatalf("%s: latency %v", name, res[0].Latency)
		}
		if got := strings.Join(pinged, ","); got != w.ip {
			t.Fatalf("%s: pinged %q, want %q", name, got, w.ip)
		}
	}
}
