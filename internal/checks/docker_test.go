package checks

import (
	"context"
	"encoding/json"
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
			_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "abcdef1234567890", "Names": []string{"/web"}, "Image": "nginx", "State": "running", "Status": "Up 1 hour"}})
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
	if !IsPrivateTarget("docker", "web") {
		t.Fatal("docker must never run online")
	}
	if err := Validate(Definition{Type: TypeDocker, Target: "bad name!"}); err == nil {
		t.Fatal("invalid container name accepted")
	}
}
