package cdn64

import (
	"reflect"
	"testing"
)

func TestOwnSpec(t *testing.T) {
	s, p := ownSpec(map[string]string{
		LabelProxyHost:    " app.example.de, www.example.de ",
		LabelProxyPort:    " 8080 ",
		LabelProxyScheme:  "HTTPS",
		LabelProxyNetwork: " proxy ",
	})
	want := dockerSpec{Source: dockerSrcNode64, Names: []string{"app.example.de", "www.example.de"}, Scheme: "https", Port: 8080, Network: "proxy"}
	if p != nil || !reflect.DeepEqual(s, want) {
		t.Fatalf("got %+v %+v, want %+v", s, p, want)
	}
	s, p = ownSpec(map[string]string{LabelProxyHost: "app.example.de"})
	if p != nil || s.Scheme != "http" || s.Port != 0 || s.Network != "" {
		t.Fatalf("defaults: %+v %+v", s, p)
	}
	for _, c := range []struct {
		labels map[string]string
		want   dockerProblem
	}{
		{map[string]string{LabelProxyPort: "80"}, dockerProblem{Key: dockerErrHost}},
		{map[string]string{LabelProxyHost: " , "}, dockerProblem{Key: dockerErrHost}},
		{map[string]string{LabelProxyHost: "a.de", LabelProxyPort: "http"}, dockerProblem{Key: dockerErrPort, Name: "http"}},
		{map[string]string{LabelProxyHost: "a.de", LabelProxyPort: "0"}, dockerProblem{Key: dockerErrPort, Name: "0"}},
		{map[string]string{LabelProxyHost: "a.de", LabelProxyPort: "65536"}, dockerProblem{Key: dockerErrPort, Name: "65536"}},
		{map[string]string{LabelProxyHost: "a.de", LabelProxyScheme: "h2c"}, dockerProblem{Key: dockerErrScheme, Name: "h2c"}},
	} {
		if _, p := ownSpec(c.labels); p == nil || *p != c.want {
			t.Errorf("%v: got %+v, want %+v", c.labels, p, c.want)
		}
	}
}

func TestDockerSpecs(t *testing.T) {
	traefik := map[string]string{"traefik.http.routers.app.rule": "Host(`t.example.de`)"}
	both := map[string]string{
		"traefik.http.routers.app.rule": "Host(`t.example.de`)",
		LabelProxyHost:                  "own.example.de",
	}
	// eigene Labels haben Vorrang vor Traefik
	s, p := dockerSpecs(both, true, nil)
	if len(p) != 0 || len(s) != 1 || s[0].Source != dockerSrcNode64 || s[0].Names[0] != "own.example.de" {
		t.Fatalf("own first: %+v %+v", s, p)
	}
	// fehlerhafte eigene Labels: kein Rueckfall auf Traefik
	s, p = dockerSpecs(map[string]string{"traefik.http.routers.app.rule": "Host(`t.example.de`)", LabelProxyPort: "80"}, true, nil)
	if len(s) != 0 || len(p) != 1 || p[0].Key != dockerErrHost {
		t.Fatalf("own invalid: %+v %+v", s, p)
	}
	s, p = dockerSpecs(traefik, true, nil)
	if len(p) != 0 || len(s) != 1 || s[0].Source != dockerSrcTraefik || s[0].Router != "app" {
		t.Fatalf("traefik: %+v %+v", s, p)
	}
	// Traefik-Labels ausgeschaltet
	if s, p = dockerSpecs(traefik, false, nil); s != nil || p != nil {
		t.Fatalf("traefik off: %+v %+v", s, p)
	}
	if s, p = dockerSpecs(map[string]string{"com.docker.compose.service": "app"}, true, nil); s != nil || p != nil {
		t.Fatalf("no labels: %+v %+v", s, p)
	}
}
