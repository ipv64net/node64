package cdn64

import (
	"reflect"
	"slices"
	"testing"
)

func TestTraefikHostRule(t *testing.T) {
	for rule, want := range map[string][]string{
		"Host(`app.example.de`)":                      {"app.example.de"},
		"  Host( `a.de` )  ":                          {"a.de"},
		"Host(\"a.de\")":                              {"a.de"},
		"Host(`a.de`,`b.de`)":                         {"a.de", "b.de"},
		"Host(`a.de`, \"b.de\")":                      {"a.de", "b.de"},
		"Host(`a.de`) || Host(`b.de`)":                {"a.de", "b.de"},
		"Host(`a.de`)||Host(`b.de`)||Host(`c.de`)":    {"a.de", "b.de", "c.de"},
		"(Host(`a.de`) || Host(`b.de`))":              {"a.de", "b.de"},
		"host(`a.de`)":                                {"a.de"},
		"Host(`a.de`, `b.de`) || Host(`c.de`)":        {"a.de", "b.de", "c.de"},
		"Host(`a.de`) || (Host(`b.de`))":              {"a.de", "b.de"},
		"\tHost(`a.de`)\n||\nHost(`b.de`)":            {"a.de", "b.de"},
		"Host(`a.de`) && PathPrefix(`/api`)":          nil,
		"PathPrefix(`/api`)":                          nil,
		"Host(`a.de`) || PathPrefix(`/api`)":          nil,
		"HostRegexp(`{sub:[a-z]+}.example.de`)":       nil,
		"HostSNI(`*`)":                                nil,
		"Headers(`X-Test`, `1`)":                      nil,
		"Host(`a.de`) || Headers(`X-Test`, `1`)":      nil,
		"!Host(`a.de`)":                               nil,
		"Host(`a.de`) |":                              nil,
		"Host(`a.de`":                                 nil,
		"Host(`a.de)":                                 nil,
		"Host()":                                      nil,
		"Host(``)":                                    nil,
		"Host(a.de)":                                  nil,
		"(Host(`a.de`)":                               nil,
		"":                                            nil,
		"Host(`a.de`) Host(`b.de`)":                   nil,
		"Host(`a.de`) || Host(`b.de`) && Path(`/x`)":  nil,
		"Host(`a.de`) || ":                            nil,
		"Host(`a.de`) || Host(`b.de`) || Method(`x`)": nil,
	} {
		got, ok := parseHostRule(rule)
		if ok != (want != nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v %v, want %v", rule, got, ok, want)
		}
	}
}

func TestTraefikSpecs(t *testing.T) {
	spec := func(r, scheme string, port int, network string, names ...string) dockerSpec {
		return dockerSpec{Source: dockerSrcTraefik, Router: r, Names: names, Scheme: scheme, Port: port, Network: network}
	}
	for _, c := range []struct {
		name   string
		labels map[string]string
		specs  []dockerSpec
		probs  []dockerProblem
	}{
		{"compose", map[string]string{
			"traefik.enable":                                        "true",
			"traefik.http.routers.whoami.rule":                      "Host(`whoami.example.de`)",
			"traefik.http.routers.whoami.entrypoints":               "websecure",
			"traefik.http.routers.whoami.tls.certresolver":          "le",
			"traefik.http.routers.whoami.middlewares":               "auth@file",
			"traefik.http.services.whoami.loadbalancer.server.port": "8080",
		}, []dockerSpec{withMW(spec("whoami", "http", 8080, "", "whoami.example.de"), "auth@file")}, nil}, // auth@file: Zugriffsliste "auth" noetig
		{"without enable and service", map[string]string{
			"traefik.http.routers.app.rule": "Host(`app.example.de`)",
		}, []dockerSpec{spec("app", "http", 0, "", "app.example.de")}, nil},
		{"enable false", map[string]string{
			"traefik.enable":                "false",
			"traefik.http.routers.app.rule": "PathPrefix(`/`)",
		}, nil, nil},
		{"enable FALSE", map[string]string{
			"Traefik.Enable":                "FALSE",
			"traefik.http.routers.app.rule": "Host(`app.example.de`)",
		}, nil, nil},
		{"web and websecure", map[string]string{
			"traefik.http.routers.app.rule":                      "Host(`app.example.de`)",
			"traefik.http.routers.app.entrypoints":               "web",
			"traefik.http.routers.app.middlewares":               "redirect-to-https",
			"traefik.http.routers.app-secure.rule":               "Host(`App.example.de`)",
			"traefik.http.routers.app-secure.entrypoints":        "websecure",
			"traefik.http.routers.app-secure.tls":                "true",
			"traefik.http.services.app.loadbalancer.server.port": "3000",
		}, []dockerSpec{spec("app", "http", 3000, "", "app.example.de")}, nil},
		{"same names, different services", map[string]string{
			"traefik.http.routers.a.rule":                       "Host(`x.example.de`)",
			"traefik.http.routers.a.service":                    "s1",
			"traefik.http.routers.b.rule":                       "Host(`x.example.de`)",
			"traefik.http.routers.b.service":                    "s2",
			"traefik.http.services.s1.loadbalancer.server.port": "80",
			"traefik.http.services.s2.loadbalancer.server.port": "81",
		}, []dockerSpec{spec("a", "http", 80, "", "x.example.de"), spec("b", "http", 81, "", "x.example.de")}, nil},
		{"two services in one container", map[string]string{
			"traefik.http.routers.web.rule":                        "Host(`web.example.de`)",
			"traefik.http.routers.web.service":                     "web",
			"traefik.http.routers.admin.rule":                      "Host(`admin.example.de`)",
			"traefik.http.routers.admin.service":                   "admin",
			"traefik.http.services.web.loadbalancer.server.port":   "80",
			"traefik.http.services.admin.loadbalancer.server.port": "9000",
		}, []dockerSpec{spec("admin", "http", 9000, "", "admin.example.de"), spec("web", "http", 80, "", "web.example.de")}, nil},
		{"missing service with two services", map[string]string{
			"traefik.http.routers.web.rule":                        "Host(`web.example.de`)",
			"traefik.http.routers.admin.rule":                      "Host(`admin.example.de`)",
			"traefik.http.routers.admin.service":                   "admin",
			"traefik.http.services.web.loadbalancer.server.port":   "80",
			"traefik.http.services.admin.loadbalancer.server.port": "9000",
		}, []dockerSpec{spec("admin", "http", 9000, "", "admin.example.de")},
			[]dockerProblem{{Router: "web", Key: dockerErrService, Name: "web"}}},
		{"unknown service", map[string]string{
			"traefik.http.routers.dash.rule":    "Host(`traefik.example.de`)",
			"traefik.http.routers.dash.service": "api@internal",
		}, nil, []dockerProblem{{Router: "dash", Key: dockerErrService, Name: "dash"}}},
		{"PathPrefix", map[string]string{
			"traefik.http.routers.api.rule": "PathPrefix(`/api`)",
			"traefik.http.routers.app.rule": "Host(`app.example.de`)",
		}, []dockerSpec{spec("app", "http", 0, "", "app.example.de")},
			[]dockerProblem{{Router: "api", Key: dockerErrRule, Name: "api"}}},
		{"Host and PathPrefix", map[string]string{
			"traefik.http.routers.api.rule": "Host(`app.example.de`) && PathPrefix(`/api`)",
		}, nil, []dockerProblem{{Router: "api", Key: dockerErrRule, Name: "api"}}},
		{"scheme https", map[string]string{
			"traefik.http.routers.pve.rule":                        "Host(`pve.example.de`)",
			"traefik.http.services.pve.loadbalancer.server.port":   "8006",
			"traefik.http.services.pve.loadbalancer.server.scheme": "HTTPS",
		}, []dockerSpec{spec("pve", "https", 8006, "", "pve.example.de")}, nil},
		{"scheme h2c", map[string]string{
			"traefik.http.routers.grpc.rule":                        "Host(`grpc.example.de`)",
			"traefik.http.services.grpc.loadbalancer.server.scheme": "h2c",
		}, nil, []dockerProblem{{Router: "grpc", Key: dockerErrService, Name: "grpc"}}},
		{"port invalid", map[string]string{
			"traefik.http.routers.app.rule":                      "Host(`app.example.de`)",
			"traefik.http.services.app.loadbalancer.server.port": "70000",
		}, nil, []dockerProblem{{Router: "app", Key: dockerErrService, Name: "app"}}},
		{"network", map[string]string{
			"traefik.docker.network":        "proxy",
			"traefik.http.routers.app.rule": "Host(`app.example.de`)",
		}, []dockerSpec{spec("app", "http", 0, "proxy", "app.example.de")}, nil},
		{"v2 multi host", map[string]string{
			"traefik.http.routers.app.rule": "Host(`example.de`, `www.example.de`) || Host(`alt.example.de`)",
		}, []dockerSpec{spec("app", "http", 0, "", "example.de", "www.example.de", "alt.example.de")}, nil},
		{"case of keys", map[string]string{
			"Traefik.HTTP.Routers.MyApp.Rule":                        "Host(`app.example.de`)",
			"traefik.http.routers.myapp.service":                     "Backend",
			"Traefik.Http.Services.BACKEND.LoadBalancer.Server.Port": "8000",
			"Traefik.Docker.Network":                                 "Proxy",
		}, []dockerSpec{spec("myapp", "http", 8000, "Proxy", "app.example.de")}, nil},
		{"tcp, udp and router without rule", map[string]string{
			"traefik.tcp.routers.db.rule":                      "HostSNI(`*`)",
			"traefik.udp.routers.dns.entrypoints":              "dns",
			"traefik.http.routers.other.service":               "x",
			"traefik.http.routers.app.rule":                    "Host(`app.example.de`)",
			"traefik.http.routers.app.priority":                "10",
			"traefik.tcp.services.db.loadbalancer.server.port": "5432",
		}, []dockerSpec{spec("app", "http", 0, "", "app.example.de")}, nil},
		{"no labels", map[string]string{"com.docker.compose.project": "x"}, nil, nil},
	} {
		specs, probs := traefikSpecs(c.labels, nil)
		if !reflect.DeepEqual(specs, c.specs) {
			t.Errorf("%s: specs %+v, want %+v", c.name, specs, c.specs)
		}
		if !reflect.DeepEqual(probs, c.probs) {
			t.Errorf("%s: problems %+v, want %+v", c.name, probs, c.probs)
		}
	}
}

func withMW(s dockerSpec, mw ...string) dockerSpec {
	s.Middlewares = mw
	return s
}

// Middlewares: forwardAuth in den Labels -> Liste mit Adresse im Namen, harmlose Arten unbeachtet, alles andere
// (Datei, basicAuth, ipAllowList, nicht definiert) muss als Zugriffsliste kommen.
func TestTraefikMiddlewares(t *testing.T) {
	l := map[string]string{
		"traefik.http.routers.app.middlewares":                 "hdr@docker, fa, basic, lan@docker, chain-x@file, gone",
		"traefik.http.middlewares.hdr.headers.stsseconds":      "3600",
		"traefik.http.middlewares.hdr.compress":                "true",
		"traefik.http.middlewares.fa.forwardauth.address":      "http://authelia:9091/api/authz/forward-auth",
		"traefik.http.middlewares.basic.basicauth.users":       "x:y",
		"traefik.http.middlewares.lan.ipallowlist.sourcerange": "192.168.0.0/16",
	}
	a, rest, ign := traefikMiddlewares(l, nil, "app")
	if a == nil || a.Name != "Traefik: fa (authelia:9091)" || a.Auth != AuthAuthelia || a.Forward.Address != "http://authelia:9091/api/authz/forward-auth" {
		t.Fatalf("access: %+v", a)
	}
	if !slices.Equal(rest, []string{"basic", "lan@docker", "chain-x@file", "gone"}) || !slices.Equal(ign, []string{"hdr@docker"}) {
		t.Fatalf("rest: %v ignored: %v", rest, ign)
	}
	if a, rest, _ := traefikMiddlewares(map[string]string{"traefik.http.routers.app.middlewares": "hdr", "traefik.http.middlewares.hdr.headers.x": "1"}, nil, "app"); a != nil || rest != nil {
		t.Fatalf("harmless only: %+v %v", a, rest)
	}
	// Datei-Middlewares mit harmlosem Namen uebergangen, mit Zugangs-Namen nicht; Definition an einem anderen Container
	l2 := map[string]string{"traefik.http.routers.app.middlewares": "redirect-to-https@file, secure-headers@file, ip-allowlist@file, authentik@docker"}
	shared := traefikShared([]map[string]string{{"traefik.http.middlewares.authentik.forwardAuth.address": "http://authentik-server:9000/outpost.goauthentik.io/auth/traefik"}})
	a, rest, ign = traefikMiddlewares(l2, shared, "app")
	if a == nil || a.Auth != AuthAuthentik || !slices.Equal(rest, []string{"ip-allowlist@file"}) ||
		!slices.Equal(ign, []string{"redirect-to-https@file", "secure-headers@file"}) {
		t.Fatalf("file/shared: %+v %v %v", a, rest, ign)
	}
}
