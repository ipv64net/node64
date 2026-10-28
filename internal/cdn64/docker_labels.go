package cdn64

import (
	"strconv"
	"strings"
)

// Proxy-Hosts aus Docker-Labels (Plan docs/PLAN-PROXY64-DOCKER.md): die Labels am Container legen Namen, Schema und
// Ziel fest; alles andere (CDN64 online, Zugriffsliste, Schutz, Zertifikat ...) wird in der Oberflaeche eingestellt
// und bleibt erhalten. Abgleich mit Docker: docker.go, Traefik-Labels: docker_traefik.go.

const (
	LabelProxyHost    = "node64.proxy.host"    // Namen, durch Komma getrennt (Pflicht)
	LabelProxyPort    = "node64.proxy.port"    // Port im Container (fehlt: der einzige freigegebene Port)
	LabelProxyScheme  = "node64.proxy.scheme"  // http (Standard) | https
	LabelProxyNetwork = "node64.proxy.network" // Docker-Netz zum Container (fehlt: automatisch)
	LabelProxyAccess  = "node64.proxy.access"  // Name einer Zugriffsliste (fehlt: in der Oberflaeche einstellbar)
	labelProxyPrefix  = "node64.proxy."
)

// Einstellungen (Tab Docker).
const (
	setDocker        = "cdn64.docker"         // "on" = Docker-Labels auswerten (Standard aus)
	setDockerTraefik = "cdn64.docker_traefik" // "off" = Traefik-Labels nicht mitlesen (Standard an)
	setDockerHost    = "cdn64.docker_host"    // Docker-API ("" = NODE64_DOCKER_HOST bzw. unix:///var/run/docker.sock)
	setDockerCert    = "cdn64.docker_cert"    // Zertifikat fuer neue Docker-Hosts: "" = keins anfordern, sonst Weg wie cert_source (auto, ipv64, http, dns:<Zugang>)
)

// Herkunft eines Hosts aus Labels.
const (
	dockerSrcNode64  = "node64"
	dockerSrcTraefik = "traefik"
)

// Gruende, aus denen ein Container nicht (vollstaendig) uebernommen wird (i18n-Schluessel, Texte in de/en.json).
const (
	dockerErrHost      = "cdn64.docker.err.host"       // node64.proxy.* ohne node64.proxy.host bzw. ohne Namen
	dockerErrPort      = "cdn64.docker.err.port"       // Port ungueltig ({name} = Wert)
	dockerErrScheme    = "cdn64.docker.err.scheme"     // Schema ungueltig ({name} = Wert)
	dockerErrNoPort    = "cdn64.docker.err.no_port"    // kein Port-Label und nicht genau ein freigegebener Port
	dockerErrNetwork   = "cdn64.docker.err.network"    // angegebenes Netz am Container nicht vorhanden ({name} = Netz)
	dockerErrNoTarget  = "cdn64.docker.err.no_target"  // keine Adresse, ueber die PROXY64 den Container erreicht
	dockerErrName      = "cdn64.docker.err.name"       // Name ungueltig ({name} = Name)
	dockerErrNameTaken = "cdn64.docker.err.name_taken" // Name gehoert zu einem von Hand angelegten Host ({name} = Name)
	dockerErrDup       = "cdn64.docker.err.dup"        // Name schon bei einem anderen Container ({name} = Container)
	dockerErrRule      = "cdn64.docker.err.rule"       // Traefik-Regel nicht unterstuetzt (nur Host(...)) ({name} = Router)
	dockerErrService   = "cdn64.docker.err.service"    // Traefik-Router ohne eindeutigen Service/Port ({name} = Router)
	dockerErrAccess    = "cdn64.docker.err.access"     // Zugriffsliste aus dem Label gibt es nicht ({name} = Name); Host kommt trotzdem
)

// dockerSpec ist ein Proxy-Host aus den Labels eines Containers.
type dockerSpec struct {
	Source  string   // dockerSrcNode64 | dockerSrcTraefik
	Router  string   // Traefik-Router ("" bei node64.proxy.*)
	Names   []string // wie angegeben (geprueft wird beim Speichern)
	Scheme  string   // http | https
	Port    int      // 0 = aus den freigegebenen Ports des Containers bestimmen
	Network string   // "" = automatisch
	Access  *dockerAccess
}

// dockerAccess: Zugriffsliste aus den Labels (node64.proxy.access bzw. Traefik-Middleware mit forwardAuth).
type dockerAccess struct {
	Name    string       // Name der Liste
	Auth    string       // Anmeldedienst, falls die Liste aus einer Traefik-Middleware angelegt wird
	Forward *ForwardAuth // nil = Liste muss es schon geben
}

// dockerProblem ist ein Label bzw. Router, das nicht uebernommen wird.
type dockerProblem struct {
	Router string // Traefik-Router ("" bei node64.proxy.*)
	Key    string // dockerErr*
	Name   string // Wert dazu
}

// dockerSpecs liest die Labels eines Containers. Stehen node64.proxy.* am Container, gelten nur diese (ein Host);
// sonst mit traefik = true je Traefik-Router ein Host.
func dockerSpecs(labels map[string]string, traefik bool) ([]dockerSpec, []dockerProblem) {
	own := false
	for k := range labels {
		if strings.HasPrefix(k, labelProxyPrefix) {
			own = true
			break
		}
	}
	if own {
		s, p := ownSpec(labels)
		if p != nil {
			return nil, []dockerProblem{*p}
		}
		return []dockerSpec{s}, nil
	}
	if traefik {
		return traefikSpecs(labels)
	}
	return nil, nil
}

// ownSpec: node64.proxy.*
func ownSpec(labels map[string]string) (dockerSpec, *dockerProblem) {
	s := dockerSpec{Source: dockerSrcNode64, Scheme: "http", Names: ParseNames(labels[LabelProxyHost])}
	if len(s.Names) == 0 {
		return s, &dockerProblem{Key: dockerErrHost}
	}
	if v := strings.TrimSpace(labels[LabelProxyPort]); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 65535 {
			return s, &dockerProblem{Key: dockerErrPort, Name: v}
		}
		s.Port = n
	}
	if v := strings.ToLower(strings.TrimSpace(labels[LabelProxyScheme])); v != "" {
		if v != "http" && v != "https" {
			return s, &dockerProblem{Key: dockerErrScheme, Name: v}
		}
		s.Scheme = v
	}
	s.Network = strings.TrimSpace(labels[LabelProxyNetwork])
	if v := strings.TrimSpace(labels[LabelProxyAccess]); v != "" {
		s.Access = &dockerAccess{Name: v}
	}
	return s, nil
}
