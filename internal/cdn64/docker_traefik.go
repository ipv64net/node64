package cdn64

import (
	"sort"
	"strconv"
	"strings"
)

// Traefik-Labels mitlesen (Phase D3, docs/PLAN-PROXY64-DOCKER.md Abschnitt 7). Ausgewertet werden nur
// traefik.enable, traefik.http.routers.<r>.rule (nur Host(...)) und .service, traefik.http.services.<s>.loadbalancer
// .server.port/.scheme und traefik.docker.network. Middlewares, Entrypoints, TLS/Certresolver, Prioritaet sowie
// TCP/UDP-Router bleiben unbeachtet. Schluessel sind wie bei Traefik unabhaengig von Gross-/Kleinschreibung.

const (
	traefikRouterPrefix  = "traefik.http.routers."
	traefikServicePrefix = "traefik.http.services."
)

// traefikSpecs: je Traefik-Router mit Host(...)-Regel ein Host, sortiert nach Router-Name. Router mit gleichen Namen
// und gleichem Ziel (z. B. http- und https-Router) ergeben nur einen Host (der alphabetisch erste Router).
func traefikSpecs(labels map[string]string) ([]dockerSpec, []dockerProblem) {
	l := make(map[string]string, len(labels))
	for k, v := range labels {
		l[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if b, err := strconv.ParseBool(l["traefik.enable"]); err == nil && !b {
		return nil, nil
	}
	var routers []string
	services := map[string]bool{}
	for k := range l {
		if r, ok := strings.CutPrefix(k, traefikRouterPrefix); ok {
			if name, ok := strings.CutSuffix(r, ".rule"); ok && name != "" && !strings.Contains(name, ".") {
				routers = append(routers, name)
			}
		} else if s, ok := strings.CutPrefix(k, traefikServicePrefix); ok {
			if i := strings.IndexByte(s, '.'); i > 0 {
				services[s[:i]] = true
			}
		}
	}
	sort.Strings(routers)
	network := l["traefik.docker.network"]
	var specs []dockerSpec
	var probs []dockerProblem
	seen := map[string]bool{} // Namensmenge + Ziel
	for _, r := range routers {
		names, ok := parseHostRule(l[traefikRouterPrefix+r+".rule"])
		if !ok {
			probs = append(probs, dockerProblem{Router: r, Key: dockerErrRule, Name: r})
			continue
		}
		svc := strings.ToLower(l[traefikRouterPrefix+r+".service"])
		if svc == "" && len(services) == 1 {
			for s := range services {
				svc = s
			}
		}
		if (svc != "" && !services[svc]) || (svc == "" && len(services) > 1) {
			probs = append(probs, dockerProblem{Router: r, Key: dockerErrService, Name: r})
			continue
		}
		s := dockerSpec{Source: dockerSrcTraefik, Router: r, Names: names, Scheme: "http", Network: network}
		if svc != "" {
			p := traefikServicePrefix + svc + ".loadbalancer.server."
			if v := l[p+"port"]; v != "" {
				n, err := strconv.Atoi(v)
				if err != nil || n < 1 || n > 65535 {
					probs = append(probs, dockerProblem{Router: r, Key: dockerErrService, Name: r})
					continue
				}
				s.Port = n
			}
			if v := strings.ToLower(l[p+"scheme"]); v != "" {
				if v != "http" && v != "https" {
					probs = append(probs, dockerProblem{Router: r, Key: dockerErrService, Name: r})
					continue
				}
				s.Scheme = v
			}
		}
		key := strings.Join(nameSet(names), ",") + "|" + svc + "|" + s.Scheme + "|" + strconv.Itoa(s.Port)
		if seen[key] {
			continue
		}
		seen[key] = true
		specs = append(specs, s)
	}
	return specs, probs
}

// nameSet: Namen kleingeschrieben, sortiert, ohne Doppelte (zum Vergleich von Routern).
func nameSet(names []string) []string {
	m := map[string]bool{}
	var out []string
	for _, n := range names {
		n = strings.ToLower(n)
		if !m[n] {
			m[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// parseHostRule liest eine Traefik-Regel aus Host(...)-Ausdruecken, verbunden mit ||, Klammern erlaubt, je Host einer
// (v3) oder mehrere Namen (v2), in Backticks oder Anfuehrungszeichen. Alles andere: ok = false.
func parseHostRule(rule string) ([]string, bool) {
	p := &ruleParser{s: rule}
	names, ok := p.or()
	p.space()
	if !ok || p.i != len(p.s) || len(names) == 0 {
		return nil, false
	}
	return names, true
}

// ruleParser ist ein kleiner Parser fuer parseHostRule.
type ruleParser struct {
	s string
	i int
}

func (p *ruleParser) space() {
	for p.i < len(p.s) && (p.s[p.i] == ' ' || p.s[p.i] == '\t' || p.s[p.i] == '\n' || p.s[p.i] == '\r') {
		p.i++
	}
}

// eat ueberspringt Leerraum und dann tok, falls es folgt.
func (p *ruleParser) eat(tok string) bool {
	p.space()
	if strings.HasPrefix(p.s[p.i:], tok) {
		p.i += len(tok)
		return true
	}
	return false
}

// or: term { "||" term }
func (p *ruleParser) or() ([]string, bool) {
	names, ok := p.term()
	if !ok {
		return nil, false
	}
	for p.eat("||") {
		n, ok := p.term()
		if !ok {
			return nil, false
		}
		names = append(names, n...)
	}
	return names, true
}

// term: "(" or ")" | Host "(" str { "," str } ")"
func (p *ruleParser) term() ([]string, bool) {
	if p.eat("(") {
		names, ok := p.or()
		if !ok || !p.eat(")") {
			return nil, false
		}
		return names, true
	}
	p.space()
	j := p.i
	for j < len(p.s) && (p.s[j] >= 'a' && p.s[j] <= 'z' || p.s[j] >= 'A' && p.s[j] <= 'Z') {
		j++
	}
	if !strings.EqualFold(p.s[p.i:j], "Host") {
		return nil, false
	}
	p.i = j
	if !p.eat("(") {
		return nil, false
	}
	var names []string
	for {
		n, ok := p.str()
		if !ok {
			return nil, false
		}
		names = append(names, n)
		if p.eat(")") {
			return names, true
		}
		if !p.eat(",") {
			return nil, false
		}
	}
}

// str: `name` oder "name" (nicht leer)
func (p *ruleParser) str() (string, bool) {
	p.space()
	if p.i >= len(p.s) || (p.s[p.i] != '`' && p.s[p.i] != '"') {
		return "", false
	}
	q := p.s[p.i]
	end := strings.IndexByte(p.s[p.i+1:], q)
	if end < 0 {
		return "", false
	}
	n := strings.TrimSpace(p.s[p.i+1 : p.i+1+end])
	p.i += end + 2
	return n, n != ""
}
