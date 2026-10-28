package cdn64

import (
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// Traefik-Labels mitlesen (Phase D3, docs/PLAN-PROXY64-DOCKER.md Abschnitt 7). Ausgewertet werden nur
// traefik.enable, traefik.http.routers.<r>.rule (nur Host(...)) und .service, traefik.http.services.<s>.loadbalancer
// .server.port/.scheme und traefik.docker.network, dazu .middlewares (traefikMiddlewares: forwardAuth wird zur
// Zugriffsliste, harmlose Arten wie headers bleiben unbeachtet, alle anderen verlangen eine Zugriffsliste gleichen
// Namens, sonst kommt ein neuer Host ausgeschaltet; Plan docs/PLAN-PROXY64-FORWARDAUTH.md). Entrypoints,
// TLS/Certresolver, Prioritaet sowie TCP/UDP-Router bleiben unbeachtet; Router fuer den Rueckweg von authentik
// (/outpost.goauthentik.io/) braucht es nicht. Schluessel sind wie bei Traefik unabhaengig von Gross-/Kleinschreibung.

const (
	traefikRouterPrefix  = "traefik.http.routers."
	traefikServicePrefix = "traefik.http.services."
)

// traefikSpecs: je Traefik-Router mit Host(...)-Regel ein Host, sortiert nach Router-Name. Router mit gleichen Namen
// und gleichem Ziel (z. B. http- und https-Router) ergeben nur einen Host (der alphabetisch erste Router).
// shared: Middleware-Definitionen aller Container (traefik.http.middlewares.*, klein geschrieben) - wie bei Traefik
// darf eine Middleware an einem anderen Container stehen (z. B. authentik am authentik-Container).
func traefikSpecs(labels, shared map[string]string) ([]dockerSpec, []dockerProblem) {
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
	seen := map[string]int{} // Namensmenge + Ziel -> Index in specs
	for _, r := range routers {
		if strings.Contains(l[traefikRouterPrefix+r+".rule"], "/outpost.goauthentik.io") { // Rueckweg macht die Zugriffsliste
			continue
		}
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
		s.Access, s.Middlewares, s.Ignored = traefikMiddlewares(l, shared, r)
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
		if i, ok := seen[key]; ok {
			// gleicher Host ueber mehrere Router (z. B. web mit Umleitung, websecure ohne): es gilt der mit den wenigsten
			// nicht uebernommenen Middlewares - Traefik liefert den Dienst ueber diesen Router ja auch so aus
			if o := specs[i]; len(s.Middlewares) < len(o.Middlewares) || len(s.Middlewares) == len(o.Middlewares) && len(s.Ignored) < len(o.Ignored) {
				specs[i].Access, specs[i].Middlewares, specs[i].Ignored = s.Access, s.Middlewares, s.Ignored
			}
			continue
		}
		seen[key] = len(specs)
		specs = append(specs, s)
	}
	return specs, probs
}

// traefikHarmless: Middleware-Arten ohne Zugriffsschutz (aendern nur Header, Pfade, Komprimierung, Takt ...).
var traefikHarmless = map[string]bool{"headers": true, "redirectscheme": true, "redirectregex": true, "compress": true, "stripprefix": true,
	"stripprefixregex": true, "addprefix": true, "replacepath": true, "replacepathregex": true, "ratelimit": true, "inflightreq": true,
	"retry": true, "buffering": true, "circuitbreaker": true, "errors": true, "contenttype": true}

// traefikMiddlewares: die erste Middleware des Routers mit forwardAuth in den Labels wird die Zugriffsliste
// "Traefik: <name> (<host:port des Dienstes>)" (andere Adresse = andere Liste). Harmlose Arten (traefikHarmless) bzw.
// nicht einsehbare mit harmlosem Namen (traefikHarmlessName) kommen nach ignored; alle anderen (basicAuth,
// ipAllowList, chain, unbekannt) nach rest - sie brauchen eine Zugriffsliste gleichen Namens.
func traefikMiddlewares(l, shared map[string]string, router string) (access *dockerAccess, rest, ignored []string) {
	get := func(k string) string {
		if v := l[k]; v != "" {
			return v
		}
		return shared[k]
	}
	for _, mw := range strings.Split(l[traefikRouterPrefix+router+".middlewares"], ",") {
		mw = strings.TrimSpace(mw)
		name, provider, _ := strings.Cut(strings.ToLower(mw), "@")
		if name == "" {
			continue
		}
		local := provider == "" || provider == "docker"
		p := "traefik.http.middlewares." + name + "."
		if addr := get(p + "forwardauth.address"); addr != "" && local && access == nil {
			var hs []string
			for _, h := range strings.Split(get(p+"forwardauth.authresponseheaders"), ",") {
				if h = strings.TrimSpace(h); h != "" {
					hs = append(hs, h)
				}
			}
			host := addr
			if u, err := url.Parse(addr); err == nil && u.Host != "" {
				host = u.Host
			}
			access = &dockerAccess{Name: "Traefik: " + name + " (" + host + ")", Auth: fwdKindOf(addr), Forward: &ForwardAuth{Address: addr, Headers: hs}}
			continue
		}
		kinds := traefikKinds(l, p)
		if kinds == nil {
			kinds = traefikKinds(shared, p)
		}
		switch {
		case local && kinds != nil && allHarmless(kinds), (!local || kinds == nil) && traefikHarmlessName(name):
			ignored = append(ignored, mw)
		default:
			rest = append(rest, mw)
		}
	}
	return access, rest, ignored
}

// traefikHarmlessName: Middleware, deren Art PROXY64 nicht sieht (Datei, anderer Anbieter), aber deren Name klar auf
// Umleitung, Header, Komprimierung o. Ae. zeigt - nicht auf Zugang (auth, allow, ip, chain, secured ...).
func traefikHarmlessName(n string) bool {
	for _, k := range []string{"auth", "sso", "login", "allow", "white", "ip", "basic", "digest", "chain", "secured", "protect",
		"private", "internal", "lan", "admin", "access", "deny", "block"} {
		if strings.Contains(n, k) {
			return false
		}
	}
	for _, k := range []string{"redirect", "https", "header", "hsts", "compress", "gzip", "strip", "prefix", "ratelimit", "rate-limit",
		"retry", "buffer", "cors", "error"} {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// traefikKinds: Arten einer in den Labels definierten Middleware (nil = nicht in den Labels).
func traefikKinds(l map[string]string, prefix string) []string {
	var out []string
	for k := range l {
		if r, ok := strings.CutPrefix(k, prefix); ok {
			if kind, _, _ := strings.Cut(r, "."); kind != "" && !slices.Contains(out, kind) {
				out = append(out, kind)
			}
		}
	}
	return out
}

func allHarmless(kinds []string) bool {
	for _, k := range kinds {
		if !traefikHarmless[k] {
			return false
		}
	}
	return true
}

// fwdKindOf: Vorlage nach der Adresse des Dienstes.
func fwdKindOf(addr string) string {
	switch a := strings.ToLower(addr); {
	case strings.Contains(a, "/outpost.goauthentik.io/"):
		return AuthAuthentik
	case strings.Contains(a, "/api/authz/") || strings.Contains(a, "/api/verify"):
		return AuthAuthelia
	case strings.Contains(a, "/oauth2/"):
		return AuthOAuth2
	}
	return AuthCustom
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
