package dns64

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

// Eigene Filterregeln im AdGuard/Adblock-Stil (Forum 5162, #70; filter/rules.go) als Textfeld auf der Seite
// Blocklisten und in der API, dazu die Suche "In welcher Liste steht diese Domain?" (#122) aus denselben Regeln,
// mit denen der DNS-Dienst antwortet.

// rulesText: eigene Sperrliste und Freigaben als Regeln fuer das Textfeld.
func (m *Module) rulesText() (string, error) {
	a, err := m.allowlist()
	if err != nil {
		return "", err
	}
	d, err := m.denylist()
	if err != nil {
		return "", err
	}
	return filter.RulesText(a, d), nil
}

// replaceRules setzt Sperrliste und Freigaben auf die Regeln aus lines (Cluster, Cache, Audit wie die Einzelfelder).
func (m *Module) replaceRules(r *http.Request, lines []string) (filter.RulesResult, error) {
	a, err := m.allowlist()
	if err != nil {
		return filter.RulesResult{}, err
	}
	d, err := m.denylist()
	if err != nil {
		return filter.RulesResult{}, err
	}
	res, err := filter.ReplaceRules(a, d, lines)
	if err != nil {
		return res, err
	}
	m.clChanged(r.Context(), ItemAllow)
	m.clChanged(r.Context(), ItemDeny)
	if e := m.running(); e != nil && res.Added+res.Removed > 0 {
		e.cache.Flush() // neue Sperren sofort, nicht erst nach Ablauf im Cache
	}
	m.audit(r, "dns64.rules.replace", strconv.Itoa(res.Deny)+" block "+strconv.Itoa(res.Allow)+" allow", "+"+strconv.Itoa(res.Added)+" -"+strconv.Itoa(res.Removed))
	return res, nil
}

// ruleErrText: Meldung zu einer abgelehnten Regel (Einzelfelder Freigeben/Sperren); ok = bekannter Regelfehler.
func (m *Module) ruleErrText(r *http.Request, err error) (string, bool) {
	switch {
	case errors.Is(err, filter.ErrRuleClient):
		return m.g.T(r, "dns64.rules.err_client"), true
	case errors.Is(err, filter.ErrRuleExact):
		return m.g.T(r, "dns64.rules.err_exact"), true
	case errors.Is(err, filter.ErrRuleAllow):
		return m.g.T(r, "dns64.rules.err_allow"), true
	case errors.Is(err, filter.ErrInvalidDomain):
		return m.g.T(r, "dns64.err_domain"), true
	}
	return "", false
}

// rulesMsg: Rueckmeldung nach dem Speichern (Zahlen, Doppelte, ungueltige Zeilen mit Hinweis auf $client).
func (m *Module) rulesMsg(r *http.Request, res filter.RulesResult) (string, string) {
	msg := m.g.T(r, "dns64.rules.saved", "deny", res.Deny, "allow", res.Allow, "added", res.Added, "removed", res.Removed)
	if res.Duplicates > 0 {
		msg += " · " + m.g.T(r, "dns64.deny.text_dup", "n", res.Duplicates)
	}
	level := "success"
	if len(res.Invalid) > 0 {
		msg += " · " + m.g.T(r, "dns64.deny.text_invalid", "n", len(res.Invalid), "list", strings.Join(res.Invalid, ", "))
		level = "warning"
	}
	if res.Client > 0 {
		msg += " " + m.g.T(r, "dns64.rules.err_client")
	}
	if res.Exact > 0 {
		msg += " " + m.g.T(r, "dns64.rules.err_exact")
	}
	return level, msg
}

func (m *Module) pageRulesSave(w http.ResponseWriter, r *http.Request) {
	res, err := m.replaceRules(r, strings.Split(r.PostFormValue("rules"), "\n"))
	switch {
	case errors.Is(err, filter.ErrInvalidDomain):
		msg := m.g.T(r, "dns64.deny.text_invalid_all", "list", strings.Join(res.Invalid, ", "))
		if res.Client > 0 {
			msg += " " + m.g.T(r, "dns64.rules.err_client")
		}
		m.g.Flash(w, r, "danger", msg)
	case err != nil:
		m.g.Flash(w, r, "danger", err.Error())
	default:
		level, msg := m.rulesMsg(r, res)
		m.log.Info("filter rules replaced", "block", res.Deny, "allow", res.Allow, "added", res.Added, "removed", res.Removed, "by", m.g.Actor(r))
		m.g.Flash(w, r, level, msg)
	}
	http.Redirect(w, r, "/dns64/lists#eigene-regeln", http.StatusSeeOther)
}

// apiRules: eigene Regeln als Text ({"rules": "…"}, eine Regel je Zeile).
func (m *Module) apiRules(w http.ResponseWriter, r *http.Request) {
	text, err := m.rulesText()
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"rules": text})
}

// apiRulesReplace ersetzt Sperrliste und Freigaben ({"rules": ["||a.example^", "@@||b.example^"]}).
func (m *Module) apiRulesReplace(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Rules []string `json:"rules"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&in); err != nil || in.Rules == nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON (rules)")
		return
	}
	res, err := m.replaceRules(r, in.Rules)
	if errors.Is(err, filter.ErrInvalidDomain) {
		writeJSON(w, http.StatusUnprocessableEntity, res)
		return
	}
	if err != nil {
		m.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// apiLookup: In welchen Listen und Regeln steht eine Domain? (?domain=…; auch als Regel wie ||example.com^)
// Dazu die eigenen Sperren und Freigaben der Geraetegruppen.
func (m *Module) apiLookup(w http.ResponseWriter, r *http.Request) {
	e := m.running()
	if e == nil {
		writeErr(w, http.StatusServiceUnavailable, errNotRunning.Error())
		return
	}
	rule, tok, err := filter.ParseRule(r.URL.Query().Get("domain"))
	if tok == "" || err != nil {
		writeErr(w, http.StatusBadRequest, m.g.T(r, "dns64.err_domain"))
		return
	}
	out := e.lists.Lookup(rule.Domain)
	if pol := m.pol.Load(); pol != nil {
		for _, p := range *pol {
			if d, ok := p.Allow.Match(rule.Domain); ok {
				out.Groups = append(out.Groups, filter.LookupGroup{Group: p.Group, Kind: "allow", Entry: d})
			}
			if d, ok := p.Block.Match(rule.Domain); ok {
				out.Groups = append(out.Groups, filter.LookupGroup{Group: p.Group, Kind: "block", Entry: d})
			}
		}
	}
	sort.Slice(out.Groups, func(i, j int) bool { return out.Groups[i].Group < out.Groups[j].Group })
	writeJSON(w, http.StatusOK, out)
}
