package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Helfer fuer die Positivlisten der Werkzeuge: Felder werden ausdruecklich ausgewaehlt, verschachtelte Objekte nur,
// wenn sie bekannt frei von Geheimnissen sind (plain). Feldnamen bleiben wie in der REST-API, damit die KI sie beim
// Aendern ueber /api wiedererkennt.

// pick: ausgewaehlte einfache Felder (Text, Zahl, Wahrheitswert, Liste solcher Werte). Zeiten werden RFC 3339 in
// UTC (Nullzeit faellt weg), Texte gesaeubert. Verschachtelte Objekte nimmt pick nie mit.
func pick(m obj, keys ...string) obj {
	o := obj{}
	for _, k := range keys {
		if v, ok := scalar(m[k], 300); ok {
			o[k] = v
		}
	}
	return o
}

// scalar: einfacher Wert bzw. Liste einfacher Werte; ok = false fuer Objekte und fehlende Werte.
func scalar(v any, max int) (any, bool) {
	switch x := v.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339Nano, x); err == nil {
			if t.Year() <= 1 {
				return nil, false
			}
			return t.UTC().Format(time.RFC3339), true
		}
		return clean(x, max), true
	case json.Number, bool, float64, int, int64:
		return x, true
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			if _, isObj := e.(map[string]any); isObj {
				continue
			}
			if sv, ok := scalar(e, max); ok {
				out = append(out, sv)
			}
		}
		return out, true
	}
	return nil, false
}

// pickList: pick fuer jedes Objekt einer Liste, hoechstens max Eintraege (0 = alle).
func pickList(v any, max int, keys ...string) []any {
	out := []any{}
	for _, e := range asArr(v) {
		if max > 0 && len(out) >= max {
			break
		}
		out = append(out, pick(asObj(e), keys...))
	}
	return out
}

// plain: Kopie einer Struktur, die bekannt frei von Geheimnissen ist (Schwellen, Zaehler, Zeitplaene). Texte
// gesaeubert, Tiefe begrenzt; der zentrale Filter (sanitize) laeuft danach trotzdem.
func plain(v any, depth int) any {
	if depth <= 0 {
		return nil
	}
	switch x := v.(type) {
	case map[string]any:
		out := obj{}
		for k, e := range x {
			if pv := plain(e, depth-1); pv != nil {
				out[k] = pv
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			if pv := plain(e, depth-1); pv != nil {
				out = append(out, pv)
			}
		}
		return out
	}
	if sv, ok := scalar(v, 300); ok {
		return sv
	}
	return nil
}

// setKeys: Namen der gesetzten Felder eines Objekts (z. B. Kanal-Konfiguration) ohne deren Werte.
func setKeys(v any) []string {
	out := []string{}
	for k, val := range asObj(v) {
		if s, ok := val.(string); ok && s == "" {
			continue
		}
		if val == nil {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// urlHost: nur Schema und Host einer Adresse (in Pfad und Query stehen oft Kennungen oder Tokens).
func urlHost(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" {
		return clean(s, 120)
	}
	return u.Scheme + "://" + u.Host
}

// first: erster vorhandener Wert unter mehreren Schreibweisen (z. B. "mode" bzw. "Mode").
func first(m obj, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return nil
}

// partSet: erlaubte Werte des Arguments "part" eines Werkzeugs mit Standard ("" = Pflicht).
type partSet struct {
	def  string
	list []string
}

func (p partSet) prop() schemaProp                     { return pEnum("part", "Which part.", p.def, p.list...) }
func (p partSet) arg(a map[string]any) (string, error) { return argPart(a, p.def, p.list...) }

// argPart: Parameter "part" (Teil der Daten) mit Standard und erlaubten Werten.
func argPart(a map[string]any, def string, allowed ...string) (string, error) {
	p := argStr(a, "part")
	if p == "" {
		p = def
	}
	for _, x := range allowed {
		if p == x {
			return p, nil
		}
	}
	return "", fmt.Errorf("unknown part %q (one of %s)", clean(p, 40), strings.Join(allowed, ", "))
}

// needID: Pflicht-Kennung fuer einen Teil (Zahl > 0).
func needID(a map[string]any, k, part string) (string, error) {
	n := argInt(a, k, 0, 0, maxID)
	if n <= 0 {
		return "", errors.New("parameter " + k + " is required for part " + part)
	}
	return strconv.Itoa(n), nil
}
