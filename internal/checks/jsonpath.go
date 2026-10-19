package checks

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// JSON-Check (Typ json): wie http, dazu Bedingungen auf Werte in der JSON-Antwort.

// JSONRule ist eine Bedingung: Pfad (z. B. "data.items[0].status"), Vergleich und erwarteter Wert.
type JSONRule struct {
	Path  string `json:"path"`
	Op    string `json:"op"`              // eq, ne, lt, le, gt, ge, contains, not_contains, regex, exists, not_exists
	Value string `json:"value,omitempty"` // Zahl, Text, true/false oder null
}

// JSONOps sind die erlaubten Vergleiche in Anzeigereihenfolge.
var JSONOps = []string{"eq", "ne", "lt", "le", "gt", "ge", "contains", "not_contains", "regex", "exists", "not_exists"}

const maxJSONRules = 10

type pathStep struct {
	key   string
	index int // >= 0: Array-Index statt Schluessel
}

// parseJSONPath zerlegt "a.b[0].c" (optional mit "$." vorne) in Schritte.
func parseJSONPath(p string) ([]pathStep, error) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(strings.TrimPrefix(p, "$"), ".")
	if p == "" {
		return nil, nil // die ganze Antwort
	}
	var out []pathStep
	for _, part := range strings.Split(p, ".") {
		if part == "" {
			return nil, fmt.Errorf("json path %q: empty segment", p)
		}
		key := part
		rest := ""
		if i := strings.IndexByte(part, '['); i >= 0 {
			key, rest = part[:i], part[i:]
		}
		if key != "" {
			out = append(out, pathStep{key: key, index: -1})
		}
		for rest != "" {
			j := strings.IndexByte(rest, ']')
			if rest[0] != '[' || j < 0 {
				return nil, fmt.Errorf("json path %q: bad index", p)
			}
			n, err := strconv.Atoi(rest[1:j])
			if err != nil || n < 0 {
				return nil, fmt.Errorf("json path %q: index must be a number >= 0", p)
			}
			out = append(out, pathStep{index: n})
			rest = rest[j+1:]
		}
	}
	return out, nil
}

// lookupJSON folgt dem Pfad; found = false, wenn es ihn nicht gibt.
func lookupJSON(doc any, steps []pathStep) (any, bool) {
	cur := doc
	for _, s := range steps {
		if s.index >= 0 {
			arr, ok := cur.([]any)
			if !ok || s.index >= len(arr) {
				return nil, false
			}
			cur = arr[s.index]
			continue
		}
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = obj[s.key]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// jsonText: Wert als Text fuer Meldungen und Vergleiche.
func jsonText(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func jsonNumber(v any) (float64, bool) {
	switch x := v.(type) {
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil && !math.IsNaN(f)
	}
	return 0, false
}

// validateJSONRules prueft die Bedingungen (Pfad, Vergleich, Regex, Zahlen bei < >).
func validateJSONRules(rules []JSONRule) error {
	if len(rules) == 0 {
		return errors.New("at least one json rule is required")
	}
	if len(rules) > maxJSONRules {
		return fmt.Errorf("at most %d json rules", maxJSONRules)
	}
	for i, r := range rules {
		if _, err := parseJSONPath(r.Path); err != nil {
			return fmt.Errorf("json rule %d: %w", i+1, err)
		}
		known := false
		for _, op := range JSONOps {
			known = known || op == r.Op
		}
		if !known {
			return fmt.Errorf("json rule %d: unknown op %q", i+1, r.Op)
		}
		switch r.Op {
		case "lt", "le", "gt", "ge":
			if _, err := strconv.ParseFloat(strings.TrimSpace(r.Value), 64); err != nil {
				return fmt.Errorf("json rule %d: %s needs a number", i+1, r.Op)
			}
		case "regex":
			if _, err := regexp.Compile(r.Value); err != nil {
				return fmt.Errorf("json rule %d: %w", i+1, err)
			}
		}
	}
	return nil
}

// evalJSONRule wertet eine Bedingung aus; text ist der gefundene Wert (fuer die Meldung).
func evalJSONRule(doc any, r JSONRule) (ok bool, text string, err error) {
	steps, err := parseJSONPath(r.Path)
	if err != nil {
		return false, "", err
	}
	v, found := lookupJSON(doc, steps)
	switch r.Op {
	case "exists":
		return found, jsonText(v), nil
	case "not_exists":
		return !found, "", nil
	}
	if !found {
		return false, "(missing)", nil
	}
	text = jsonText(v)
	want := strings.TrimSpace(r.Value)
	switch r.Op {
	case "eq", "ne":
		eq := text == want
		if a, ok1 := jsonNumber(v); ok1 {
			if b, err := strconv.ParseFloat(want, 64); err == nil {
				eq = a == b
			}
		}
		return eq == (r.Op == "eq"), text, nil
	case "lt", "le", "gt", "ge":
		a, ok1 := jsonNumber(v)
		b, err := strconv.ParseFloat(want, 64)
		if !ok1 || err != nil {
			return false, text, nil
		}
		switch r.Op {
		case "lt":
			return a < b, text, nil
		case "le":
			return a <= b, text, nil
		case "gt":
			return a > b, text, nil
		}
		return a >= b, text, nil
	case "contains", "not_contains":
		has := strings.Contains(text, r.Value)
		if arr, isArr := v.([]any); isArr { // Array: ein Element ist gleich dem Wert
			has = false
			for _, e := range arr {
				has = has || jsonText(e) == want
			}
		}
		return has == (r.Op == "contains"), text, nil
	case "regex":
		re, err := regexp.Compile(r.Value)
		if err != nil {
			return false, text, err
		}
		return re.MatchString(text), text, nil
	}
	return false, text, fmt.Errorf("unknown op %q", r.Op)
}

// opSymbol fuer Meldungen.
func opSymbol(op string) string {
	switch op {
	case "eq":
		return "=="
	case "ne":
		return "!="
	case "lt":
		return "<"
	case "le":
		return "<="
	case "gt":
		return ">"
	case "ge":
		return ">="
	}
	return op
}

// checkJSONBody wertet alle Bedingungen auf body aus. anyOf = eine erfuellte genuegt. Liefert die Meldung des
// ersten Fehlers (bzw. die Zusammenfassung) und den Wert der ersten Bedingung (fuer Details/Verlauf).
func checkJSONBody(body []byte, rules []JSONRule, anyOf bool) (pass bool, reason Reason, msg string, first any) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	var doc interface{}
	if err := dec.Decode(&doc); err != nil {
		return false, ReasonJSONInvalid, "response is not valid JSON: " + err.Error(), nil
	}
	var fails []string
	passed := 0
	for i, r := range rules {
		ok, text, err := evalJSONRule(doc, r)
		if i == 0 {
			if steps, perr := parseJSONPath(r.Path); perr == nil {
				first, _ = lookupJSON(doc, steps)
			}
		}
		if err != nil {
			return false, ReasonInvalid, err.Error(), first
		}
		if ok {
			passed++
			continue
		}
		cond := r.Path + " " + opSymbol(r.Op)
		if r.Op != "exists" && r.Op != "not_exists" {
			cond += " " + r.Value
		}
		fails = append(fails, fmt.Sprintf("%s (is %s)", cond, text))
	}
	if (anyOf && passed > 0) || (!anyOf && len(fails) == 0) {
		return true, ReasonOK, "", first
	}
	return false, ReasonJSONMismatch, "json: " + strings.Join(fails, "; "), first
}

// Textform der Bedingungen (Formular): eine je Zeile, "Pfad Vergleich Wert", z. B. "status == ok",
// "queue < 100", "tags contains b", "version exists", "name ~ ^web-[0-9]+$".
var opWords = map[string]string{"==": "eq", "=": "eq", "!=": "ne", "<": "lt", "<=": "le", ">": "gt", ">=": "ge",
	"contains": "contains", "!contains": "not_contains", "~": "regex", "exists": "exists", "!exists": "not_exists"}

// ParseJSONRules liest die Textform; leere Zeilen und Zeilen mit # werden uebergangen.
func ParseJSONRules(text string) ([]JSONRule, error) {
	var out []JSONRule
	for n, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			return nil, fmt.Errorf("line %d: expected \"path operator value\"", n+1)
		}
		op, ok := opWords[f[1]]
		if !ok {
			return nil, fmt.Errorf("line %d: unknown operator %q", n+1, f[1])
		}
		r := JSONRule{Path: f[0], Op: op}
		if op != "exists" && op != "not_exists" {
			// Wert: Rest der Zeile (darf Leerzeichen enthalten), Anfuehrungszeichen aussen weg
			i := strings.Index(line, f[1]) + len(f[1])
			r.Value = strings.TrimSpace(line[i:])
			if len(r.Value) >= 2 && r.Value[0] == '"' && r.Value[len(r.Value)-1] == '"' {
				r.Value = r.Value[1 : len(r.Value)-1]
			}
		} else if len(f) > 2 {
			return nil, fmt.Errorf("line %d: %s takes no value", n+1, f[1])
		}
		out = append(out, r)
	}
	return out, nil
}

// FormatJSONRules ist die Textform fuer das Formular.
func FormatJSONRules(rules []JSONRule) string {
	sym := map[string]string{"eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=", "contains": "contains",
		"not_contains": "!contains", "regex": "~", "exists": "exists", "not_exists": "!exists"}
	var lines []string
	for _, r := range rules {
		l := r.Path + " " + sym[r.Op]
		if r.Op != "exists" && r.Op != "not_exists" {
			l += " " + r.Value
		}
		lines = append(lines, l)
	}
	return strings.Join(lines, "\n")
}
