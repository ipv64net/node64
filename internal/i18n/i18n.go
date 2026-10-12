// Package i18n liefert Uebersetzungen aus eingebetteten JSON-Sprachdateien.
//
// Schluessel sind flach und mit Punkten gegliedert ("nav.dashboard").
// Platzhalter stehen in geschweiften Klammern: "Hallo {name}".
// Pluralformen: "key.one" und "key.other" (optional "key.zero"), gewaehlt
// ueber den Platzhalter "count".
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

//go:embed locales/*.json
var localeFS embed.FS

const Fallback = "en"

// Default ist die Sprache ohne passende Browser-Angabe (ipv64: Deutsch).
const Default = "de"

type Bundle struct {
	msgs  map[string]map[string]string
	langs []string
	tags  []language.Tag
}

// Load liest alle locales/<lang>.json.
func Load() (*Bundle, error) {
	b := &Bundle{msgs: map[string]map[string]string{}}
	entries, err := fs.ReadDir(localeFS, "locales")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		lang := strings.TrimSuffix(e.Name(), ".json")
		raw, err := fs.ReadFile(localeFS, "locales/"+e.Name())
		if err != nil {
			return nil, err
		}
		var nested map[string]any
		if err := json.Unmarshal(raw, &nested); err != nil {
			return nil, fmt.Errorf("locale %s: %w", lang, err)
		}
		flat := map[string]string{}
		flatten("", nested, flat)
		b.msgs[lang] = flat
		b.langs = append(b.langs, lang)
	}
	if _, ok := b.msgs[Fallback]; !ok {
		return nil, fmt.Errorf("locale %s missing", Fallback)
	}
	sort.Strings(b.langs)
	// Fallback zuerst, damit der Matcher ihn als Standard nimmt
	sort.SliceStable(b.langs, func(i, j int) bool { return b.langs[i] == Default && b.langs[j] != Default })
	for _, l := range b.langs {
		b.tags = append(b.tags, language.Make(l))
	}
	return b, nil
}

func flatten(prefix string, in map[string]any, out map[string]string) {
	for k, v := range in {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		switch t := v.(type) {
		case map[string]any:
			flatten(key, t, out)
		case string:
			out[key] = t
		default:
			out[key] = fmt.Sprint(t)
		}
	}
}

// Languages liefert die verfuegbaren Sprachen.
func (b *Bundle) Languages() []string { return append([]string{}, b.langs...) }

// Has sagt, ob eine Sprache existiert.
func (b *Bundle) Has(lang string) bool { _, ok := b.msgs[lang]; return ok }

// Match waehlt aus einem Accept-Language-Header die beste verfuegbare Sprache.
func (b *Bundle) Match(acceptLanguage string) string {
	if acceptLanguage == "" {
		return b.def()
	}
	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil || len(tags) == 0 {
		return b.def()
	}
	_, idx, conf := language.NewMatcher(b.tags).Match(tags...)
	if conf == language.No || idx < 0 || idx >= len(b.langs) {
		return b.def()
	}
	return b.langs[idx]
}

// T uebersetzt key in lang. args sind Paare name, wert fuer Platzhalter.
// Unbekannte Schluessel kommen als Schluessel zurueck, damit sie auffallen.
func (b *Bundle) T(lang, key string, args ...any) string {
	vars := map[string]string{}
	var count *int64
	for i := 0; i+1 < len(args); i += 2 {
		name := fmt.Sprint(args[i])
		vars[name] = fmt.Sprint(args[i+1])
		if name == "count" {
			if n, ok := toInt(args[i+1]); ok {
				count = &n
				vars[name] = b.FormatInt(lang, n)
			}
		}
	}
	msg, ok := b.lookup(lang, key, count)
	if !ok {
		return key
	}
	if len(vars) == 0 {
		return msg
	}
	for k, v := range vars {
		msg = strings.ReplaceAll(msg, "{"+k+"}", v)
	}
	return msg
}

func (b *Bundle) lookup(lang, key string, count *int64) (string, bool) {
	for _, l := range []string{lang, Fallback} {
		m, ok := b.msgs[l]
		if !ok {
			continue
		}
		if count != nil {
			if *count == 0 {
				if s, ok := m[key+".zero"]; ok {
					return s, true
				}
			}
			if *count == 1 {
				if s, ok := m[key+".one"]; ok {
					return s, true
				}
			}
			if s, ok := m[key+".other"]; ok {
				return s, true
			}
		}
		if s, ok := m[key]; ok {
			return s, true
		}
	}
	return "", false
}

func toInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case int32:
		return int64(t), true
	case uint:
		return int64(t), true
	case float64:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// FormatInt formatiert eine ganze Zahl nach Locale (Tausendertrennung).
func (b *Bundle) FormatInt(lang string, n int64) string {
	return message.NewPrinter(language.Make(lang)).Sprintf("%d", n)
}

// FormatFloat formatiert eine Dezimalzahl mit festen Nachkommastellen.
func (b *Bundle) FormatFloat(lang string, f float64, decimals int) string {
	return message.NewPrinter(language.Make(lang)).Sprintf("%.*f", decimals, f)
}

// FormatDateTime formatiert Datum und Uhrzeit in der Zeitzone des Nutzers.
func (b *Bundle) FormatDateTime(lang string, t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "–"
	}
	if loc != nil {
		t = t.In(loc)
	}
	if lang == "de" {
		return t.Format("02.01.2006 15:04:05")
	}
	return t.Format("2006-01-02 15:04:05")
}

// FormatDate formatiert nur das Datum.
func (b *Bundle) FormatDate(lang string, t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "–"
	}
	if loc != nil {
		t = t.In(loc)
	}
	if lang == "de" {
		return t.Format("02.01.2006")
	}
	return t.Format("2006-01-02")
}

// FormatDuration gibt eine Dauer lesbar aus, z. B. "2 h 5 min" oder "12 s".
func (b *Bundle) FormatDuration(lang string, d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int64(d.Hours() / 24)
	h := int64(d.Hours()) % 24
	m := int64(d.Minutes()) % 60
	s := int64(d.Seconds()) % 60
	var parts []string
	if days > 0 {
		parts = append(parts, b.T(lang, "time.days", "count", days))
	}
	if h > 0 {
		parts = append(parts, fmt.Sprintf("%d h", h))
	}
	if m > 0 && days == 0 {
		parts = append(parts, fmt.Sprintf("%d min", m))
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%d s", s))
	}
	return strings.Join(parts, " ")
}

// def liefert die Standardsprache (Deutsch, sonst die Rueckfallsprache).
func (b *Bundle) def() string {
	if b.Has(Default) {
		return Default
	}
	return Fallback
}
