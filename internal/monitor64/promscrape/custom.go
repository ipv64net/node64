package promscrape

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/monitor64/model"
)

// Eigene Metriken: fuer beliebige Exporter eine Liste "Metrik-Name + Label-Filter -> Messgroesse mit Einheit und
// Faktor". Jede passende Serie wird ein Dienst "prom:<name>{labels}" (Art "prom", nur Anzeige/Verlauf; Schwellen
// setzt man am Dienst). Zaehler optional als Rate je Sekunde.

// Grenzen der eigenen Metriken.
const (
	MaxCustom          = 50  // Eintraege je Zugang
	maxCustomLabels    = 16  // Filter-Labels je Eintrag
	maxCustomPerEntry  = 20  // passende Serien je Eintrag
	maxCustomServices  = 100 // Dienste aus eigenen Metriken insgesamt
	maxCustomKeyLength = 200 // laengere Schluessel werden gekuerzt (mit Pruefsumme)
)

// CustomMetric ist eine eigene Metrik (Konfiguration des Zugangs, JSON).
type CustomMetric struct {
	Name   string            `json:"name"`             // Metrik-Name, z. B. "nginx_connections_active"
	Labels map[string]string `json:"labels,omitempty"` // muessen exakt passen ("" = Label fehlt bzw. leer)
	Title  string            `json:"title,omitempty"`  // Anzeigename (leer = Name)
	Unit   string            `json:"unit,omitempty"`   // z. B. "%", "B", "B/s", "°C", "ms"
	Factor float64           `json:"factor,omitempty"` // Wert * Faktor (0 = 1)
	Rate   bool              `json:"rate,omitempty"`   // Zaehler: Aenderung je Sekunde
}

// ValidateCustom prueft die Liste (Kern: beim Speichern des Zugangs).
func ValidateCustom(l []CustomMetric) error {
	if len(l) > MaxCustom {
		return errors.New(model.T("monitor64.txt.pm_custom_max", "n", MaxCustom))
	}
	for i, c := range l {
		if c.Name == "" || len(c.Name) > 200 {
			return errors.New(model.T("monitor64.txt.pm_custom_name_n", "n", i+1))
		}
		for j := 0; j < len(c.Name); j++ {
			if !isNameChar(c.Name[j], j == 0) {
				return errors.New(model.T("monitor64.txt.pm_custom_name_bad", "name", clip(c.Name, 60)))
			}
		}
		if len(c.Labels) > maxCustomLabels {
			return errors.New(model.T("monitor64.txt.pm_custom_labels", "name", c.Name, "n", maxCustomLabels))
		}
		for k, v := range c.Labels {
			if k == "" || len(k) > 100 || len(v) > 200 {
				return errors.New(model.T("monitor64.txt.pm_custom_label_bad", "name", c.Name))
			}
		}
		if len(c.Title) > 100 || len(c.Unit) > 16 {
			return errors.New(model.T("monitor64.txt.pm_custom_title_long", "name", c.Name))
		}
		if !finite(c.Factor) {
			return errors.New(model.T("monitor64.txt.pm_custom_factor", "name", c.Name))
		}
	}
	return nil
}

// rateState ist der vorige Wert eines Zaehlers.
type rateState struct {
	t time.Time
	v float64
}

// customServices bildet die eigenen Metriken ab; prev haelt die Zaehler fuer Raten (wird ersetzt).
func customServices(m *Metrics, list []CustomMetric, now time.Time, prev map[string]rateState) ([]model.Service, map[string]rateState) {
	if len(list) == 0 {
		return nil, nil
	}
	next := map[string]rateState{}
	var out []model.Service
	used := map[string]bool{}
	for _, c := range list {
		var matches []*Sample
		ss := m.Get(c.Name)
		for i := range ss {
			if matchLabels(&ss[i], c.Labels) {
				matches = append(matches, &ss[i])
				if len(matches) >= maxCustomPerEntry {
					break
				}
			}
		}
		for _, s := range matches {
			if len(out) >= maxCustomServices {
				return out, next
			}
			key := customKey(s)
			if used[key] {
				continue
			}
			used[key] = true
			name := firstNonEmpty(clip(c.Title, 100), c.Name)
			if len(matches) > 1 {
				if d := distinct(s, c.Labels); d != "" {
					name += " (" + d + ")"
				}
			}
			sv := model.Service{Key: key, Name: model.Raw(clip(name, 200)), Kind: "prom", Default: true}
			f := c.Factor
			if f == 0 {
				f = 1
			}
			v, ok := s.Value, finite(s.Value)
			if ok && c.Rate {
				next[key] = rateState{t: now, v: v}
				p, had := prev[key]
				dt := now.Sub(p.t).Seconds()
				if !had || dt <= 0 || v < p.v { // erste Runde bzw. Zaehler zurueckgesetzt
					ok = false
				} else {
					v = (v - p.v) / dt
				}
			}
			if ok {
				v *= f
				ok = finite(v)
			}
			if ok {
				sv.Metrics = []model.Metric{{Name: "value", Value: round4(v), Unit: clip(c.Unit, 16)}}
				sv.Text = strings.TrimSpace(formatValue(v) + " " + model.Raw(clip(c.Unit, 16)))
			} else if !c.Rate || !finite(s.Value) {
				sv.Text = model.T("monitor64.txt.no_valid_value")
			}
			out = append(out, sv)
		}
	}
	return out, next
}

func matchLabels(s *Sample, want map[string]string) bool {
	for k, v := range want {
		if s.Label(k) != v {
			return false
		}
	}
	return true
}

// customKey: "prom:<name>{l1="v1",...}" (Labels sortiert); zu lang -> gekuerzt mit Pruefsumme.
func customKey(s *Sample) string {
	ls := append([]Label(nil), s.Labels...)
	sort.Slice(ls, func(i, j int) bool { return ls[i].Name < ls[j].Name })
	var b strings.Builder
	b.WriteString("prom:" + s.Name)
	if len(ls) > 0 {
		b.WriteByte('{')
		for i, l := range ls {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(l.Name + "=" + strconv.Quote(l.Value))
		}
		b.WriteByte('}')
	}
	k := b.String()
	if len(k) <= maxCustomKeyLength {
		return k
	}
	h := sha256.Sum256([]byte(k))
	cut := maxCustomKeyLength - 17
	return strings.ToValidUTF8(k[:cut], "") + "#" + hex.EncodeToString(h[:8])
}

// distinct: Labels, die nicht im Filter stehen ("a=1, b=2"), fuer den Anzeigenamen mehrerer Treffer.
func distinct(s *Sample, filter map[string]string) string {
	var parts []string
	for _, l := range s.Labels {
		if _, ok := filter[l.Name]; !ok {
			parts = append(parts, l.Name+"="+l.Value)
		}
	}
	sort.Strings(parts)
	return clip(strings.Join(parts, ", "), 120)
}

func formatValue(v float64) string {
	a := math.Abs(v)
	switch {
	case a >= 1e6 || (a > 0 && a < 0.001):
		return strconv.FormatFloat(v, 'g', 4, 64)
	case a >= 100:
		return strconv.FormatFloat(v, 'f', 0, 64)
	}
	return strings.TrimRight(strings.TrimRight(strconv.FormatFloat(v, 'f', 2, 64), "0"), ".")
}

func round4(v float64) float64 {
	if math.Abs(v) >= 1e12 {
		return v
	}
	return math.Round(v*10000) / 10000
}
