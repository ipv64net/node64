// Package metrics schreibt Kennzahlen im Textformat von Prometheus (text/plain; version=0.0.4).
// Kern und Module tragen ihre Werte ueber einen Writer bei; gleichnamige Werte werden zu einer
// Familie (ein HELP/TYPE) zusammengefasst, egal in welcher Reihenfolge sie kommen.
package metrics

import (
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// ContentType ist der Content-Type der Ausgabe.
const ContentType = "text/plain; version=0.0.4; charset=utf-8"

// Typ einer Familie.
const (
	Gauge   = "gauge"
	Counter = "counter"
)

var (
	nameRe  = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	labelRe = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
)

type family struct {
	help, typ string
	samples   []string
}

// Writer sammelt die Werte einer Abfrage. Nicht nebenlaeufig benutzen.
type Writer struct {
	order []string
	fams  map[string]*family
}

// New liefert einen leeren Writer.
func New() *Writer { return &Writer{fams: map[string]*family{}} }

// Gauge setzt einen Momentanwert. labels sind Paare Name, Wert.
func (w *Writer) Gauge(name, help string, v float64, labels ...string) {
	w.add(name, help, Gauge, v, labels)
}

// Counter setzt einen fortlaufenden Zaehler (Name sollte auf _total enden).
func (w *Writer) Counter(name, help string, v float64, labels ...string) {
	w.add(name, help, Counter, v, labels)
}

// Bool: 1 fuer true, 0 fuer false.
func Bool(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

func (w *Writer) add(name, help, typ string, v float64, labels []string) {
	if !nameRe.MatchString(name) || len(labels)%2 != 0 {
		return // Programmierfehler: lieber weglassen als die ganze Ausgabe ungueltig machen
	}
	f := w.fams[name]
	if f == nil {
		f = &family{help: help, typ: typ}
		w.fams[name] = f
		w.order = append(w.order, name)
	} else if f.typ != typ {
		return
	}
	var b strings.Builder
	b.WriteString(name)
	if len(labels) > 0 {
		b.WriteByte('{')
		for i := 0; i < len(labels); i += 2 {
			if !labelRe.MatchString(labels[i]) {
				return
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(labels[i])
			b.WriteString(`="`)
			b.WriteString(escapeLabel(labels[i+1]))
			b.WriteByte('"')
		}
		b.WriteByte('}')
	}
	b.WriteByte(' ')
	b.WriteString(formatValue(v))
	f.samples = append(f.samples, b.String())
}

// WriteTo schreibt alle Familien in der Reihenfolge ihres ersten Auftretens.
func (w *Writer) WriteTo(out io.Writer) (int64, error) {
	var b strings.Builder
	for _, name := range w.order {
		f := w.fams[name]
		if f.help != "" {
			b.WriteString("# HELP " + name + " " + escapeHelp(f.help) + "\n")
		}
		b.WriteString("# TYPE " + name + " " + f.typ + "\n")
		for _, s := range f.samples {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	n, err := io.WriteString(out, b.String())
	return int64(n), err
}

func formatValue(v float64) string {
	switch {
	case math.IsNaN(v):
		return "NaN"
	case math.IsInf(v, 1):
		return "+Inf"
	case math.IsInf(v, -1):
		return "-Inf"
	}
	return strconv.FormatFloat(v, 'g', -1, 64)
}

var (
	labelEsc = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	helpEsc  = strings.NewReplacer(`\`, `\\`, "\n", `\n`)
)

func escapeLabel(s string) string { return labelEsc.Replace(s) }
func escapeHelp(s string) string  { return helpEsc.Replace(s) }
