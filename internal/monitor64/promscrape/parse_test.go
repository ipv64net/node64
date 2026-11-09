package promscrape

import (
	"bytes"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
)

func TestParseLines(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    map[string]int // Name -> Anzahl Serien
		skipped int
		check   func(t *testing.T, m *Metrics)
	}{
		{name: "einfach", in: "a 1\nb_total{x=\"1\"} 2.5\n", want: map[string]int{"a": 1, "b_total": 1}},
		{name: "kommentare und leerzeilen", in: "# HELP a Hilfe mit { und \"\n# TYPE a gauge\n\n   \na 1\n# EOF\n", want: map[string]int{"a": 1},
			check: func(t *testing.T, m *Metrics) {
				if m.Type("a") != "gauge" {
					t.Errorf("type = %q", m.Type("a"))
				}
			}},
		{name: "escapes", in: `x{p="C:\\Windows\\sys",q="a\"b",n="z\nz",u="\x2d"} 1` + "\n", want: map[string]int{"x": 1},
			check: func(t *testing.T, m *Metrics) {
				s := m.Get("x")[0]
				if s.Label("p") != `C:\Windows\sys` || s.Label("q") != `a"b` || s.Label("n") != "z\nz" || s.Label("u") != `\x2d` {
					t.Errorf("labels = %#v", s.Labels)
				}
			}},
		{name: "zeitstempel", in: "a 1 1700000000000\nb 2 1700000000.123\nc 3 kaputt\n", want: map[string]int{"a": 1, "b": 1}, skipped: 1},
		{name: "nan inf", in: "a NaN\nb +Inf\nc -Inf\nd Inf\ne 1e400\n", want: map[string]int{"a": 1, "b": 1, "c": 1, "d": 1, "e": 1},
			check: func(t *testing.T, m *Metrics) {
				if !math.IsNaN(m.Get("a")[0].Value) || !math.IsInf(m.Get("c")[0].Value, -1) {
					t.Error("NaN/-Inf falsch")
				}
				if _, ok := m.Value("a"); ok {
					t.Error("Value liefert NaN")
				}
				if _, ok := m.Value("e"); ok {
					t.Error("Value liefert Ueberlauf")
				}
			}},
		{name: "histogramm und summary", in: "# TYPE h histogram\nh_bucket{le=\"0.1\"} 1\nh_bucket{le=\"+Inf\"} 2\nh_sum 3\nh_count 2\n" +
			"# TYPE s summary\ns{quantile=\"0.5\"} 1\ns_sum 4\ns_count 5\n# TYPE c counter\nc_total 1\nc_created 1.7e9\nx_bucket{le=\"1\"} 1\n",
			want: map[string]int{"h_sum": 1, "h_count": 1, "s_sum": 1, "s_count": 1, "c_total": 1}, skipped: 5},
		{name: "openmetrics exemplar", in: "a_total 5 # {trace_id=\"abc\"} 1 1700000000\nb 1 123 # {x=\"y\"} 2\n", want: map[string]int{"a_total": 1, "b": 1}},
		{name: "utf8 name", in: "{\"my.metric\",env=\"prod\"} 7\n{\"other\"} 1\n# TYPE \"my.metric\" gauge\n", want: map[string]int{"my.metric": 1, "other": 1},
			check: func(t *testing.T, m *Metrics) {
				if m.Get("my.metric")[0].Label("env") != "prod" || m.Type("my.metric") != "gauge" {
					t.Errorf("utf8: %#v", m.Get("my.metric"))
				}
			}},
		{name: "leerzeichen in labels", in: "a{ x = \"1\" , y=\"2\", } 1\n", want: map[string]int{"a": 1}},
		{name: "crlf", in: "a 1\r\nb 2\r\n", want: map[string]int{"a": 1, "b": 1}},
		{name: "muell", in: "1abc 2\na{x=1} 2\na{x=\"1\" 2\na{x=\"1\"}2\na\n=\"x\" 1\na 1 2 3\na{\"x\",\"y\"} 1\na{=\"v\"} 1\nb 3\n",
			want: map[string]int{"b": 1}, skipped: 9},
		{name: "ohne zeilenende", in: "a 1", want: map[string]int{"a": 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Parse([]byte(tc.in), Limits{})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int{}
			for n, ss := range m.byName {
				got[n] = len(ss)
			}
			if len(got) != len(tc.want) {
				t.Errorf("Namen = %v, erwartet %v", got, tc.want)
			}
			for n, c := range tc.want {
				if got[n] != c {
					t.Errorf("%s: %d Serien, erwartet %d", n, got[n], c)
				}
			}
			if m.Skipped != tc.skipped {
				t.Errorf("Skipped = %d, erwartet %d", m.Skipped, tc.skipped)
			}
			if tc.check != nil {
				tc.check(t, m)
			}
		})
	}
}

func TestParseLimits(t *testing.T) {
	// Zeile zu lang: uebersprungen
	long := "a{x=\"" + strings.Repeat("y", 200) + "\"} 1\nb 1\n"
	m, err := Parse([]byte(long), Limits{MaxLineBytes: 100})
	if err != nil || m.Series != 1 || m.Skipped != 1 {
		t.Errorf("lange Zeile: %v %+v", err, m)
	}
	// zu viele Labels: Zeile uebersprungen
	m, err = Parse([]byte("a{a=\"1\",b=\"2\",c=\"3\"} 1\nb{a=\"1\"} 1\n"), Limits{MaxLabels: 2})
	if err != nil || m.Series != 1 || m.Skipped != 1 {
		t.Errorf("Labels: %v %+v", err, m)
	}
	// zu viele Serien: Fehler
	if _, err := Parse([]byte("a 1\nb 2\nc 3\n"), Limits{MaxSeries: 2}); !errors.Is(err, ErrTooManySeries) {
		t.Errorf("Serien: %v", err)
	}
	// zu gross: Fehler
	if _, err := Parse(bytes.Repeat([]byte("a 1\n"), 100), Limits{MaxBytes: 50}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Groesse: %v", err)
	}
	// TYPE-Eintraege begrenzt
	var b strings.Builder
	for i := 0; i < 10; i++ {
		b.WriteString("# TYPE m" + strings.Repeat("x", i) + " gauge\n")
	}
	m, err = Parse([]byte(b.String()), Limits{MaxSeries: 3})
	if err != nil || len(m.types) != 3 {
		t.Errorf("types: %v %d", err, len(m.types))
	}
}

// Alle Fixtures: jede Zeile ist entweder gelesen oder ein Bucket/Quantil (keine ungueltigen Zeilen).
func TestParseFixtures(t *testing.T) {
	for _, f := range []string{"node_exporter-1.12.1.txt", "node_exporter-e2e-excerpt.txt", "windows_exporter-0.32.txt", "windows_exporter-0.25.txt"} {
		b, err := os.ReadFile("testdata/" + f)
		if err != nil {
			t.Fatal(err)
		}
		m, err := Parse(b, Limits{})
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		lines := 0
		for _, ln := range strings.Split(string(b), "\n") {
			if ln = strings.TrimSpace(ln); ln != "" && ln[0] != '#' {
				lines++
			}
		}
		if m.Series+m.Skipped != lines {
			t.Errorf("%s: %d gelesen + %d uebersprungen != %d Zeilen", f, m.Series, m.Skipped, lines)
		}
		for _, ss := range m.byName {
			for _, s := range ss {
				for _, l := range s.Labels {
					if l.Name == "le" || l.Name == "quantile" {
						t.Errorf("%s: Bucket/Quantil nicht verworfen: %s", f, s.Name)
					}
				}
			}
		}
		if m.Series < 20 {
			t.Errorf("%s: nur %d Serien", f, m.Series)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"a 1\n", "a{b=\"c\"} 1 2\n", "# TYPE x histogram\nx_bucket{le=\"1\"} 1\n", "{\"a.b\",c=\"\\\\\"} NaN\n",
		"a{b=\"\\\"} 1", "a{", "{", "{\"", "a{b=\"c\",} -Inf # {x=\"y\"} 1"} {
		f.Add([]byte(s))
	}
	if b, err := os.ReadFile("testdata/windows_exporter-0.25.txt"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := Parse(b, Limits{MaxSeries: 1000, MaxLabels: 8, MaxLineBytes: 4096})
		if err != nil {
			return
		}
		if m.Series > 1000 {
			t.Fatalf("Serien %d", m.Series)
		}
		for _, ss := range m.byName {
			for _, s := range ss {
				if len(s.Labels) > 8 {
					t.Fatalf("Labels %d", len(s.Labels))
				}
			}
		}
		// Abbildung darf bei Muell nicht abstuerzen
		_ = nodeReport(m, testNow)
		_ = windowsReport(m, testNow, winIO{})
		_, _ = customServices(m, []CustomMetric{{Name: "a", Rate: true}, {Name: "b", Labels: map[string]string{"c": ""}}}, testNow, nil)
	})
}
