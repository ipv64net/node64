package module

import "testing"

func TestParseChangelog(t *testing.T) {
	md := "# Änderungen – Test\n\n## 1.1.0 – 2026-10-14\n\nEinleitung mit `code`.\n\n### Neu\n- Punkt *eins*\n  weiter\n- Punkt zwei\n\n### Behoben\n- Fehler\n\n## 1.0.0 – 2026-09-01\n- ohne Abschnitt\n"
	r := ParseChangelog(md)
	if len(r) != 2 {
		t.Fatalf("releases = %d", len(r))
	}
	if r[0].Version != "1.1.0" || r[0].Date.Format("2006-01-02") != "2026-10-14" {
		t.Fatalf("head = %+v", r[0])
	}
	if len(r[0].Intro) != 1 || r[0].Intro[0] != "Einleitung mit code." {
		t.Fatalf("intro = %q", r[0].Intro)
	}
	if len(r[0].Sections) != 2 || r[0].Sections[0].Title != "Neu" || r[0].Sections[0].Items[0] != "Punkt eins weiter" || len(r[0].Sections[1].Items) != 1 {
		t.Fatalf("sections = %+v", r[0].Sections)
	}
	if len(r[1].Sections) != 1 || r[1].Sections[0].Items[0] != "ohne Abschnitt" {
		t.Fatalf("second = %+v", r[1])
	}
	if d := (Info{Changelog: md}).LastChange(); d.Format("2006-01-02") != "2026-10-14" {
		t.Fatalf("last change = %v", d)
	}
}
