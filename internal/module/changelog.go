package module

import (
	"strings"
	"time"
)

// Release ist ein Eintrag im Aenderungsprotokoll eines Moduls ("## 1.2.0 – 2026-10-14").
type Release struct {
	Version  string
	Date     time.Time
	Intro    []string
	Sections []ChangeSection
}

// ChangeSection ist ein Abschnitt einer Version ("### Neu", "### Behoben", ...).
type ChangeSection struct {
	Title string
	Items []string
}

// Releases zerlegt das Aenderungsprotokoll (Format siehe docs/MODUL-VERSIONEN.md), neueste Version zuerst.
func (i Info) Releases() []Release { return ParseChangelog(i.Changelog) }

// LastChange ist das Datum der neuesten Version im Aenderungsprotokoll (Null = unbekannt).
func (i Info) LastChange() time.Time {
	if r := ParseChangelog(i.Changelog); len(r) > 0 {
		return r[0].Date
	}
	return time.Time{}
}

// ParseChangelog liest "## <Version> – <JJJJ-MM-TT>", "### <Abschnitt>" und "- <Punkt>"; Fliesstext direkt
// unter einer Version wird zur Einleitung. Inline-Markdown (`code`, *kursiv*) wird zu reinem Text.
func ParseChangelog(md string) []Release {
	var out []Release
	var cur *Release
	for _, line := range strings.Split(strings.ReplaceAll(md, "\r\n", "\n"), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "## "):
			out = append(out, parseHead(strings.TrimSpace(t[3:])))
			cur = &out[len(out)-1]
		case cur == nil || t == "":
		case strings.HasPrefix(t, "### "):
			cur.Sections = append(cur.Sections, ChangeSection{Title: plain(t[4:])})
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* "):
			if len(cur.Sections) == 0 {
				cur.Sections = append(cur.Sections, ChangeSection{})
			}
			s := &cur.Sections[len(cur.Sections)-1]
			s.Items = append(s.Items, plain(t[2:]))
		case strings.HasPrefix(line, "  ") && len(cur.Sections) > 0 && len(cur.Sections[len(cur.Sections)-1].Items) > 0:
			// Fortsetzung eines Punktes
			s := &cur.Sections[len(cur.Sections)-1]
			s.Items[len(s.Items)-1] += " " + plain(t)
		case len(cur.Sections) == 0:
			cur.Intro = append(cur.Intro, plain(t))
		}
	}
	return out
}

func parseHead(h string) Release {
	for _, sep := range []string{" – ", " — ", " - "} {
		if v, d, ok := strings.Cut(h, sep); ok {
			r := Release{Version: strings.TrimSpace(v)}
			r.Date, _ = time.Parse("2006-01-02", strings.TrimSpace(d))
			return r
		}
	}
	return Release{Version: h}
}

func plain(s string) string {
	return strings.NewReplacer("`", "", "**", "", "*", "").Replace(strings.TrimSpace(s))
}
