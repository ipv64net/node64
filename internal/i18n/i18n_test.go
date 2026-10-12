package i18n

import (
	"testing"
	"time"
)

func TestLoadAndTranslate(t *testing.T) {
	b, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := b.T("de", "nav.dashboard"); got != "Dashboard" {
		t.Fatalf("de nav.dashboard = %q", got)
	}
	if got := b.T("en", "nav.settings"); got != "Settings" {
		t.Fatalf("en nav.settings = %q", got)
	}
	if got := b.T("fr", "nav.settings"); got != "Settings" {
		t.Fatalf("fallback to en failed: %q", got)
	}
	if got := b.T("de", "does.not.exist"); got != "does.not.exist" {
		t.Fatalf("unknown key should be returned: %q", got)
	}
	if got := b.T("de", "nav.version", "version", "1.0"); got != "Version 1.0" {
		t.Fatalf("placeholder: %q", got)
	}
	if got := b.T("de", "time.days", "count", 1); got != "1 Tag" {
		t.Fatalf("plural one: %q", got)
	}
	if got := b.T("de", "time.days", "count", 3); got != "3 Tage" {
		t.Fatalf("plural other: %q", got)
	}
	if got := b.T("en", "time.days", "count", 1234); got != "1,234 days" {
		t.Fatalf("plural with number formatting: %q", got)
	}
}

func TestEveryKeyExistsInAllLanguages(t *testing.T) {
	b, _ := Load()
	for _, lang := range b.Languages() {
		for key := range b.msgs["en"] {
			if _, ok := b.msgs[lang][key]; !ok {
				t.Errorf("%s: missing key %s", lang, key)
			}
		}
		for key := range b.msgs[lang] {
			if _, ok := b.msgs["en"][key]; !ok {
				t.Errorf("en: missing key %s (exists in %s)", key, lang)
			}
		}
	}
}

func TestMatch(t *testing.T) {
	b, _ := Load()
	cases := map[string]string{"de-DE,de;q=0.9,en;q=0.8": "de", "en-US,en;q=0.9": "en", "fr-FR": "de", "": "de", "de-AT": "de"}
	for in, want := range cases {
		if got := b.Match(in); got != want {
			t.Errorf("Match(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFormat(t *testing.T) {
	b, _ := Load()
	loc, _ := time.LoadLocation("Europe/Berlin")
	ts := time.Date(2026, 10, 10, 10, 5, 0, 0, time.UTC)
	if got := b.FormatDateTime("de", ts, loc); got != "10.10.2026 12:05:00" {
		t.Fatalf("de datetime: %q", got)
	}
	if got := b.FormatDateTime("en", ts, time.UTC); got != "2026-10-10 10:05:00" {
		t.Fatalf("en datetime: %q", got)
	}
	if got := b.FormatDuration("de", 26*time.Hour+5*time.Minute); got != "1 Tag 2 h" {
		t.Fatalf("duration: %q", got)
	}
	if got := b.FormatDuration("en", 42*time.Second); got != "42 s" {
		t.Fatalf("duration: %q", got)
	}
}
