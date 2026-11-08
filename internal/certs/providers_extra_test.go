package certs

import "testing"

// Neue Anbieter (#39): Pflichtfelder werden geprueft, mit Werten entsteht ein Anbieter ohne Netzzugriff.
func TestProvidersExtra(t *testing.T) {
	cases := map[string]map[string]string{
		"luadns":     {"email": "a@example.com", "token": "t"},
		"hostingde":  {"key": "k"},
		"variomedia": {"token": "t"},
		"netlify":    {"token": "t"},
		"njalla":     {"token": "t"},
		"spaceship":  {"key": "k", "secret": "s"},
		"domeneshop": {"token": "t", "secret": "s"},
		"simply":     {"account": "S123456", "key": "k"},
	}
	for id, vals := range cases {
		if _, err := checkValues(id, map[string]string{}); err == nil {
			t.Errorf("%s: empty values accepted", id)
		}
		v, err := checkValues(id, vals)
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if p, err := buildProvider(id, v); err != nil || p == nil {
			t.Errorf("%s: build: %v", id, err)
		}
	}
	if len(Providers()) < 35 {
		t.Fatalf("providers: %d", len(Providers()))
	}
}
