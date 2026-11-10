// Package modeltest hilft Tests, die uebersetzbaren Texte der Sammler (model.T) zu pruefen: Tests vergleichen den Text,
// den ein Betrachter sieht – mit den echten Sprachdateien, so faellt auch ein fehlender oder geaenderter Text auf.
package modeltest

import (
	"sync"

	"github.com/ipv64net/node64/internal/i18n"
	"github.com/ipv64net/node64/internal/monitor64/model"
)

var (
	once   sync.Once
	bundle *i18n.Bundle
	err    error
)

// Lang uebersetzt alle Token in s in die Sprache lang ("de", "en"). Ohne Sprachdateien bricht der Test ab (Panic).
func Lang(lang, s string) string {
	once.Do(func() { bundle, err = i18n.Load() })
	if err != nil {
		panic(err)
	}
	return model.Translate(s, func(key string, args ...any) string { return bundle.T(lang, key, args...) })
}

// DE ist der deutsche Text.
func DE(s string) string { return Lang("de", s) }

// EN ist der englische Text.
func EN(s string) string { return Lang("en", s) }

// Service liefert eine Kopie des Dienstes mit Name, Text und Fact-Texten in der Sprache lang.
func Service(lang string, s model.Service) model.Service {
	s.Name, s.Text = Lang(lang, s.Name), Lang(lang, s.Text)
	facts := make([]model.Fact, len(s.Facts))
	for i, f := range s.Facts {
		facts[i] = model.Fact{Code: f.Code, Text: Lang(lang, f.Text)}
	}
	if len(facts) > 0 {
		s.Facts = facts
	}
	return s
}

// Services uebersetzt eine Liste von Diensten (Kopie).
func Services(lang string, l []model.Service) []model.Service {
	out := make([]model.Service, len(l))
	for i, s := range l {
		out[i] = Service(lang, s)
	}
	return out
}
