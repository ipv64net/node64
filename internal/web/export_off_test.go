package web

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/ipv64net/node64/internal/module"
)

// offExporter ist ein nie eingeschaltetes Modul: sein Export scheitert (keine Tabellen).
type offExporter struct{ module.Placeholder }

func (offExporter) Export(context.Context) (any, error) {
	return nil, errors.New("no such table: off_items")
}
func (offExporter) Import(context.Context, json.RawMessage) (int, error) {
	return 0, errors.New("must not be imported")
}

// Der Export nimmt nur laufende Module mit: ein nie eingeschaltetes bricht ihn nicht ab und landet nicht in der
// Datei (sonst schaltete der Import es auf der Ziel-Node ein).
func TestExportSkipsModulesNotRunning(t *testing.T) {
	a := newTestAppWith(t, offExporter{module.Placeholder{I: module.Info{Name: "offmod", TitleKey: "nav.dyndns", Path: "/offmod"}}})
	cf, err := a.s.buildExport(context.Background(), "plain", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cf.Modules["offmod"]; ok {
		t.Fatal("module that is not running must not be exported")
	}
}
