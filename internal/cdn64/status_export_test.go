package cdn64

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// pageList: Statusseiten mit frei waehlbaren IDs (andere Node = andere IDs).
type pageList []StatusPageInfo

func (pageList) StatusSite(int64) http.Handler                     { return http.NotFoundHandler() }
func (p pageList) StatusPageList(context.Context) []StatusPageInfo { return p }

// Export/Import: Hosts der Art "status" zeigen auf der Ziel-Node auf die Seite gleichen Slugs; fehlt sie, wird der
// Host ausgeschaltet angelegt statt auf eine fremde Seite mit zufaellig gleicher ID zu zeigen.
func TestExportImportStatusHostBySlug(t *testing.T) {
	ctx := context.Background()
	a := newEnv(t)
	a.m.SetStatusPages(pageList{{ID: 7, Slug: "home"}, {ID: 8, Slug: "alt"}})
	a.enable(t)
	for _, x := range []struct {
		name string
		page int64
	}{{"home.test", 7}, {"alt.test", 8}} {
		h := newHostKind(KindStatus)
		h.Names, h.StatusPageID, h.CertID = []string{x.name}, x.page, CertNone
		if err := a.m.saveHost(ctx, h); err != nil {
			t.Fatal(err)
		}
	}
	exp, err := a.m.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(exp)

	b := newEnv(t)
	b.m.SetStatusPages(pageList{{ID: 8, Slug: "fremd"}, {ID: 21, Slug: "home"}}) // "alt" fehlt, ID 8 ist eine andere Seite
	b.enable(t)
	n, err := b.m.Import(ctx, raw)
	if n != 2 || err == nil || !strings.Contains(err.Error(), `"alt"`) {
		t.Fatalf("import: %d %v", n, err)
	}
	list, err := b.m.hosts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*Host{}
	for _, h := range list {
		got[h.Names[0]] = h
	}
	if h := got["home.test"]; h == nil || h.StatusPageID != 21 || !h.Enabled {
		t.Fatalf("home: %+v", h)
	}
	if h := got["alt.test"]; h == nil || h.Enabled {
		t.Fatalf("alt must be switched off: %+v", h)
	}
}
