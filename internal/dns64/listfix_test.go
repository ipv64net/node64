package dns64

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/ipv64net/node64/internal/dns64/filter"
)

// Sperrliste als Text: eine gleichlautende Freigabe einer neuen Domain faellt weg (wie beim Sperren einzelner
// Domains), Freigaben von Subdomains und von Domains, die schon gesperrt waren, bleiben.
func TestReplaceDenyDropsAllow(t *testing.T) {
	m, _ := testModule(t)
	mux := listsMux(m)
	a, err := m.allowlist()
	if err != nil {
		t.Fatal(err)
	}
	dl, err := m.denylist()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dl.Add("alt.example"); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"ads.example", "ok.tracker.example", "alt.example"} {
		if _, err := a.Add(d); err != nil {
			t.Fatal(err)
		}
	}
	if w := apiDo(mux, "PUT", "/api/dns64/denylist", `{"domains":["ads.example","tracker.example","alt.example"]}`); w.Code != 200 {
		t.Fatalf("replace: %d %s", w.Code, w.Body)
	}
	a, _ = m.allowlist() // aus der Datei neu geladen
	if a.Contains("ads.example") {
		t.Fatal("allow entry of newly blocked domain kept")
	}
	if !a.Contains("ok.tracker.example") || !a.Contains("alt.example") {
		t.Fatalf("allow entries lost: %v", a.List())
	}
}

// Freigaben importieren: hosts-Zeilen liefern die Domain, IP-Adressen allein sind ungueltig, Standardnamen einer
// hosts-Datei werden uebergangen.
func TestImportAllowHosts(t *testing.T) {
	m, _ := testModule(t)
	n, bad, err := m.importAllow([]string{"0.0.0.0 ads.example", "127.0.0.1 localhost", "0.0.0.0", "1.2.3.4", "ok.example # Kommentar", ""})
	if err != nil || n != 2 || bad != 2 {
		t.Fatalf("import: n=%d bad=%d err=%v", n, bad, err)
	}
	a, _ := m.allowlist()
	if !a.Contains("ads.example") || !a.Contains("ok.example") || len(a.List()) != 2 {
		t.Fatalf("allowlist: %v", a.List())
	}
}

// Export/Import nimmt die Freigabe-Listen mit; kaputte Listen im Import werden nicht uebernommen.
func TestExportImportAllowLists(t *testing.T) {
	ctx := context.Background()
	a, _ := testModule(t)
	c := a.loadConfig(ctx)
	if err := c.addAllowList("FP", "https://allow.example/fp.txt"); err != nil {
		t.Fatal(err)
	}
	if err := a.saveConfig(ctx, c); err != nil {
		t.Fatal(err)
	}
	out, err := a.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(out)
	b, _ := testModule(t)
	if _, err := b.Import(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if l := b.loadConfig(ctx).AllowLst; len(l) != 1 || l[0].URL != "https://allow.example/fp.txt" || l[0].Name != "FP" || !l[0].Enabled {
		t.Fatalf("allow lists after import: %+v", l)
	}

	if importListsOK(setAllowLst, `[{"name":"x","url":"ftp://x.example/a"}]`) || importListsOK(setAllowLst, "kaputt") {
		t.Fatal("invalid allow lists accepted")
	}
	var many []listSetting
	for i := range filter.MaxLists + 1 {
		many = append(many, listSetting{List: filter.List{URL: "https://l.example/" + strconv.Itoa(i)}, Enabled: true})
	}
	js, _ := json.Marshal(many)
	if importListsOK(setAllowLst, string(js)) || importListsOK(setLists, string(js)) {
		t.Fatal("too many lists accepted")
	}
	if !importListsOK(setLists, "[]") || !importListsOK(setPort, "x") {
		t.Fatal("valid import rejected")
	}
}

// Blocklisten: hoechstens filter.MaxLists eingeschaltete; die Mehrfach-Eingabe meldet die ueberzaehligen als nicht
// hinzugefuegt, Speichern mit zu vielen scheitert.
func TestBlocklistMax(t *testing.T) {
	m, _ := testModule(t)
	c := m.loadConfig(context.Background())
	var lines []string
	for i := len(c.activeLists()); i < filter.MaxLists+2; i++ {
		lines = append(lines, "https://block.example/"+strconv.Itoa(i)+".txt")
	}
	res := c.addListsBulk(lines, false)
	if len(c.activeLists()) != filter.MaxLists || len(res.Full) != 2 || len(res.Invalid) != 0 || len(res.Added) != len(lines)-2 {
		t.Fatalf("bulk: active=%d %+v", len(c.activeLists()), res)
	}
	if !slices.Contains(res.Full, lines[len(lines)-1]) {
		t.Fatalf("full: %v", res.Full)
	}
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	var ce *cfgError
	if err := c.addList("", "https://block.example/extra.txt"); !errors.As(err, &ce) || ce.Key != "err_list_max" {
		t.Fatalf("addList: %v", err)
	}
	// ausgeschaltete zaehlen nicht, zu viele eingeschaltete lassen sich nicht speichern
	c.Lists = append(c.Lists, listSetting{List: filter.List{Name: "aus", URL: "https://block.example/off.txt"}, Custom: true})
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	c.Lists[len(c.Lists)-1].Enabled = true
	if err := c.validate(); !errors.As(err, &ce) || ce.Key != "err_list_max" {
		t.Fatalf("validate: %v", err)
	}
}
