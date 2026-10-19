package web

import (
	"context"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/store"
)

func TestAuditFilterAndTranslation(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	for _, act := range []string{"login", "cdn64.host.create", "dns64.cache.flush", "edge.default", "check.run", "unbekannt.x"} {
		if err := a.store.Audit(ctx, store.AuditEntry{Actor: "admin", Action: act, Target: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	got, err := a.store.AuditListFiltered(ctx, 100, 0, auditAreas["cdn64"])
	if err != nil || len(got) != 2 || got[0].Action != "edge.default" || got[1].Action != "cdn64.host.create" {
		t.Fatalf("cdn64 filter: %+v %v", got, err)
	}
	if all, _ := a.store.AuditList(ctx, 100, 0); len(all) != 6 {
		t.Fatalf("all: %d", len(all))
	}
	v := &View{s: a.s, Lang: "en"}
	if s := v.AuditAction("cdn64.host.create"); s != "Host created" {
		t.Fatalf("en: %q", s)
	}
	v.Lang = "de"
	if s := v.AuditAction("dns64.cache.flush"); s != "Cache geleert" {
		t.Fatalf("de: %q", s)
	}
	if s := v.AuditAction("unbekannt.x"); s != "unbekannt.x" {
		t.Fatalf("unknown: %q", s)
	}
	// Seite: Filter und uebersetzte Aktion
	loginAs(t, a, "admin", "sehr geheimes passwort")
	resp, body := a.get(t, "/audit?area=cdn64")
	if resp.StatusCode != 200 || !strings.Contains(body, `title="cdn64.host.create">Host angelegt<`) || strings.Contains(body, `title="check.run"`) {
		t.Fatalf("page: %d", resp.StatusCode)
	}
}
