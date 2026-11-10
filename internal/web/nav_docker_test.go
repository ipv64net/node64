package web

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/module"
)

// Unter Healthchecks stehen Statusseiten und Healthchecks-Sync, nur mit Healthchecks; Proxmox VE und Docker nicht mehr
// (nach Monitor64 umgezogen).
func TestNavHealthchecksSubmenu(t *testing.T) {
	a := newTestAppWith(t, module.Placeholder{I: module.Info{Name: "healthchecks", TitleKey: "nav.healthchecks", Path: "/healthchecks"}})
	subs := func(path string) (keys []string, active string) {
		for _, n := range a.s.nav(httptest.NewRequest("GET", path, nil)) {
			if n.Sub && (strings.HasPrefix(n.Path, "/healthchecks/") || n.Path == "/link") {
				keys = append(keys, n.Key)
			}
			if n.Active {
				active = n.Key
			}
		}
		return
	}
	if k, _ := subs("/"); len(k) != 0 {
		t.Fatalf("healthchecks disabled, submenu %v", k)
	}
	if err := a.store.SetModuleEnabled(context.Background(), "healthchecks", true); err != nil {
		t.Fatal(err)
	}
	k, active := subs("/healthchecks/status-pages")
	if strings.Join(k, ",") != "nav.status_pages,nav.link" {
		t.Fatalf("submenu: %v", k)
	}
	if active != "nav.status_pages" {
		t.Fatalf("active: %q", active)
	}
}
