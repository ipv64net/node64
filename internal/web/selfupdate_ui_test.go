package web

import (
	"context"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/selfupdate"
)

// Angebotene neue Version: kleiner Link "Changelog" auf das GitHub-Release dieser Version.
func TestSettingsUpdateChangelogLink(t *testing.T) {
	a := newTestAppDeps(t, func(d *Deps) { d.Updater = selfupdate.New(t.TempDir(), "1.0.0") })
	loginAs(t, a, "admin", "sehr geheimes passwort")
	if err := a.store.SetSetting(context.Background(), selfupdate.SetLatest, `{"version":"1.2.3","checked_at":"2026-11-14T10:00:00Z"}`); err != nil {
		t.Fatal(err)
	}
	_, body := a.get(t, "/settings")
	if !strings.Contains(body, `href="https://github.com/ipv64net/node64/releases/tag/v1.2.3" target="_blank" rel="noopener">Changelog</a>`) {
		t.Fatal("settings: no changelog link for the offered version")
	}
}
