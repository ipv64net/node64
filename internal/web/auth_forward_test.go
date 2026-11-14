package web

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/ipv64net/node64/internal/authcfg"
)

// Forward-Auth gilt nur eingeschaltet, nur von eingetragenen Proxy-Adressen und nur fuer bekannte lokale Benutzer.
func TestForwardAuth(t *testing.T) {
	a := newTestApp(t)
	loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings/users")
	csrf := csrfOf(t, body)
	asProxy := func(user string) int {
		req, _ := http.NewRequest("GET", a.srv.URL+"/settings", nil)
		req.Header.Set("Remote-User", user)
		resp, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := asProxy("admin"); c != http.StatusSeeOther {
		t.Fatalf("forward auth off: %d", c)
	}
	save := func(enabled, trusted string) int {
		resp, _ := a.post(t, "/settings/login/forward", url.Values{"_csrf": {csrf}, "enabled": {enabled}, "trusted": {trusted}, "header": {"Remote-User"}})
		return resp.StatusCode
	}
	if c := save("1", "0.0.0.0/0"); c != http.StatusUnprocessableEntity {
		t.Fatalf("all addresses must be refused: %d", c)
	}
	if c := save("1", ""); c != http.StatusUnprocessableEntity {
		t.Fatalf("enabled without proxy must be refused: %d", c)
	}
	if c := save("1", "10.9.8.0/24"); c != http.StatusSeeOther {
		t.Fatalf("save: %d", c)
	}
	if c := asProxy("admin"); c != http.StatusSeeOther {
		t.Fatalf("request not from the proxy must be ignored: %d", c)
	}
	if c := save("1", "10.9.8.0/24, 127.0.0.1"); c != http.StatusSeeOther {
		t.Fatalf("save: %d", c)
	}
	if c := asProxy("admin"); c != http.StatusOK {
		t.Fatalf("proxy user must be signed in: %d", c)
	}
	if c := asProxy("ADMIN"); c != http.StatusOK {
		t.Fatalf("user names are case-insensitive like the login: %d", c)
	}
	if c := asProxy("nobody"); c != http.StatusSeeOther {
		t.Fatalf("unknown user must not get in: %d", c)
	}
	// Anmeldung und 2FA erledigt der Proxy: Passwort-Pflicht und 2FA-Pflicht gelten fuer Forward-Auth nicht
	ctx := context.Background()
	admin, _ := a.store.UserByName(ctx, "admin")
	_ = a.store.SetUserMustChange(ctx, admin.ID, true)
	_ = authcfg.SetTwoFARequired(ctx, a.store, true)
	if c := asProxy("admin"); c != http.StatusOK {
		t.Fatalf("forward auth is exempt from must-change and 2FA requirement: %d", c)
	}
	_ = a.store.SetUserMustChange(ctx, admin.ID, false)
	_ = authcfg.SetTwoFARequired(ctx, a.store, false)
	if c := save("", "127.0.0.1"); c != http.StatusSeeOther || asProxy("admin") != http.StatusSeeOther {
		t.Fatal("switched off: header must be ignored again")
	}
}
