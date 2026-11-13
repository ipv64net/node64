package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/totp"
)

// postParallel schickt die Formulare gleichzeitig, je Formular mit dem Client von apps[i], und liefert die Statuscodes.
func postParallel(t *testing.T, apps []*testApp, path string, forms []url.Values) []int {
	t.Helper()
	codes := make([]int, len(forms))
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, f := range forms {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := apps[i].client.PostForm(apps[i].srv.URL+path, f)
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			codes[i] = resp.StatusCode
		}()
	}
	close(start)
	wg.Wait()
	return codes
}

// withClient liefert die App mit einem eigenen Client (eigene Cookies, also eigene Sitzung).
func withClient(a *testApp) *testApp {
	b := *a
	jar, _ := cookiejar.New(nil)
	b.client = &http.Client{Jar: jar, CheckRedirect: a.client.CheckRedirect}
	return &b
}

func countStatus(codes []int, status int) int {
	n := 0
	for _, c := range codes {
		if c == status {
			n++
		}
	}
	return n
}

// totpPending legt einen Benutzer mit 2FA an, meldet mit Passwort an und liefert das CSRF-Token der zweiten Stufe.
func totpPending(t *testing.T, a *testApp, secret, recovery string) (userID int64, csrf string) {
	t.Helper()
	ctx := context.Background()
	if u, _ := a.store.UserByName(ctx, "admin"); u != nil {
		userID = u.ID
	} else {
		hash, _ := HashPassword("sehr geheimes passwort")
		u, err := a.store.CreateUser(ctx, "admin", hash, "de", "UTC")
		if err != nil {
			t.Fatal(err)
		}
		userID = u.ID
		if err := a.store.SetUserTOTP(ctx, u.ID, secret, recovery); err != nil {
			t.Fatal(err)
		}
	}
	_, body := a.get(t, "/login")
	resp, _ := a.post(t, "/login", url.Values{"_csrf": {csrfOf(t, body)}, "username": {"admin"}, "password": {"sehr geheimes passwort"}})
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login/totp") {
		t.Fatalf("password step: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	_, body = a.get(t, "/login/totp")
	return userID, csrfOf(t, body)
}

// Gleichzeitige Ersteinrichtung legt genau ein Konto an.
func TestSetupParallel(t *testing.T) {
	a := newTestApp(t)
	var apps []*testApp
	var forms []url.Values
	for i := 0; i < 4; i++ {
		c := withClient(a)
		_, body := c.get(t, "/setup")
		apps = append(apps, c)
		forms = append(forms, url.Values{"_csrf": {csrfOf(t, body)}, "lang": {"de"}, "username": {fmt.Sprintf("admin%d", i)},
			"password": {"sehr geheimes passwort"}, "password2": {"sehr geheimes passwort"}, "timezone": {"Europe/Berlin"}, "node_name": {"pi"}})
	}
	codes := postParallel(t, apps, "/setup", forms)
	if countStatus(codes, http.StatusSeeOther) != 1 || countStatus(codes, http.StatusForbidden) != len(forms)-1 {
		t.Fatalf("setup statuses: %v", codes)
	}
	if n, _ := a.store.UserCount(context.Background()); n != 1 {
		t.Fatalf("users after parallel setup: %d", n)
	}
}

// Ein TOTP-Code gilt nur einmal (auch gleichzeitig), der naechste Zeitschritt geht.
func TestTOTPCodeOnce(t *testing.T) {
	a := newTestApp(t)
	secret := totp.NewSecret()
	code, _ := totp.Code(secret, time.Now())
	apps, forms := []*testApp{}, []url.Values{}
	for i := 0; i < 4; i++ { // je Versuch eine eigene Sitzung, die auf den zweiten Faktor wartet
		c := withClient(a)
		_, csrf := totpPending(t, c, secret, "")
		apps, forms = append(apps, c), append(forms, url.Values{"_csrf": {csrf}, "code": {code}})
	}
	codes := postParallel(t, apps, "/login/totp", forms)
	if countStatus(codes, http.StatusSeeOther) != 1 || countStatus(codes, http.StatusUnauthorized) != len(forms)-1 {
		t.Fatalf("parallel same code: %v", codes)
	}
	// derselbe Code bei einer spaeteren Anmeldung: abgelehnt
	_, csrf := totpPending(t, a, secret, "")
	if resp, _ := a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {code}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("reused code: %d", resp.StatusCode)
	}
	next, _ := totp.Code(secret, time.Now().Add(totp.Period*time.Second))
	if resp, _ := a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {next}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("next step: %d", resp.StatusCode)
	}
}

// Ein Wiederherstellungscode gilt auch bei gleichzeitigen Anfragen nur einmal.
func TestRecoveryCodeParallel(t *testing.T) {
	a := newTestApp(t)
	codes, hashes := totp.NewRecoveryCodes(3)
	secret := totp.NewSecret()
	var uid int64
	apps, forms := []*testApp{}, []url.Values{}
	for i := 0; i < 4; i++ {
		c := withClient(a)
		id, csrf := totpPending(t, c, secret, strings.Join(hashes, ","))
		uid, apps, forms = id, append(apps, c), append(forms, url.Values{"_csrf": {csrf}, "code": {codes[1]}})
	}
	st := postParallel(t, apps, "/login/totp", forms)
	if countStatus(st, http.StatusSeeOther) != 1 || countStatus(st, http.StatusUnauthorized) != len(forms)-1 {
		t.Fatalf("parallel recovery code: %v", st)
	}
	rec, _ := a.store.UserTOTPRecovery(context.Background(), uid)
	if strings.Count(rec, ",") != 1 || strings.Contains(rec, totp.HashRecovery(codes[1])) {
		t.Fatalf("recovery list: %q", rec)
	}
}

// Das 2FA-Limit wird vor der Pruefung verbucht: gleichzeitige Fehlversuche kommen nicht ueber das Limit.
func TestTOTPLimitParallel(t *testing.T) {
	a := newTestApp(t)
	_, csrf := totpPending(t, a, totp.NewSecret(), "")
	apps, forms := []*testApp{}, []url.Values{}
	for i := 0; i < 20; i++ {
		apps, forms = append(apps, a), append(forms, url.Values{"_csrf": {csrf}, "code": {"000000"}})
	}
	codes := postParallel(t, apps, "/login/totp", forms)
	if n := countStatus(codes, http.StatusUnauthorized); n > int(loginBurst) {
		t.Fatalf("%d attempts checked, limit %v: %v", n, loginBurst, codes)
	}
	if countStatus(codes, http.StatusTooManyRequests) < len(forms)-int(loginBurst) {
		t.Fatalf("expected rate limiting: %v", codes)
	}
}

// Der Code zum Einschalten gilt danach nicht noch einmal fuer die Anmeldung.
func TestTOTPEnableConsumesStep(t *testing.T) {
	a := newTestApp(t)
	u := loginAs(t, a, "admin", "sehr geheimes passwort")
	_, body := a.get(t, "/settings/2fa")
	csrf := csrfOf(t, body)
	secret := a.store.SettingOr(context.Background(), pendingKey+fmt.Sprint(u.ID), "")
	if secret == "" {
		t.Fatal("no pending secret")
	}
	code, _ := totp.Code(secret, time.Now())
	if resp, _ := a.post(t, "/settings/2fa/enable", url.Values{"_csrf": {csrf}, "code": {code}}); resp.StatusCode != http.StatusOK {
		t.Fatalf("enable: %d", resp.StatusCode)
	}
	_, body = a.get(t, "/settings")
	a.post(t, "/logout", url.Values{"_csrf": {csrfOf(t, body)}})
	_, csrf = totpPending(t, a, "", "")
	if resp, _ := a.post(t, "/login/totp", url.Values{"_csrf": {csrf}, "code": {code}}); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("enable code reused for login: %d", resp.StatusCode)
	}
}
