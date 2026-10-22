package web

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/store"
)

// Schickt der Browser zwei Sitzungs-Cookies gleichen Namens (altes von http, neues von https), zaehlt die gueltige –
// sonst landete jede Anmeldung wieder auf /login.
func TestSessionCookieDuplicateNames(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	u, err := a.store.CreateUser(ctx, "dup", "geheim-passwort", "", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sess := &store.Session{ID: "gueltige-sitzung-0123456789", UserID: u.ID, CSRF: "csrf-0123456789-0123456789-0123", CreatedAt: now, LastSeenAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := a.store.CreateSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	_ = a.store.SetSessionTOTP(ctx, sess.ID, true)
	req, _ := http.NewRequest(http.MethodGet, a.srv.URL+"/", nil)
	req.Header.Add("Cookie", sessionCookie+"_h=alte-ungueltige-sitzung") // http: eigener Name
	req.Header.Add("Cookie", sessionCookie+"=sicheres-cookie-von-https")
	req.Header.Add("Cookie", sessionCookie+"_h="+sess.ID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/" {
		t.Fatalf("status %d at %s, want dashboard", resp.StatusCode, resp.Request.URL.Path)
	}
}
