package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/ipv64net/node64/internal/store"
)

// Schutzregel „letzter aktiver lokaler Administrator“ bei gleichzeitigen Anfragen: von zwei lokalen Administratoren
// sperrt die eine Anfrage den einen und loescht die andere den anderen bzw. stuft eine Gruppe herab - hoechstens eine
// darf durchkommen (Pruefen und Schreiben unter einer Sperre).
func TestLastLocalAdminConcurrent(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	// handelnder Administrator aus dem Verzeichnis: zaehlt nicht als lokaler Administrator
	actor, err := a.store.CreateUserWith(ctx, store.NewUser{Username: "ad.admin", Role: store.RoleAdmin, Source: store.SourceLDAP})
	if err != nil {
		t.Fatal(err)
	}
	req := func() *http.Request {
		r := httptest.NewRequest("POST", "/settings/users", nil)
		return r.WithContext(context.WithValue(r.Context(), ctxUser, actor))
	}
	activeLocal := func() int {
		users, _ := a.store.Users(ctx)
		n := 0
		for _, u := range users {
			if !u.Disabled && u.Source == store.SourceLocal && a.store.EffectiveRole(ctx, u) == store.RoleAdmin {
				n++
			}
		}
		return n
	}
	for i := 0; i < 40; i++ {
		// vorherige lokale Administratoren aus dem Weg (direkt im Store, ohne Schutzregel)
		users, _ := a.store.Users(ctx)
		for _, u := range users {
			if u.Source == store.SourceLocal {
				_, _ = a.store.DeleteUser(ctx, u.ID)
			}
		}
		g := &store.Group{Name: "Admins" + strconv.Itoa(i), Role: store.RoleAdmin}
		_ = a.store.SaveGroup(ctx, g)
		x, _ := a.store.CreateUserWith(ctx, store.NewUser{Username: "x" + strconv.Itoa(i), PasswordHash: "$h", Role: store.RoleAdmin})
		y, _ := a.store.CreateUserWith(ctx, store.NewUser{Username: "y" + strconv.Itoa(i), PasswordHash: "$h", Role: store.RoleRead, GroupUIDs: []string{g.UID}})
		var wg sync.WaitGroup
		start := make(chan struct{})
		ops := []func(){
			func() { _, _ = a.s.deleteOtherUser(req(), x.ID) },
			func() {
				_ = a.s.uaUpdate(req(), y, store.UserAdmin{Role: store.RoleRead, Disabled: true, GroupUIDs: y.GroupUIDs})
			},
			func() { _, _ = a.s.groupDelete(req(), g.UID) },
		}
		if i%2 == 1 { // Gruppe statt Benutzer y
			ops = []func(){ops[0], ops[2]}
		} else {
			ops = ops[:2]
		}
		for _, op := range ops {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				op()
			}()
		}
		close(start)
		wg.Wait()
		if n := activeLocal(); n == 0 {
			t.Fatalf("round %d: no active local administrator left", i)
		}
		_, _ = a.store.DeleteGroup(ctx, g.UID)
	}
}
