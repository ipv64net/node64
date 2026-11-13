package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Gleichzeitige Ersteinrichtung: nur eine Anfrage legt ein Konto an, alle anderen bekommen ErrSetupDone.
func TestCreateFirstUserParallel(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	created, done := 0, 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.CreateFirstUser(ctx, fmt.Sprintf("admin%d", i), "hash", "de", "UTC")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				created++
			case errors.Is(err, ErrSetupDone):
				done++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if created != 1 || done != n-1 {
		t.Fatalf("created %d, setup done %d", created, done)
	}
	if c, _ := st.UserCount(ctx); c != 1 {
		t.Fatalf("users: %d", c)
	}
	if _, err := st.CreateFirstUser(ctx, "later", "hash", "", ""); !errors.Is(err, ErrSetupDone) {
		t.Fatalf("second setup: %v", err)
	}
}

// Wiederherstellungscode: von gleichzeitigen Verbrauchern derselben gelesenen Liste gewinnt genau einer.
func TestUseTOTPRecoveryParallel(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, "admin", "hash", "de", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserTOTP(ctx, u.ID, "SECRET", "a,b,c"); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.UseTOTPRecovery(ctx, u.ID, "a,b,c", "a,c")
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("recovery code used %d times", wins)
	}
	if rec, _ := st.UserTOTPRecovery(ctx, u.ID); rec != "a,c" {
		t.Fatalf("stored list: %q", rec)
	}
	if ok, _ := st.UseTOTPRecovery(ctx, u.ID, "a,c", "c"); !ok {
		t.Fatal("next code from the current list must work")
	}
}

// Zeitschritt: jeder Schritt nur einmal, nur steigend; gleichzeitig gewinnt genau einer.
func TestUseTOTPStep(t *testing.T) {
	st := openTest(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, "admin", "hash", "de", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := st.EnableUserTOTP(ctx, u.ID, "SECRET", "a,b", 100); err != nil || !ok {
		t.Fatalf("enable: %v %v", ok, err)
	}
	if ok, _ := st.EnableUserTOTP(ctx, u.ID, "OTHER", "x", 101); ok {
		t.Fatal("enable twice must fail")
	}
	if got, _ := st.UserByID(ctx, u.ID); got.TOTPSecret != "SECRET" {
		t.Fatalf("secret overwritten: %q", got.TOTPSecret)
	}
	if ok, _ := st.UseTOTPStep(ctx, u.ID, 100); ok {
		t.Fatal("step used for enabling must not work again")
	}
	if ok, _ := st.UseTOTPStep(ctx, u.ID, 99); ok {
		t.Fatal("older step must fail")
	}
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := st.UseTOTPStep(ctx, u.ID, 101)
			if err != nil {
				t.Error(err)
			}
			if ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("step used %d times", wins)
	}
	if ok, _ := st.UseTOTPStep(ctx, u.ID, 102); !ok {
		t.Fatal("next step must work")
	}
}
