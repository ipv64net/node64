package web

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// resetModule zaehlt BeforeReset (module.Resetter).
type resetModule struct {
	pingModule
	calls *int
}

func (m resetModule) BeforeReset(context.Context) error {
	*m.calls++
	return errors.New("ipv64 not reachable")
}

// Vor dem Reset raeumen laufende Module online auf; ein Fehler dabei haelt den Reset nicht auf.
func TestResetCallsModuleCleanup(t *testing.T) {
	calls := 0
	a := newTestAppWith(t, resetModule{calls: &calls})
	ctx := context.Background()
	_ = a.store.SetModuleEnabled(ctx, "ping", true)
	a.registry.StartEnabled(ctx)
	problems, err := a.s.requestReset(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(problems) != 1 {
		t.Fatalf("calls=%d problems=%v", calls, problems)
	}
	if _, err := os.Stat(filepath.Join(a.s.Cfg.DataDir, ResetFileName)); err != nil {
		t.Fatal("reset marker missing")
	}
}
