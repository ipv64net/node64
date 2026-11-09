//go:build windows

package m64win

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// TestCollectLive liest diesen Windows-Host einmal (nur lesend, ohne Adminrechte moeglich). Mit -v steht der Bericht
// im Log; M64WIN_SLOW=1 wartet zusaetzlich auf SMART und Windows Update (kann Minuten dauern).
func TestCollectLive(t *testing.T) {
	cache := NewCache()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	r := Collect(ctx, Options{Cache: cache})
	t.Logf("Collect: %s", time.Since(start).Round(time.Millisecond))
	if os.Getenv("M64WIN_SLOW") == "1" {
		cache.Wait()
		ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel2()
		r = Collect(ctx2, Options{Cache: cache})
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	t.Logf("Bericht (%d Byte):\n%s", len(b), b)
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	t.Logf("Heap %d KB, Sys %d KB", ms.HeapAlloc>>10, ms.Sys>>10)

	if r.CPU == nil || r.CPU.Cores <= 0 || r.CPU.Idle == 0 {
		t.Errorf("cpu = %+v", r.CPU)
	}
	if r.Mem == nil || r.Mem.Total == 0 || r.Mem.Available > r.Mem.Total {
		t.Errorf("mem = %+v", r.Mem)
	}
	if r.Uptime <= 0 {
		t.Errorf("uptime = %v", r.Uptime)
	}
	sysDrive := os.Getenv("SystemDrive")
	found := false
	for _, f := range r.FS {
		if f.Mount == sysDrive && f.Total > 0 && f.Used+f.Avail <= f.Total+f.Total/100 {
			found = true
		}
	}
	if !found {
		t.Errorf("fs ohne %s: %+v", sysDrive, r.FS)
	}
	if len(r.Net) == 0 {
		t.Errorf("keine Netzwerk-Schnittstellen")
	}
	if r.Reboot == nil {
		t.Errorf("reboot fehlt")
	}
	for _, s := range r.WinSvc {
		if s.StartType != "auto" || s.Name == "" || s.State == "" {
			t.Errorf("winsvc %+v", s)
		}
	}
	for _, e := range r.Errors {
		if e.Section == m64proto.SecCPU || e.Section == m64proto.SecMem || e.Section == m64proto.SecWinSvc {
			t.Errorf("Fehler: %+v", e)
		}
	}
	// zweiter Bericht: Zaehler steigen nicht rueckwaerts
	r2 := Collect(context.Background(), Options{Cache: cache, Sections: []string{m64proto.SecCPU, m64proto.SecNet}})
	if r2.CPU == nil || r2.CPU.Idle < r.CPU.Idle || r2.FS != nil || r2.WinSvc != nil {
		t.Errorf("zweiter Bericht: %+v", r2)
	}
}

// Langsame Abschnitte kommen aus dem Cache: der erste Bericht wartet nur kurz und meldet "wird gelesen".
func TestCollectSlowFake(t *testing.T) {
	cache := NewCache()
	block := make(chan struct{})
	ps := func(ctx context.Context, script string) ([]byte, error) {
		<-block
		switch script {
		case storageScript, raidScript:
			return os.ReadFile("testdata/storage_admin.json")
		case updatesScript:
			return []byte(`{"pending":3,"security":1,"reboot":true}`), nil
		}
		return nil, errors.New("unbekanntes Skript")
	}
	secs := []string{m64proto.SecSmart, m64proto.SecUpdates, m64proto.SecReboot, m64proto.SecRAID}
	r := Collect(context.Background(), Options{Cache: cache, PS: ps, Sections: secs})
	if r.SMART != nil || r.Updates != nil || len(r.Notes) < 2 {
		t.Fatalf("erster Bericht: %+v", r)
	}
	close(block)
	cache.Wait()
	r = Collect(context.Background(), Options{Cache: cache, PS: ps, Sections: secs})
	if len(r.SMART) != 3 || r.Updates == nil || r.Updates.Security != 1 || r.Reboot == nil || !r.Reboot.Required {
		t.Fatalf("zweiter Bericht: %+v", r)
	}
	if len(r.RAID) != 1 || r.RAID[0].State != "degraded" {
		t.Fatalf("raid: %+v", r.RAID)
	}
}
