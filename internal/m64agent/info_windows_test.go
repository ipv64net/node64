//go:build windows

package m64agent

import (
	"strings"
	"testing"
)

func TestWindowsName(t *testing.T) {
	for _, tc := range []struct {
		name, display string
		build         uint32
		typ           uint8
		want          string
	}{
		{"Windows 10 Pro", "24H2", 26100, 1, "Windows 11 Pro 24H2"},
		{"Windows 10 Pro", "22H2", 19045, 1, "Windows 10 Pro 22H2"},
		{"Windows Server 2022 Standard", "21H2", 20348, 3, "Windows Server 2022 Standard 21H2"},
		{"Windows 10 Enterprise", "", 26100, 3, "Windows 10 Enterprise"}, // kein Arbeitsplatz: unveraendert
		{"", "", 0, 1, "Windows"},
	} {
		if got := windowsName(tc.name, tc.display, tc.build, tc.typ); got != tc.want {
			t.Errorf("%q: %q", tc.name, got)
		}
	}
}

func TestHostInfoWindows(t *testing.T) {
	p, k, boot := hostInfo()
	t.Logf("%q %q %d", p, k, boot)
	if !strings.HasPrefix(p, "Windows") || !strings.HasPrefix(k, "10.") || boot <= 0 {
		t.Fatalf("%q %q %d", p, k, boot)
	}
}
