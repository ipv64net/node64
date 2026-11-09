//go:build windows

package m64agent

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// hostInfo liest Windows-Ausgabe (Registry "ProductName" und "DisplayVersion"), Version mit Build (RtlGetVersion,
// UBR) und Startzeit (GetTickCount64).
func hostInfo() (platform, kernel string, boot int64) {
	v := windows.RtlGetVersion()
	var name, display string
	var ubr uint64
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		name, _, _ = k.GetStringValue("ProductName")
		display, _, _ = k.GetStringValue("DisplayVersion")
		ubr, _, _ = k.GetIntegerValue("UBR")
		k.Close()
	}
	platform = windowsName(name, display, v.BuildNumber, v.ProductType)
	kernel = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	if ubr > 0 {
		kernel += "." + strconv.FormatUint(ubr, 10)
	}
	boot = time.Now().Add(-windows.DurationSinceBoot()).Unix()
	return platform, kernel, boot
}

// windowsName: Windows 11 meldet in der Registry weiterhin "Windows 10 ..." (erkennbar am Build ab 22000, nur
// Arbeitsplatz-Ausgaben; ProductType 1).
func windowsName(name, display string, build uint32, productType uint8) string {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Windows"
	}
	if build >= 22000 && productType == 1 && strings.HasPrefix(name, "Windows 10") {
		name = "Windows 11" + strings.TrimPrefix(name, "Windows 10")
	}
	if display = strings.TrimSpace(display); display != "" {
		name += " " + display
	}
	return cleanText(name, 100)
}
