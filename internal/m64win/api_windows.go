//go:build windows

package m64win

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Funktionen, die x/sys/windows nicht exportiert (ueber die System-DLLs, kein cgo).
var (
	modkernel32              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = modkernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = modkernel32.NewProc("GlobalMemoryStatusEx")
	procGetTickCount64       = modkernel32.NewProc("GetTickCount64")
)

// pageSize: Seitengroesse unter Windows (amd64 und arm64).
const pageSize = 4096

// Steuercodes fuer DeviceIoControl.
const (
	ioctlDiskPerformance      = 0x00070020 // CTL_CODE(IOCTL_DISK_BASE, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)
	ioctlStorageQueryProperty = 0x002d1400 // CTL_CODE(IOCTL_STORAGE_BASE, 0x500, METHOD_BUFFERED, FILE_ANY_ACCESS)
)

// alignedBuf liefert einen auf 8 Byte ausgerichteten Puffer auf dem Heap (die API legt dort Strukturen mit Zeigern
// ab; ein []byte auf dem Stack waere weder ausgerichtet noch sicher vor dem Verschieben).
func alignedBuf(n int) []byte {
	u := make([]uint64, (n+7)/8)
	return unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), n)
}

// filetime macht aus einer FILETIME eine Zahl (100 ns).
func filetime(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

// readCPU liest die Summen-Zaehler aller Kerne (GetSystemTimes).
func readCPU() (*m64proto.CPU, error) {
	var idle, kernel, user windows.Filetime
	r, _, err := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		return nil, fmt.Errorf("GetSystemTimes: %w", err)
	}
	cores := int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS))
	return cpuFromTimes(filetime(idle), filetime(kernel), filetime(user), cores), nil
}

// memoryStatusEx ist MEMORYSTATUSEX.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

// readMem liest den Arbeitsspeicher (GlobalMemoryStatusEx) und die Auslagerungsdateien (belegt/gesamt).
func readMem() (*m64proto.Mem, error) {
	var ms memoryStatusEx
	ms.Length = uint32(unsafe.Sizeof(ms))
	r, _, err := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms)))
	if r == 0 {
		return nil, fmt.Errorf("GlobalMemoryStatusEx: %w", err)
	}
	m := &m64proto.Mem{Total: ms.TotalPhys, Available: min(ms.AvailPhys, ms.TotalPhys)}
	buf := alignedBuf(4096)
	var n uint32
	if err := windows.NtQuerySystemInformation(windows.SystemPageFileInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &n); err == nil {
		if total, used, ok := parsePagefiles(buf[:min(int(n), len(buf))], pageSize); ok {
			m.SwapTotal, m.SwapFree = total, total-used
		}
	}
	return m, nil
}

// uptime liefert die Zeit seit dem Start (GetTickCount64, mit Ruhezustand).
func uptime() time.Duration {
	r, _, _ := procGetTickCount64.Call()
	return time.Duration(r) * time.Millisecond
}

// readFS liest die festen Laufwerke (keine Netz-, Wechsel- und CD-Laufwerke), je Laufwerk mit Zeitlimit (startDrive).
func readFS(ctx context.Context, c *Cache) ([]m64proto.FS, []error) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return nil, []error{fmt.Errorf("GetLogicalDrives: %w", err)}
	}
	type drive struct {
		letter string
		call   *driveCall
	}
	var drives []drive
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		letter := string(rune('A'+i)) + ":"
		drives = append(drives, drive{letter, c.startDrive("fs "+letter, func() (any, error) { return readDrive(letter) })})
	}
	var out []m64proto.FS
	var errs []error
	for _, d := range drives {
		f, err := waitDrive[*m64proto.FS](ctx, d.call, d.letter, driveLimit)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if f != nil {
			out = append(out, *f)
		}
	}
	return out, errs
}

// readDrive liest ein Laufwerk (nil: kein festes Laufwerk).
func readDrive(letter string) (*m64proto.FS, error) {
	root, _ := windows.UTF16PtrFromString(letter + `\`)
	if windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return nil, nil
	}
	var avail, total, free uint64
	if err := windows.GetDiskFreeSpaceEx(root, &avail, &total, &free); err != nil {
		return nil, fmt.Errorf("%s: %w", letter, err)
	}
	f := &m64proto.FS{Mount: letter, Total: total, Used: total - min(free, total), Avail: min(avail, total)}
	var flags uint32
	fsName := make([]uint16, 64)
	if windows.GetVolumeInformation(root, nil, 0, nil, nil, &flags, &fsName[0], uint32(len(fsName))) == nil {
		f.Type = clip(windows.UTF16ToString(fsName))
		f.ReadOnly = flags&windows.FILE_READ_ONLY_VOLUME != 0
	}
	return f, nil
}

// diskRead ist das Ergebnis einer Platte (readDisk).
type diskRead struct {
	d         m64proto.DiskIO
	idle      int64 // Leerlaufzeit (DISK_PERFORMANCE)
	missing   bool  // Platte gibt es nicht
	removable bool
}

// readDisks liest die I/O-Zaehler der Platten (\\.\PhysicalDriveN; Oeffnen ohne Zugriffsrechte reicht, kein
// Admin noetig) samt Seriennummer und Modell, je Platte mit Zeitlimit (startDrive). hung: haengende Platten (als
// Hinweis, auch wenn andere Platten Werte liefern).
func readDisks(ctx context.Context, c *Cache) (out []m64proto.DiskIO, hung []error, firstErr error) {
	calls := make([]*driveCall, maxDrives)
	for i := range calls {
		name := "PhysicalDrive" + strconv.Itoa(i)
		calls[i] = c.startDrive("disk "+name, func() (any, error) { return readDisk(name) })
	}
	for i, call := range calls {
		name := "PhysicalDrive" + strconv.Itoa(i)
		r, err := waitDrive[diskRead](ctx, call, name, driveLimit)
		if err != nil {
			if errors.Is(err, errDriveTimeout) || ctx.Err() != nil { // kein Fehler der Platte selbst
				hung = append(hung, err)
			} else if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if r.missing || r.removable {
			continue // Kartenleser, USB-Sticks (USB-Festplatten melden sich als feste Platte)
		}
		r.d.IOTimeMs = c.busy.update(name, r.idle, time.Since(monoStart))
		out = append(out, r.d)
	}
	if len(out) > 0 {
		firstErr = nil // einzelne Platte ohne Zaehler (z. B. Kartenleser ohne Medium) ist kein Abschnittsfehler
	}
	return out, hung, firstErr
}

// readDisk oeffnet und liest eine Platte.
func readDisk(name string) (diskRead, error) {
	p, _ := windows.UTF16PtrFromString(`\\.\` + name)
	h, err := windows.CreateFile(p, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return diskRead{missing: true}, nil
		}
		return diskRead{}, fmt.Errorf("%s: %w", name, err)
	}
	defer windows.CloseHandle(h)
	d, idle, removable, err := diskIO(h, name)
	return diskRead{d: d, idle: idle, removable: removable}, err
}

func diskIO(h windows.Handle, name string) (m64proto.DiskIO, int64, bool, error) {
	d := m64proto.DiskIO{Name: name}
	// STORAGE_PROPERTY_QUERY{PropertyId: StorageDeviceProperty (0), QueryType: PropertyStandardQuery (0)}
	q := alignedBuf(12)
	desc := alignedBuf(1024)
	var n uint32
	if windows.DeviceIoControl(h, ioctlStorageQueryProperty, &q[0], uint32(len(q)), &desc[0], uint32(len(desc)), &n, nil) == nil {
		if sd, ok := parseStorageDesc(desc[:n]); ok {
			if sd.removable {
				return d, 0, true, nil
			}
			d.Serial, d.Model = sd.serial, sd.model()
		}
	}
	perf := alignedBuf(88)
	if err := windows.DeviceIoControl(h, ioctlDiskPerformance, nil, 0, &perf[0], uint32(len(perf)), &n, nil); err != nil {
		return d, 0, false, fmt.Errorf("%s: IOCTL_DISK_PERFORMANCE: %w", name, err)
	}
	p, ok := parseDiskPerf(perf[:n])
	if !ok {
		return d, 0, false, fmt.Errorf("%s: IOCTL_DISK_PERFORMANCE: %d Byte", name, n)
	}
	d.ReadBytes, d.WriteBytes = p.bytesRead, p.bytesWritten
	d.ReadOps, d.WriteOps = uint64(p.reads), uint64(p.writes)
	return d, p.idle, false, nil
}

// readNet liest die Schnittstellen samt Zaehlern (GetIfTable2); Filter-Treiber, Loopback und Tunnel fehlen,
// virtuelle Schnittstellen nur, wenn sie verbunden sind.
func readNet() ([]m64proto.NetIf, error) {
	var tab *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &tab); err != nil {
		return nil, fmt.Errorf("GetIfTable2Ex: %w", err)
	}
	defer windows.FreeMibTable(unsafe.Pointer(tab))
	rows := unsafe.Slice(&tab.Table[0], tab.NumEntries)
	var out []m64proto.NetIf
	seen := map[string]bool{}
	for i := range rows {
		r := &rows[i]
		kind, skip := netKind(r.InterfaceAndOperStatusFlags, r.Type)
		if skip {
			continue
		}
		up := r.OperStatus == windows.IfOperStatusUp
		if kind == "virtual" && !up {
			continue
		}
		name := clip(windows.UTF16ToString(r.Alias[:]))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		n := m64proto.NetIf{Name: name, Kind: kind, Up: up, MTU: int(min(r.Mtu, 1<<20)),
			RxBytes: r.InOctets, TxBytes: r.OutOctets,
			RxPackets: r.InUcastPkts + r.InNUcastPkts, TxPackets: r.OutUcastPkts + r.OutNUcastPkts,
			RxErrors: r.InErrors, TxErrors: r.OutErrors, RxDropped: r.InDiscards, TxDropped: r.OutDiscards}
		if up {
			n.SpeedMbit = linkSpeedMbit(max(r.TransmitLinkSpeed, r.ReceiveLinkSpeed))
		}
		if l := int(r.PhysicalAddressLength); l > 0 && l <= len(r.PhysicalAddress) {
			n.MAC = macString(r.PhysicalAddress[:l])
		}
		out = append(out, n)
		if len(out) >= maxItems {
			break
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// readServices liest die Dienste (EnumServicesStatusEx) und liefert die mit Starttyp Automatisch (siehe svcWanted).
// Lesen geht ohne Adminrechte (SC_MANAGER_ENUMERATE_SERVICE, SERVICE_QUERY_CONFIG).
func readServices() ([]m64proto.WinService, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager: %w", err)
	}
	defer windows.CloseServiceHandle(scm)
	var all []svcInfo
	buf := alignedBuf(64 << 10)
	var resume uint32
	for round := 0; round < 64; round++ {
		var needed, count uint32
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, windows.SERVICE_WIN32, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &needed, &count, &resume, nil)
		if err != nil && !errors.Is(err, windows.ERROR_MORE_DATA) {
			return nil, fmt.Errorf("EnumServicesStatusEx: %w", err)
		}
		if count == 0 && errors.Is(err, windows.ERROR_MORE_DATA) {
			if needed <= uint32(len(buf)) || needed > 4<<20 {
				return nil, fmt.Errorf("EnumServicesStatusEx: buffer %d", needed)
			}
			buf = alignedBuf(int(needed))
			continue
		}
		ents := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), count)
		for _, e := range ents {
			st := e.ServiceStatusProcess
			all = append(all, svcInfo{name: windows.UTF16PtrToString(e.ServiceName), display: windows.UTF16PtrToString(e.DisplayName),
				state: st.CurrentState, exitCode: st.Win32ExitCode, specific: st.ServiceSpecificExitCode})
		}
		if err == nil || len(all) >= 4096 {
			break
		}
	}
	var out []m64proto.WinService
	for _, s := range all {
		if !queryServiceConfig(scm, &s) || !svcWanted(s) {
			continue
		}
		out = append(out, m64proto.WinService{Name: clip(s.name), Display: clip(s.display), State: svcState(s.state), StartType: "auto"})
		if len(out) >= maxItems {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// queryServiceConfig ergaenzt Starttyp, verzoegerten Start und Trigger; false, wenn der Dienst nicht lesbar ist.
func queryServiceConfig(scm windows.Handle, s *svcInfo) bool {
	name, err := windows.UTF16PtrFromString(s.name)
	if err != nil {
		return false
	}
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return false
	}
	defer windows.CloseServiceHandle(h)
	buf := alignedBuf(8 << 10)
	var n uint32
	err = windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), uint32(len(buf)), &n)
	if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) && n > uint32(len(buf)) && n <= 256<<10 { // lange Abhaengigkeiten
		buf = alignedBuf(int(n))
		err = windows.QueryServiceConfig(h, (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0])), uint32(len(buf)), &n)
	}
	if err != nil {
		return false
	}
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	s.startType = cfg.StartType
	if cfg.ServiceType&0x40 != 0 { // SERVICE_USER_SERVICE: Dienst je Benutzer (Vorlage bzw. Instanz)
		s.startType = 0xffff
		return true
	}
	if s.startType != svcAutoStart {
		return true
	}
	small := alignedBuf(256)
	if windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &small[0], uint32(len(small)), &n) == nil && n >= 4 {
		s.delayed = (*windows.SERVICE_DELAYED_AUTO_START_INFO)(unsafe.Pointer(&small[0])).IsDelayedAutoStartUp != 0
	}
	trig := alignedBuf(8 << 10)
	err = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_TRIGGER_INFO, &trig[0], uint32(len(trig)), &n)
	if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		s.triggers = 1 // viele Trigger
	} else if err == nil && n >= 4 {
		s.triggers = *(*uint32)(unsafe.Pointer(&trig[0])) // SERVICE_TRIGGER_INFO.cTriggers
	}
	return true
}

// readReboot prueft die Registry-Merkmale fuer "Neustart noetig".
func readReboot() (wu, cbs, renames bool) {
	keyExists := func(path string) bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		k.Close()
		return true
	}
	wu = keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`)
	cbs = keyExists(`SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`)
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE); err == nil {
		if v, _, err := k.GetStringsValue("PendingFileRenameOperations"); err == nil {
			for _, s := range v {
				if s != "" {
					renames = true
					break
				}
			}
		} else if errors.Is(err, registry.ErrUnexpectedType) {
			renames = true // anderer Typ als REG_MULTI_SZ: vorhandener Wert zaehlt
		}
		k.Close()
	}
	return wu, cbs, renames
}
