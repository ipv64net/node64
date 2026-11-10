//go:build windows

package main

import (
	_ "embed"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Symbol im Infobereich der Taskleiste ("monitor64-agent tray"): zeigt, dass der Dienst laeuft, seine Version, die
// letzte Abfrage durch die Node und ob ein Update ansteht (die Node nennt die verfuegbare Version, siehe
// m64agent.Status). Laeuft mit den Rechten des angemeldeten Benutzers und liest nur: den Zustand des Dienstes beim
// Dienst-Manager und <Programmordner>\status.json. Gestartet vom Dienst (trayspawn_windows.go) oder von Hand.

//go:embed tray.png
var trayPNG []byte

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassEx       = user32.NewProc("RegisterClassExW")
	procCreateWindowEx        = user32.NewProc("CreateWindowExW")
	procDefWindowProc         = user32.NewProc("DefWindowProcW")
	procGetMessage            = user32.NewProc("GetMessageW")
	procTranslateMessage      = user32.NewProc("TranslateMessage")
	procDispatchMessage       = user32.NewProc("DispatchMessageW")
	procPostQuitMessage       = user32.NewProc("PostQuitMessage")
	procPostMessage           = user32.NewProc("PostMessageW")
	procRegisterWindowMessage = user32.NewProc("RegisterWindowMessageW")
	procSetTimer              = user32.NewProc("SetTimer")
	procCreatePopupMenu       = user32.NewProc("CreatePopupMenu")
	procAppendMenu            = user32.NewProc("AppendMenuW")
	procTrackPopupMenu        = user32.NewProc("TrackPopupMenu")
	procDestroyMenu           = user32.NewProc("DestroyMenu")
	procSetForegroundWindow   = user32.NewProc("SetForegroundWindow")
	procGetCursorPos          = user32.NewProc("GetCursorPos")
	procLoadIcon              = user32.NewProc("LoadIconW")
	procCreateIconFromRes     = user32.NewProc("CreateIconFromResourceEx")
	procGetSystemMetrics      = user32.NewProc("GetSystemMetrics")
	procShellNotifyIcon       = shell32.NewProc("Shell_NotifyIconW")
	procGetModuleHandle       = kernel32.NewProc("GetModuleHandleW")
	procGetUserDefaultUILang  = kernel32.NewProc("GetUserDefaultUILanguage")
)

const (
	wmDestroy   = 0x0002
	wmTimer     = 0x0113
	wmLButtonUp = 0x0202
	wmRButtonUp = 0x0205
	wmTrayIcon  = 0x8000 + 1 // WM_APP + 1: Meldungen des Symbols

	nimAdd, nimModify, nimDelete = 0, 1, 2
	nifMessage, nifIcon, nifTip  = 1, 2, 4

	mfString, mfDisabled, mfSeparator = 0x0, 0x2, 0x800
	tpmRightButton, tpmBottomAlign    = 0x2, 0x20
	tpmNoNotify, tpmReturnCmd         = 0x80, 0x100

	idiApplication, idiWarning = 32512, 32515
	smCxSmIcon, smCySmIcon     = 49, 50

	trayRefresh = 5 * time.Second
	cmdHide     = 1
)

// notifyIconData ist NOTIFYICONDATAW (ab Vista).
type notifyIconData struct {
	Size            uint32
	Wnd             windows.HWND
	ID              uint32
	Flags           uint32
	CallbackMessage uint32
	Icon            windows.Handle
	Tip             [128]uint16
	State           uint32
	StateMask       uint32
	Info            [256]uint16
	Version         uint32
	InfoTitle       [64]uint16
	InfoFlags       uint32
	GUIDItem        windows.GUID
	BalloonIcon     windows.Handle
}

type wndClassEx struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   windows.Handle
	Icon       windows.Handle
	Cursor     windows.Handle
	Background windows.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     windows.Handle
}

type winMsg struct {
	Wnd     windows.HWND
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      struct{ X, Y int32 }
	Private uint32
}

// trayView ist, was das Symbol zeigt.
type trayView struct {
	Version   string
	Installed bool  // Dienst eingerichtet
	Running   bool  // Dienst laeuft
	Started   int64 // Start des Dienstes (Unix-Sekunden, 0 = unbekannt)
	LastReq   int64 // letzte Abfrage der Node
	Latest    string
	PID       int
}

// trayLines baut Tooltip und Menuezeilen (de = Deutsch, sonst Englisch); now fuer "vor ...".
func trayLines(v trayView, de bool, now time.Time) (tip string, lines []string) {
	t := func(d, e string) string {
		if de {
			return d
		}
		return e
	}
	title := "Monitor64-Agent " + v.Version
	var svc, short string
	switch {
	case !v.Installed:
		svc, short = t("Dienst ist nicht eingerichtet", "Service is not installed"), t("nicht eingerichtet", "not installed")
	case !v.Running:
		svc, short = t("Dienst läuft nicht", "Service is not running"), t("läuft nicht", "not running")
	default:
		svc, short = t("Dienst läuft", "Service is running"), t("läuft", "running")
		if v.Started > 0 {
			svc += t(" seit ", " since ") + time.Unix(v.Started, 0).Format(t("02.01. 15:04", "Jan 2 15:04"))
		}
	}
	lines = append(lines, title, svc)
	if v.Running {
		if v.LastReq > 0 {
			lines = append(lines, t("Letzte Abfrage durch die Node: ", "Last poll by the node: ")+trayAgo(now.Sub(time.Unix(v.LastReq, 0)), de))
		} else {
			lines = append(lines, t("Noch keine Abfrage durch die Node", "Not polled by the node yet"))
		}
	}
	tip = title + " – " + short
	switch {
	case v.Latest == "":
		lines = append(lines, t("Update: noch keine Angabe der Node", "Update: no information from the node yet"))
	case newerVersion(v.Latest, v.Version):
		lines = append(lines, t("Update verfügbar: ", "Update available: ")+v.Latest+t(" – Einspielen über Node64", " – installed via Node64"))
		tip += t(" – Update verfügbar: ", " – update available: ") + v.Latest
	default:
		lines = append(lines, t("Update: aktuell", "Update: up to date"))
	}
	return tip, lines
}

// trayAgo: "vor 12 s", "vor 3 min", "vor 2 h" bzw. englisch.
func trayAgo(d time.Duration, de bool) string {
	if d < 0 {
		d = 0
	}
	var n int
	var unit string
	switch {
	case d < time.Minute:
		n, unit = int(d/time.Second), "s"
	case d < time.Hour:
		n, unit = int(d/time.Minute), "min"
	default:
		n, unit = int(d/time.Hour), "h"
	}
	if de {
		return fmt.Sprintf("vor %d %s", n, unit)
	}
	return fmt.Sprintf("%d %s ago", n, unit)
}

// newerVersion: a ist neuer als b (Zahlen je Punkt verglichen, "v" vorn und Zusatz nach "-" zaehlen nicht; nicht
// lesbare Versionen wie "dev" gelten nie als aelter).
func newerVersion(a, b string) bool {
	pa, oka := versionParts(a)
	pb, okb := versionParts(b)
	if !oka || !okb {
		return false
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func versionParts(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	v, _, _ = strings.Cut(v, "-")
	v, _, _ = strings.Cut(v, "+")
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, len(out) > 0
}

// serviceState fragt den Dienst-Manager (nur Leserechte, geht ohne Administratorrechte).
func serviceState() (installed, running bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(serviceName)
	h, err := windows.OpenService(scm, name, windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return false, false
	}
	defer windows.CloseServiceHandle(h)
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(h, &st); err != nil {
		return true, false
	}
	return true, st.CurrentState == windows.SERVICE_RUNNING
}

// trayApp ist das laufende Symbol.
type trayApp struct {
	wnd        windows.HWND
	icon, warn windows.Handle
	statusPath string
	de         bool
	added      bool
	tip        string
	warnShown  bool
	pid        int  // Dienst-Instanz, zu der das Symbol gehoert (aus status.json)
	hide       bool // vom Benutzer ausgeblendet
	taskbarMsg uint32
}

// view liest den aktuellen Stand.
func (a *trayApp) view() trayView {
	v := trayView{Version: Version}
	v.Installed, v.Running = serviceState()
	if st, ok := readStatus(a.statusPath); ok && v.Running {
		v.Version, v.Started, v.LastReq, v.Latest, v.PID = st.Version, st.Started, st.LastRequest, st.Latest, st.PID
	}
	return v
}

func (a *trayApp) notify(cmd uintptr, tip string, icon windows.Handle) bool {
	nid := notifyIconData{Wnd: a.wnd, ID: 1, Flags: nifMessage | nifIcon | nifTip, CallbackMessage: wmTrayIcon, Icon: icon}
	nid.Size = uint32(unsafe.Sizeof(nid))
	u, _ := windows.UTF16FromString(tip)
	if len(u) > len(nid.Tip) {
		u = append(u[:len(nid.Tip)-1], 0)
	}
	copy(nid.Tip[:], u)
	r, _, _ := procShellNotifyIcon.Call(cmd, uintptr(unsafe.Pointer(&nid)))
	return r != 0
}

// refresh zeigt den Stand (Tooltip, Warnsymbol, wenn der Dienst nicht laeuft). Liefert false, wenn das Symbol enden
// soll: der Dienst wurde neu gestartet (z. B. nach einem Update) - seine neue Instanz startet ein eigenes Symbol.
func (a *trayApp) refresh() bool {
	v := a.view()
	if v.PID != 0 {
		if a.pid == 0 {
			a.pid = v.PID
		} else if a.pid != v.PID {
			return false
		}
	}
	tip, _ := trayLines(v, a.de, time.Now())
	icon, warn := a.icon, !v.Running
	if warn && a.warn != 0 {
		icon = a.warn
	}
	switch {
	case !a.added:
		a.added = a.notify(nimAdd, tip, icon) // scheitert, solange die Taskleiste noch nicht bereit ist: spaeter erneut
	case tip != a.tip || warn != a.warnShown:
		a.notify(nimModify, tip, icon)
	}
	a.tip, a.warnShown = tip, warn
	return true
}

// menu zeigt die Angaben als Menue am Mauszeiger; "Symbol ausblenden" beendet das Symbol.
func (a *trayApp) menu() {
	_, lines := trayLines(a.view(), a.de, time.Now())
	m, _, _ := procCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer procDestroyMenu.Call(m)
	for _, l := range lines {
		p, _ := windows.UTF16PtrFromString(l)
		procAppendMenu.Call(m, mfString|mfDisabled, 0, uintptr(unsafe.Pointer(p)))
	}
	procAppendMenu.Call(m, mfSeparator, 0, 0)
	hide := "Hide icon"
	if a.de {
		hide = "Symbol ausblenden"
	}
	p, _ := windows.UTF16PtrFromString(hide)
	procAppendMenu.Call(m, mfString, cmdHide, uintptr(unsafe.Pointer(p)))
	var pt struct{ X, Y int32 }
	procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	procSetForegroundWindow.Call(uintptr(a.wnd)) // sonst schliesst das Menue nicht beim Klick daneben
	cmd, _, _ := procTrackPopupMenu.Call(m, tpmRightButton|tpmBottomAlign|tpmNoNotify|tpmReturnCmd, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(a.wnd), 0)
	procPostMessage.Call(uintptr(a.wnd), 0, 0, 0)
	if cmd == cmdHide {
		a.hide = true
		a.quit()
	}
}

func (a *trayApp) quit() {
	if a.added {
		a.notify(nimDelete, "", 0)
		a.added = false
	}
	procPostQuitMessage.Call(0)
}

func (a *trayApp) wndProc(wnd windows.HWND, msg uint32, wp, lp uintptr) uintptr {
	switch {
	case msg == wmTrayIcon:
		if ev := uint32(lp) & 0xffff; ev == wmLButtonUp || ev == wmRButtonUp {
			a.menu()
		}
		return 0
	case msg == wmTimer:
		if !a.refresh() {
			a.quit()
		}
		return 0
	case msg == a.taskbarMsg && a.taskbarMsg != 0: // Explorer neu gestartet: Symbol erneut anmelden
		a.added = false
		a.refresh()
		return 0
	case msg == wmDestroy:
		a.quit()
		return 0
	}
	r, _, _ := procDefWindowProc.Call(uintptr(wnd), uintptr(msg), wp, lp)
	return r
}

// tray zeigt das Symbol, bis es ausgeblendet wird (Rueckgabe trayExitHidden) oder der Dienst neu startet.
func tray(args []string) int {
	if len(args) > 0 {
		fmt.Fprintln(os.Stderr, "usage: monitor64-agent tray")
		return 2
	}
	runtime.LockOSThread() // Fenster und Meldungsschleife gehoeren zu einem Thread
	name, _ := windows.UTF16PtrFromString(`Local\monitor64-agent-tray`)
	if mu, err := windows.CreateMutex(nil, false, name); err == windows.ERROR_ALREADY_EXISTS {
		return trayExitRunning // je Sitzung ein Symbol
	} else if mu != 0 {
		defer windows.CloseHandle(mu)
	}
	a := &trayApp{statusPath: statusPath(selfPath())}
	if lang, _, _ := procGetUserDefaultUILang.Call(); lang&0x3ff == 0x07 { // LANG_GERMAN
		a.de = true
	}
	cx, _, _ := procGetSystemMetrics.Call(smCxSmIcon)
	cy, _, _ := procGetSystemMetrics.Call(smCySmIcon)
	ico, _, _ := procCreateIconFromRes.Call(uintptr(unsafe.Pointer(&trayPNG[0])), uintptr(len(trayPNG)), 1, 0x00030000, cx, cy, 0)
	if ico == 0 {
		ico, _, _ = procLoadIcon.Call(0, idiApplication)
	}
	warn, _, _ := procLoadIcon.Call(0, idiWarning)
	a.icon, a.warn = windows.Handle(ico), windows.Handle(warn)

	inst, _, _ := procGetModuleHandle.Call(0)
	class, _ := windows.UTF16PtrFromString("Monitor64AgentTray")
	wc := wndClassEx{WndProc: windows.NewCallback(a.wndProc), Instance: windows.Handle(inst), ClassName: class}
	wc.Size = uint32(unsafe.Sizeof(wc))
	if r, _, err := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		fmt.Fprintln(os.Stderr, "monitor64-agent: tray: window class:", err)
		return 1
	}
	wnd, _, err := procCreateWindowEx.Call(0, uintptr(unsafe.Pointer(class)), uintptr(unsafe.Pointer(class)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if wnd == 0 {
		fmt.Fprintln(os.Stderr, "monitor64-agent: tray: window:", err)
		return 1
	}
	a.wnd = windows.HWND(wnd)
	tb, _ := windows.UTF16PtrFromString("TaskbarCreated")
	if m, _, _ := procRegisterWindowMessage.Call(uintptr(unsafe.Pointer(tb))); m != 0 {
		a.taskbarMsg = uint32(m)
	}
	a.refresh()
	procSetTimer.Call(wnd, 1, uintptr(trayRefresh/time.Millisecond), 0)

	var msg winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&msg)), 0, 0, 0)
		if int32(r) <= 0 {
			break
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&msg)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&msg)))
	}
	if a.hide {
		return trayExitHidden
	}
	return 1 // Dienst neu gestartet bzw. Fenster geschlossen: die neue Instanz des Dienstes startet das Symbol neu
}
