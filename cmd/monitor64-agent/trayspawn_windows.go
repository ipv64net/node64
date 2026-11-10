//go:build windows

package main

import (
	"context"
	"log/slog"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Der Dienst laeuft als SYSTEM in Sitzung 0 und kann selbst kein Symbol zeigen. Er startet deshalb in jeder
// angemeldeten Sitzung "monitor64-agent tray" mit dem Token des angemeldeten Benutzers (nie mit hoeheren Rechten)
// und ohne Konsolenfenster. Kein Autostart-Eintrag: das Symbol gibt es genau, solange der Dienst laeuft.
const (
	trayEvery     = 10 * time.Second
	trayRetry     = time.Minute      // nach einem Fehler des Symbols
	trayRetryBusy = 15 * time.Second // lief schon eines (z. B. noch das der vorigen Version)

	// Rueckgabewerte von "tray"
	trayExitHidden  = 0 // vom Benutzer ausgeblendet: in dieser Sitzung nicht wieder starten
	trayExitRunning = 3 // in der Sitzung laeuft schon ein Symbol
)

// trayProcs: vom Dienst gestartete Symbole je Sitzung (fuer stopTrays vor dem Beenden).
var trayProcs = struct {
	sync.Mutex
	m map[uint32]windows.Handle
}{m: map[uint32]windows.Handle{}}

// stopTrays beendet alle gestarteten Symbole (Dienst stoppt bzw. startet nach einem Update neu: die Programmdatei
// darf dann niemand mehr offen haben).
func stopTrays() {
	trayProcs.Lock()
	defer trayProcs.Unlock()
	for id, h := range trayProcs.m {
		_ = windows.TerminateProcess(h, 1)
		_, _ = windows.WaitForSingleObject(h, 2000)
		_ = windows.CloseHandle(h)
		delete(trayProcs.m, id)
	}
}

// trayKeeper haelt in jeder angemeldeten Sitzung ein Symbol am Laufen, bis ctx endet.
func trayKeeper(ctx context.Context, exe string, log *slog.Logger) {
	defer stopTrays()
	hidden := map[uint32]bool{}       // vom Benutzer ausgeblendet (bis zur Abmeldung)
	retryAt := map[uint32]time.Time{} // naechster Versuch nach einem Fehler
	warned := false
	t := time.NewTicker(trayEvery)
	defer t.Stop()
	for {
		active := activeSessions()
		now := time.Now()
		trayProcs.Lock()
		for id, h := range trayProcs.m {
			if ev, _ := windows.WaitForSingleObject(h, 0); ev == uint32(windows.WAIT_TIMEOUT) && active[id] {
				continue // laeuft
			}
			var code uint32
			if !active[id] {
				_ = windows.TerminateProcess(h, 1) // Sitzung abgemeldet bzw. getrennt
			} else if windows.GetExitCodeProcess(h, &code) == nil {
				switch code {
				case trayExitHidden:
					hidden[id] = true
				case trayExitRunning:
					retryAt[id] = now.Add(trayRetryBusy)
				default:
					retryAt[id] = now.Add(trayRetry)
				}
			}
			_ = windows.CloseHandle(h)
			delete(trayProcs.m, id)
		}
		for id := range active {
			if _, ok := trayProcs.m[id]; ok || hidden[id] || now.Before(retryAt[id]) {
				continue
			}
			h, err := spawnTray(id, exe)
			if err != nil {
				retryAt[id] = now.Add(trayRetry)
				if !warned {
					warned = true
					log.Warn("monitor64-agent: tray icon not started", "session", id, "err", err)
				}
				continue
			}
			trayProcs.m[id] = h
		}
		trayProcs.Unlock()
		for id := range hidden { // abgemeldet: bei der naechsten Anmeldung wieder zeigen
			if !active[id] {
				delete(hidden, id)
				delete(retryAt, id)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// activeSessions liefert die Sitzungen mit angemeldetem, aktivem Benutzer (ohne Sitzung 0 der Dienste).
func activeSessions() map[uint32]bool {
	out := map[uint32]bool{}
	var list *windows.WTS_SESSION_INFO
	var n uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &list, &n); err != nil || list == nil {
		return out
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(list)))
	for _, s := range unsafe.Slice(list, n) {
		if s.SessionID != 0 && s.State == windows.WTSActive {
			out[s.SessionID] = true
		}
	}
	return out
}

// spawnTray startet "<exe> tray" in der Sitzung id mit dem Token des dort angemeldeten Benutzers.
func spawnTray(id uint32, exe string) (windows.Handle, error) {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(id, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err == nil {
		defer windows.DestroyEnvironmentBlock(env)
	} else {
		env = nil
	}
	app, err := windows.UTF16PtrFromString(exe)
	if err != nil {
		return 0, err
	}
	cmd, err := windows.UTF16PtrFromString(syscall.EscapeArg(exe) + " tray")
	if err != nil {
		return 0, err
	}
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Desktop: desk}
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi windows.ProcessInformation
	flags := uint32(windows.CREATE_NO_WINDOW | windows.CREATE_UNICODE_ENVIRONMENT)
	if err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false, flags, env, nil, &si, &pi); err != nil {
		return 0, err
	}
	_ = windows.CloseHandle(pi.Thread)
	return pi.Process, nil
}
