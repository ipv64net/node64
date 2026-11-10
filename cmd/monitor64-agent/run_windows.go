//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows/svc"

	"github.com/ipv64net/node64/internal/m64agent"
)

// Name des Windows-Dienstes.
const serviceName = "monitor64-agent"

// Protokoll des Dienstes (ohne Konsole): <dir>\agent.log, bei maxLogBytes nach agent.log.1 gedreht; Abstuerze
// zusaetzlich in crash.log.
const maxLogBytes = 1 << 20

// asService: der Prozess laeuft als Windows-Dienst (restartSelf beendet sich dann, der Dienst-Manager startet neu).
var asService atomic.Bool

// logDone schliesst das Protokoll des Dienstes (vor os.Exit, damit nichts verloren geht).
var logDone func()

func init() {
	platformRun = runWindows
	onServer = desktopStatus
}

// desktopStatus: als Dienst den Stand fuer das Symbol im Infobereich schreiben und das Symbol in den angemeldeten
// Sitzungen starten (ausser mit --no-tray). Im Vordergrund geschieht nichts.
func desktopStatus(ctx context.Context, srv *m64agent.Server, exe string, f runFlags, log *slog.Logger) {
	if !asService.Load() || exe == "" {
		return
	}
	go statusLoop(ctx, srv, exe, log)
	if !f.noTray {
		go trayKeeper(ctx, exe, log)
	}
}

// runWindows startet den Agent als Dienst (vom Dienst-Manager gestartet) bzw. im Vordergrund (Konsole).
func runWindows(exe string, args []string) int {
	keepRunLink(exe)
	// Ordner der Einstellungen nie mit geerbten Rechten anlegen (Hostschluessel, Protokoll; siehe ensureDataDir)
	dir, flagsOK := defaultDir, false
	if f, err := parseRunFlags(args, io.Discard); err == nil {
		dir, flagsOK = f.dir, true
	}
	isSvc, err := svc.IsWindowsService()
	// Im Vordergrund mit fehlerhaften Flags keinen Ordner anlegen: der Standardordner gehoerte dann dem Benutzer und
	// stuende einer spaeteren Installation im Weg. Der Dienst braucht ihn auch dann (Protokoll mit der Fehlermeldung).
	var dirErr error
	if flagsOK || (err == nil && isSvc) {
		dirErr = ensureDataDir(dir)
	}
	if err != nil || !isSvc {
		if dirErr != nil {
			fmt.Fprintln(os.Stderr, "monitor64-agent:", dirErr)
		}
		return runAgent(exe, args)
	}
	asService.Store(true)
	logDone = serviceLog(dir, dirErr)
	defer logDone()
	h := &agentService{exe: exe, args: args}
	if err := svc.Run(serviceName, h); err != nil {
		fmt.Fprintln(os.Stderr, "monitor64-agent: service:", err)
		return 1
	}
	return h.code
}

// keepRunLink legt einen zweiten Namen (<exe>.run) fuer die laufende Datei an. Windows erlaubt dann, den Namen <exe>
// zu ersetzen, waehrend sie laeuft - das braucht der Rueckfall nach einem Update (die neue Version laeuft, wenn sie
// beim zweiten Start die alte Datei zurueckholt). Der Verweis der vorigen Datei wird dabei entfernt. Ist der Ordner
// nicht beschreibbar, gibt es keinen Verweis (dann scheitert nur dieser Rueckfall, die Datei bleibt).
func keepRunLink(exe string) {
	if exe == "" {
		return
	}
	run := exe + ".run"
	_ = os.Remove(run)
	_ = os.Link(exe, run)
}

// agentService verbindet den Dienst-Manager mit runAgent.
type agentService struct {
	exe  string
	args []string
	code int
}

func (a *agentService) Execute(_ []string, req <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseContext = func() context.Context { return ctx }
	done := make(chan int, 1)
	go func() { done <- runAgent(a.exe, a.args) }()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				st <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				st <- svc.Status{State: svc.StopPending, WaitHint: 10000}
				cancel()
			}
		case code := <-done:
			a.code = code
			if code != 0 {
				// eigener Fehlercode: der Dienst-Manager startet neu (Wiederherstellung auch ohne Absturz, siehe install)
				return true, uint32(code)
			}
			return false, 0
		}
	}
}

// serviceLog leitet stderr (slog des Agents) in eine Datei in dir mit Groessengrenze um und meldet Abstuerze nach
// crash.log. Liefert eine Funktion, die das Protokoll schliesst. dirErr: dir liess sich nicht anlegen.
func serviceLog(dir string, dirErr error) func() {
	if dirErr != nil {
		return func() {}
	}
	if f, err := os.OpenFile(filepath.Join(dir, "crash.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		_ = f.Close() // SetCrashOutput haelt eine eigene Kopie
	}
	r, w, err := os.Pipe()
	if err != nil {
		return func() {}
	}
	l := &rotLog{path: filepath.Join(dir, "agent.log"), max: maxLogBytes}
	os.Stderr = w
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(l, r)
		l.close()
		close(done)
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = w.Close()
			<-done
		})
	}
}

// rotLog schreibt in eine Datei und dreht sie bei max Bytes (eine alte Datei bleibt).
type rotLog struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

func (l *rotLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil && l.size+int64(len(p)) > l.max {
		_ = l.f.Close()
		l.f = nil
		_ = os.Rename(l.path, l.path+".1")
	}
	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return len(p), nil // Protokoll ist Zusatz: der Agent laeuft weiter
		}
		l.f = f
		if fi, err := f.Stat(); err == nil {
			l.size = fi.Size()
		}
		if l.size+int64(len(p)) > l.max && l.size > 0 { // vom letzten Lauf schon voll
			_ = f.Close()
			l.f = nil
			_ = os.Rename(l.path, l.path+".1")
			if l.f, err = os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
				l.f = nil
				return len(p), nil
			}
			l.size = 0
		}
	}
	n, _ := l.f.Write(p)
	l.size += int64(n)
	return len(p), nil
}

func (l *rotLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		_ = l.f.Close()
		l.f = nil
	}
}
