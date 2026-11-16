package m64linux

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/m64proto"
)

// #169 (Oracle Linux 9): Unter der gehaerteten Unit (ProtectSystem=strict) bricht dnf beim Oeffnen von
// /var/log/dnf.log ab und meldet Exit 1 - "needs-restarting -r" galt dann dauerhaft als "Neustart noetig".
const nrConfigError = "Config error: [Errno 30] Read-only file system: '/var/log/dnf.log'\n"

func TestNeedsRestarting169(t *testing.T) {
	for _, c := range []struct {
		name     string
		code     int
		out      string
		req, ok  bool
		errMatch string
	}{
		{"Neustart noetig", 1, "Core libraries or services have been updated since boot-up:\n  * kernel\n\nReboot is required to fully utilize these updates.\n", true, true, ""},
		{"uebersetzt", 1, "Seit dem Systemstart wurden Kernbibliotheken aktualisiert.\nEin Neustart ist erforderlich.\n", true, true, ""},
		{"nicht noetig", 0, "No core libraries or services have been updated since boot-up.\n", false, true, ""},
		{"Config error", 1, nrConfigError, false, false, "Read-only file system"},
		{"Traceback", 1, "Traceback (most recent call last):\n  File \"/usr/bin/dnf\", line 61\nPermissionError: [Errno 13] Permission denied\n", false, false, "Traceback"},
		{"anderer Code", 2, "", false, false, "2"},
	} {
		req, ok, err := NeedsRestarting(c.code, []byte(c.out))
		if req != c.req || ok != c.ok || (c.errMatch == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.errMatch)) {
			t.Errorf("%s: req=%v ok=%v err=%v", c.name, req, ok, err)
		}
	}
}

// Agent: mit PkgLogDir und dnf laeuft needs-restarting ueber dnf mit eigenem Log-Ordner (nicht /var/log); ein
// Config error ergibt keinen Neustart, sondern einen Fehler im Abschnitt reboot (Dienst unbekannt statt "ja").
func TestCollectNeedsRestarting169(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "dnf")
	var got []string
	result := ExecResult{Code: 1, Stderr: []byte(nrConfigError)}
	opt := Options{Root: t.TempDir(), Cache: NewCache(), Sections: []string{m64proto.SecReboot}, PkgLogDir: logDir,
		Has: func(n string) bool { return n == "needs-restarting" || n == "dnf" },
		Exec: func(_ context.Context, name string, args ...string) (ExecResult, error) {
			got = append([]string{name}, args...)
			return result, nil
		}}
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	r := Collect(context.Background(), opt)
	if want := "dnf --setopt=logdir=" + logDir + " needs-restarting -r"; strings.Join(got, " ") != want {
		t.Fatalf("Aufruf %q, erwartet %q", strings.Join(got, " "), want)
	}
	if r.Reboot != nil || len(r.Errors) != 1 || r.Errors[0].Section != m64proto.SecReboot || !strings.Contains(r.Errors[0].Error, "Read-only") {
		t.Fatalf("Config error als Neustart gewertet: reboot=%+v errs=%+v", r.Reboot, r.Errors)
	}
	// echtes "Neustart noetig" (neuer Puffer)
	result = ExecResult{Code: 1, Stdout: []byte("Reboot is required to fully utilize these updates.\n")}
	opt.Cache = NewCache()
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	if r := Collect(context.Background(), opt); r.Reboot == nil || !r.Reboot.Required || len(r.Errors) != 0 {
		t.Fatalf("Neustart noetig: %+v %+v", r.Reboot, r.Errors)
	}
}

// Agent: dnf check-update und updateinfo mit eigenem Log-Ordner.
func TestCollectUpdatesDnfLogDir169(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "dnf")
	var calls []string
	opt := Options{Root: t.TempDir(), Cache: NewCache(), Sections: []string{m64proto.SecUpdates}, PkgLogDir: logDir,
		Has: func(n string) bool { return n == "dnf" },
		Exec: func(_ context.Context, name string, args ...string) (ExecResult, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return ExecResult{Code: 0}, nil
		}}
	Collect(context.Background(), opt)
	opt.Cache.Wait()
	if len(calls) == 0 {
		t.Fatal("dnf nicht aufgerufen")
	}
	for _, c := range calls {
		if !strings.HasPrefix(c, "dnf --setopt=logdir="+logDir+" -q ") {
			t.Errorf("Aufruf ohne eigenen Log-Ordner: %q", c)
		}
	}
}

// SSH: das Skript gibt die Ausgabe von needs-restarting mit; ein Config error ist kein "Neustart noetig".
func TestParseScriptNeedsRestarting169(t *testing.T) {
	out := "\n<<<m64:start>>>\n1\n\n<<<m64:needs_restarting>>>\n1\n" + nrConfigError + "\n<<<m64:end>>>\n"
	r, err := ParseScriptOutput([]byte(out), testNow)
	if err != nil {
		t.Fatal(err)
	}
	rebootErr := false
	for _, e := range r.Errors {
		rebootErr = rebootErr || (e.Section == m64proto.SecReboot && strings.Contains(e.Error, "Read-only"))
	}
	if r.Reboot != nil || !rebootErr {
		t.Fatalf("reboot=%+v errs=%+v", r.Reboot, r.Errors)
	}
	out = "\n<<<m64:start>>>\n1\n\n<<<m64:needs_restarting>>>\n1\nReboot is required to fully utilize these updates.\n\n<<<m64:end>>>\n"
	if r, _ := ParseScriptOutput([]byte(out), testNow); r.Reboot == nil || !r.Reboot.Required {
		t.Fatalf("Neustart noetig: %+v", r.Reboot)
	}
	if !strings.Contains(Script, `m64_o=$(m64_run TERM 30 needs-restarting -r 2>&1)`) {
		t.Error("Skript gibt die Ausgabe von needs-restarting nicht mit")
	}
}
