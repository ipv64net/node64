package monitor64

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ipv64net/node64/internal/monitor64/transport"
)

// SSH mit Passwort: der Hostschluessel wird nicht mehr still gelernt. Ein in der Oberflaeche bestaetigter Fingerabdruck
// laesst sich setzen, solange keiner gemerkt ist; ein gemerkter aendert sich nur ueber "verwerfen".
func TestPasswordAccessHostKeyConfirm(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	h := &Host{Name: "alt01", Address: "10.0.0.40", Kind: "linux-ssh", IntervalSec: 60, Paused: true}
	if err := e.m.store.SaveHost(ctx, h, SystemActor); err != nil {
		t.Fatal(err)
	}
	rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "ssh", "config": map[string]any{"user": "monitor64"}, "secret": "geheim"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var a accessOut
	decodeBody(t, rec.Body.Bytes(), &a)
	if a.HostKey != "" {
		t.Fatalf("host key without confirmation: %q", a.HostKey)
	}
	fp1, fp2 := "SHA256:"+strings.Repeat("a", 43), "SHA256:"+strings.Repeat("b", 43)
	stored := func() string { return e.col(`SELECT hostkey FROM m64_access WHERE uid = ?`, a.UID) }
	if rec := e.do("PUT", "/api/monitor64/access/"+a.UID, map[string]any{"hostkey": fp1}); rec.Code != 200 || stored() != fp1 {
		t.Fatalf("confirm: %d %s stored=%q", rec.Code, rec.Body, stored())
	}
	// gemerkt: ein anderer Fingerabdruck per PUT aendert nichts (nur "reset")
	if rec := e.do("PUT", "/api/monitor64/access/"+a.UID, map[string]any{"hostkey": fp2}); rec.Code != 200 || stored() != fp1 {
		t.Fatalf("overwrite: %d stored=%q", rec.Code, stored())
	}
	if rec := e.do("PUT", "/api/monitor64/access/"+a.UID, map[string]any{"hostkey": "reset"}); rec.Code != 200 || stored() != "" {
		t.Fatalf("reset: %d stored=%q", rec.Code, stored())
	}
	// Zugang mit Schluessel-Anmeldung und nur gelerntem Hostschluessel: das erste Passwort verwirft ihn (erst
	// bestaetigen), mit dem Fingerabdruck in derselben Eingabe (in der Oberflaeche bestaetigt) bleibt er
	keyAcc := func() accessOut {
		rec := e.do("POST", "/api/monitor64/hosts/"+h.UID+"/access", map[string]any{"type": "ssh", "config": map[string]any{"user": "monitor64"}, "hostkey": fp1})
		if rec.Code != http.StatusCreated {
			t.Fatalf("create key access: %d %s", rec.Code, rec.Body)
		}
		var o accessOut
		decodeBody(t, rec.Body.Bytes(), &o)
		return o
	}
	k1, k2 := keyAcc(), keyAcc()
	if rec := e.do("PUT", "/api/monitor64/access/"+k1.UID, map[string]any{"secret": "geheim"}); rec.Code != 200 {
		t.Fatalf("add password: %d %s", rec.Code, rec.Body)
	}
	if got := e.col(`SELECT hostkey FROM m64_access WHERE uid = ?`, k1.UID); got != "" {
		t.Fatalf("learned host key kept for the first password: %q", got)
	}
	if rec := e.do("PUT", "/api/monitor64/access/"+k2.UID, map[string]any{"secret": "geheim", "hostkey": fp1}); rec.Code != 200 {
		t.Fatalf("add password with confirmed key: %d %s", rec.Code, rec.Body)
	}
	if got := e.col(`SELECT hostkey FROM m64_access WHERE uid = ?`, k2.UID); got != fp1 {
		t.Fatalf("confirmed host key lost: %q", got)
	}
	// ein weiteres Passwort (schon eines hinterlegt) laesst den bestaetigten Schluessel stehen
	if rec := e.do("PUT", "/api/monitor64/access/"+k2.UID, map[string]any{"secret": "neu"}); rec.Code != 200 || e.col(`SELECT hostkey FROM m64_access WHERE uid = ?`, k2.UID) != fp1 {
		t.Fatalf("password change dropped the confirmed key: %d", rec.Code)
	}
	// Anzeige am Zugang, solange die Bestaetigung fehlt
	txt := accessErrText(&transport.UnconfirmedKeyError{Got: fp1})
	if !strings.Contains(txt, "monitor64.detail.hostkey_unconfirmed") {
		t.Fatalf("access text: %q", txt)
	}
	if got := accessErrText(errors.New("dial tcp: refused")); got != "dial tcp: refused" {
		t.Fatalf("other errors unchanged: %q", got)
	}
}
