package healthchecks

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ipv64net/node64/internal/wire"
)

// Testlauf von ipv64 vor dem Umhaengen auf online/hybrid (wie im Portal): die Standorte messen die Definition aus
// dem Formular einmal; umgehaengt wird erst beim Speichern.

// OnlineTest ist das Ergebnis eines Testlaufs.
type OnlineTest struct {
	Status  string          `json:"status"` // ok, failed, expired
	Error   string          `json:"error,omitempty"`
	Results []OnlineTestRow `json:"results"`
}

// OnlineTestRow ist das Ergebnis eines Standorts.
type OnlineTestRow struct {
	Location string `json:"location"`
	OK       bool   `json:"ok"`
	Message  string `json:"message"`
}

// SetOnlineTest installiert den Testlauf ueber den hub (nil = standalone).
func (m *Module) SetOnlineTest(fn func(ctx context.Context, def wire.Check, locations []string) (*OnlineTest, error)) {
	m.onlineTest = fn
}

var errNoOnlineTest = errors.New("online test needs the ipv64 link")

// runOnlineTest prueft die Eingabe wie beim Speichern (ohne Ausfuehrungsort) und laesst ipv64 sie messen.
func (m *Module) runOnlineTest(ctx context.Context, token string, in checkJSON) (*OnlineTest, error) {
	if m.onlineTest == nil || m.linked == nil || !m.linked() {
		return nil, errNoOnlineTest
	}
	locs := in.Locations
	in.Execution = "local" // Ausfuehrungsort und Limits prueft erst das Speichern; ipv64 prueft private Ziele selbst
	c := &Check{Token: token}
	if err := m.apply(c, in, true); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 80*time.Second)
	defer cancel()
	return m.onlineTest(ctx, m.WireCheck(c, nil), locs)
}

// uiOnlineTest: POST /healthchecks/online-test (Formularfelder wie beim Speichern, token optional) -> JSON.
func (m *Module) uiOnlineTest(w http.ResponseWriter, r *http.Request) {
	in, err := checkFromForm(r)
	if err == nil {
		var res *OnlineTest
		res, err = m.runOnlineTest(r.Context(), r.PostFormValue("token"), in)
		if err == nil {
			writeJSON(w, http.StatusOK, res)
			return
		}
	}
	writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": err.Error()})
}

// apiOnlineTest: POST /api/checks/online-test {Check wie beim Anlegen, "token" optional} -> OnlineTest.
func (m *Module) apiOnlineTest(w http.ResponseWriter, r *http.Request) {
	var in struct {
		checkJSON
		Token string `json:"token"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	res, err := m.runOnlineTest(r.Context(), in.Token, in.checkJSON)
	if err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
