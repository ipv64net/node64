package sonar

// Ablage im DataDir: sonar64.key (Ed25519-Seed, 0600) und sonar64.json (Node-ID, Seq, Tageszaehler, letzter Plan
// mit ETag). Zusammen ein paar KB; geschrieben wird nur bei Meldung, neuem Plan und Anmeldung.

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	keyFile       = "sonar64.key"
	stateFile     = "sonar64.json"
	maxStateFile  = 1 << 20   // groesser wird nicht gelesen
	maxStoredPlan = 256 << 10 // groessere Plaene (Anker) bleiben nur im Speicher
)

// persisted ist der Inhalt von sonar64.json.
type persisted struct {
	NodeID    string    `json:"node_id,omitempty"`
	TokenID   string    `json:"token_id,omitempty"` // erste 16 Hex von SHA-256(Token): Token-Wechsel erkennen
	Seq       uint64    `json:"seq"`
	Day       string    `json:"day,omitempty"` // UTC-Tag des Zaehlers
	SentToday int       `json:"sent_today"`
	PlanRaw   []byte    `json:"plan_raw,omitempty"` // exakte Bytes von plan (Base64 in JSON)
	PlanKID   string    `json:"plan_kid,omitempty"`
	PlanSig   string    `json:"plan_sig,omitempty"`
	ETag      string    `json:"etag,omitempty"`
	PlanGot   time.Time `json:"plan_got,omitzero"`
}

// tokenID ist die Kurzform eines Tokens (nie das Token selbst ablegen).
func tokenID(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:8])
}

// shortID ist die Kurz-ID eines Knotens: erste 4 Byte von SHA-256(NodeID), hex klein.
func shortID(nodeID string) string {
	h := sha256.Sum256([]byte(nodeID))
	return hex.EncodeToString(h[:4])
}

// loadOrCreateKey laedt den Knoten-Schluessel oder legt ihn an. Ein kaputter Schluessel ist ein Fehler (nie still
// ueberschreiben, sonst waere der Knoten seine Identitaet los).
func loadOrCreateKey(dir string) (ed25519.PrivateKey, error) {
	p := filepath.Join(dir, keyFile)
	b, err := readLimited(p, 1024)
	if errors.Is(err, os.ErrNotExist) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		if err := writeAtomic(p, []byte(base64.StdEncoding.EncodeToString(seed)+"\n")); err != nil {
			return nil, fmt.Errorf("sonar: write key: %w", err)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if err != nil {
		return nil, fmt.Errorf("sonar: read key: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("sonar: key file " + keyFile + " is damaged (remove it only if the node may get a new identity)")
	}
	_ = os.Chmod(p, 0o600) // zu weite Rechte korrigieren (Windows: ohne Wirkung)
	return ed25519.NewKeyFromSeed(seed), nil
}

// loadState liest sonar64.json (fehlt = leer).
func loadState(dir string) (persisted, error) {
	var st persisted
	b, err := readLimited(filepath.Join(dir, stateFile), maxStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return persisted{}, err
	}
	if !validNodeID(st.NodeID) {
		st.NodeID = ""
	}
	return st, nil
}

// writeState schreibt sonar64.json atomar.
func writeState(dir string, st persisted) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, stateFile), b)
}

func readLimited(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("sonar: " + filepath.Base(p) + " too large")
	}
	return b, nil
}

// writeAtomic schreibt ueber eine Temp-Datei (0600) und benennt sie um.
func writeAtomic(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), "."+filepath.Base(p)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name() // CreateTemp legt mit 0600 an
	defer os.Remove(tmp)
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// saveState schreibt den Zustand (ohne DataDir nichts). Fehler nur ins Log.
func (r *Runner) saveState() {
	if r.cfg.DataDir == "" {
		return
	}
	r.mu.Lock()
	st := r.st
	r.mu.Unlock()
	if err := writeState(r.cfg.DataDir, st); err != nil {
		r.log.Warn("sonar64: cannot save state", "err", err)
	}
}

// sentTodayLocked liefert den Tageszaehler (UTC) und setzt ihn um Mitternacht zurueck. r.mu gehalten.
func (r *Runner) sentTodayLocked(now time.Time) int {
	day := now.UTC().Format("2006-01-02")
	if r.st.Day != day {
		r.st.Day, r.st.SentToday = day, 0
	}
	return r.st.SentToday
}
