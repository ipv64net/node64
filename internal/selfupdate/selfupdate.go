// Package selfupdate aktualisiert Node64 ohne neues Image: Das Programm aus dem Image ist zugleich der Starter
// (Launch) und waehlt beim Start die neueste geprueft abgelegte Version unter <data>/bin. Ein Update holt ein
// signiertes Manifest, laedt das Programm der eigenen Architektur, prueft Groesse und SHA-256, sichert die Datenbank
// und startet in-place neu (exec, PID bleibt). Laeuft die neue Version nicht stabil, geht der Starter nach
// MaxAttempts Starts ohne "gesund" auf die vorige Version samt Datenbank-Sicherung zurueck. Plan: docs/PLAN-SELF-UPDATE.md.
package selfupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/update"
)

const (
	DefaultBase  = "https://ipv64.net/node64/releases" // Manifest: <Base>/<Kanal>/manifest.json (+ .sig)
	MaxAttempts  = 3                                   // Starts ohne "gesund", dann Rueckfall
	HealthyAfter = 5 * time.Minute                     // so lange muss eine neue Version laufen
	maxBinary    = 200 << 20                           // Obergrenze fuer ein Programm
	maxManifest  = 64 << 10

	envChild        = "NODE64_SELFUPDATE_VERSION" // gesetzt im Programm aus <data>/bin (vom Starter)
	envImage        = "NODE64_IMAGE_BINARY"       // Pfad des Programms aus dem Image (fuer den Neustart)
	envImageVersion = "NODE64_IMAGE_VERSION"
)

// Kanaele: stable (ohne Vorab-Kennung) und preview (alpha/beta).
var Channels = []string{"stable", "preview"}

// PublicKeys: oeffentliche Ed25519-Schluessel (base64, durch Komma getrennt), die Manifeste signieren duerfen.
// Ergaenzbar beim Bauen: -ldflags "-X github.com/ipv64net/node64/internal/selfupdate.PublicKeys=..."
var PublicKeys = defaultKeys

// Keys liefert die gueltigen oeffentlichen Schluessel.
func Keys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, k := range strings.Split(PublicKeys, ",") {
		b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
		if err == nil && len(b) == ed25519.PublicKeySize {
			out = append(out, ed25519.PublicKey(b))
		}
	}
	return out
}

// Arch: Architektur-Schluessel im Manifest (amd64, arm64, armv7).
func Arch() string {
	if runtime.GOARCH == "arm" {
		return "armv7"
	}
	return runtime.GOARCH
}

// ---------------------------------------------------------------- Manifest

// File ist ein Programm im Manifest.
type File struct {
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest beschreibt eine Version (signiert, manifest.sig = base64(Ed25519-Signatur der Datei)).
type Manifest struct {
	Version    string          `json:"version"`
	Channel    string          `json:"channel"`
	Date       string          `json:"date,omitempty"`
	Notes      string          `json:"notes,omitempty"`       // URL der Hinweise
	MinVersion string          `json:"min_version,omitempty"` // aelter: erst per Image aktualisieren
	Files      map[string]File `json:"files"`
}

// Verify prueft die Signatur (mindestens ein Schluessel) und liest das Manifest.
func Verify(raw, sig []byte, keys []ed25519.PublicKey) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, errors.New("no update signing key built in")
	}
	s, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sig)))
	if err != nil || len(s) != ed25519.SignatureSize {
		return nil, errors.New("invalid signature format")
	}
	ok := false
	for _, k := range keys {
		if ed25519.Verify(k, raw, s) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("signature does not match")
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Version == "" || len(m.Files) == 0 {
		return nil, errors.New("manifest incomplete")
	}
	return &m, nil
}

// Sign signiert ein Manifest (fuer das Release-Werkzeug und Tests).
func Sign(raw []byte, key ed25519.PrivateKey) []byte {
	return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(key, raw)))
}

// ---------------------------------------------------------------- Zustand in <data>/bin/state.json

// Installed ist eine abgelegte Version.
type Installed struct {
	File      string    `json:"file"`
	SHA256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Installed time.Time `json:"installed"`
}

// Trial: eine neue Version, die noch nicht als gesund gilt.
type Trial struct {
	Version  string    `json:"version"`
	Attempts int       `json:"attempts"`
	Since    time.Time `json:"since"`
	Backup   string    `json:"backup,omitempty"` // Datenbank vor dem Update (Dateiname in bin/)
}

// State ist der Zustand des Selbst-Updates.
type State struct {
	Current  string               `json:"current,omitempty"` // gewaehlte Version aus bin/ ("" = Image)
	Previous string               `json:"previous,omitempty"`
	Versions map[string]Installed `json:"versions,omitempty"`
	Trial    *Trial               `json:"trial,omitempty"`
	Bad      []string             `json:"bad,omitempty"`    // fehlgeschlagene Versionen (nicht erneut automatisch)
	Notice   string               `json:"notice,omitempty"` // letzter Rueckfall: "von|zurueck auf|Zeit" (Anzeige)
	// NoticeSent: Rueckfall schon gemeldet (Benachrichtigung einmal)
	NoticeSent bool `json:"notice_sent,omitempty"`
}

func binDir(dataDir string) string { return filepath.Join(dataDir, "bin") }

// LoadState liest den Zustand (fehlt die Datei: leer).
func LoadState(dataDir string) (*State, error) {
	st := &State{Versions: map[string]Installed{}}
	b, err := os.ReadFile(filepath.Join(binDir(dataDir), "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return &State{Versions: map[string]Installed{}}, err
	}
	if st.Versions == nil {
		st.Versions = map[string]Installed{}
	}
	return st, nil
}

// Save schreibt den Zustand atomar.
func (st *State) Save(dataDir string) error {
	if err := os.MkdirAll(binDir(dataDir), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := filepath.Join(binDir(dataDir), "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(binDir(dataDir), "state.json"))
}

func (st *State) isBad(v string) bool {
	for _, b := range st.Bad {
		if b == v {
			return true
		}
	}
	return false
}

// fileOK prueft eine abgelegte Version (Groesse und SHA-256).
func fileOK(path string, in Installed) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, maxBinary+1))
	if err != nil {
		return err
	}
	if n != in.Size || hex.EncodeToString(h.Sum(nil)) != in.SHA256 {
		return errors.New("checksum mismatch")
	}
	return nil
}

// rollback: Version als fehlgeschlagen merken, Datenbank-Sicherung zurueckspielen, vorige Version waehlen.
func (st *State) rollback(dataDir, imageVersion string) {
	failed := st.Current
	if !st.isBad(failed) {
		st.Bad = append(st.Bad, failed)
	}
	if st.Trial != nil && st.Trial.Backup != "" {
		db := filepath.Join(dataDir, "node64.db")
		backup := filepath.Join(binDir(dataDir), st.Trial.Backup)
		if err := copyFile(backup, db); err == nil {
			_ = os.Remove(db + "-wal")
			_ = os.Remove(db + "-shm")
		} else if _, serr := os.Stat(backup); serr == nil {
			// Sicherung nicht zurueckgespielt: nach backups/ retten, damit cleanup sie nicht loescht
			keep := filepath.Join(dataDir, "backups", st.Trial.Backup)
			if os.MkdirAll(filepath.Dir(keep), 0o750) == nil && os.Rename(backup, keep) == nil {
				backup = keep
			}
			fmt.Fprintf(os.Stderr, "node64: self-update rollback could not restore the database (%v), backup kept at %s\n", err, backup)
		}
	}
	st.Current = ""
	if p := st.Previous; p != "" && !st.isBad(p) && update.Newer(p, imageVersion) {
		st.Current = p
	}
	back := st.Current
	if back == "" {
		back = imageVersion
	}
	st.Notice, st.NoticeSent = fmt.Sprintf("%s|%s|%s", failed, back, time.Now().UTC().Format(time.RFC3339)), false
	st.Previous, st.Trial = "", nil
	st.cleanup(dataDir) // fehlgeschlagenes Programm und die zurueckgespielte Sicherung weg
}

// copyFile kopiert src atomar nach dst (eigene Zwischendatei, fsync, rename). Die Zwischendatei darf nicht
// node64.db.restore heissen: die setzt applyRestore beim Start als hochgeladene Datenbank ein.
func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".rollback.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp) // keine halbe Kopie liegen lassen
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	if d, derr := os.Open(filepath.Dir(dst)); derr == nil { // Umbenennung dauerhaft machen
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// cleanup loescht Programme und Sicherungen, die nicht mehr gebraucht werden (behaelt Current und Previous).
func (st *State) cleanup(dataDir string) {
	keep := map[string]bool{"state.json": true}
	for _, v := range []string{st.Current, st.Previous} {
		if in, ok := st.Versions[v]; ok && v != "" {
			keep[in.File] = true
		}
	}
	if st.Trial != nil && st.Trial.Backup != "" {
		keep[st.Trial.Backup] = true
	}
	for v, in := range st.Versions {
		if !keep[in.File] {
			delete(st.Versions, v)
		}
	}
	entries, _ := os.ReadDir(binDir(dataDir))
	for _, e := range entries {
		if !keep[e.Name()] && !e.IsDir() {
			_ = os.Remove(filepath.Join(binDir(dataDir), e.Name()))
		}
	}
}

// choose: die zu startende Version aus bin/ ("" = Image). Zaehlt Startversuche, faellt zurueck, raeumt auf.
// Aenderungen am Zustand werden gespeichert.
func choose(dataDir, imageVersion string) (version, path string) {
	st, err := LoadState(dataDir)
	if err != nil || (st.Current == "" && st.Trial == nil) {
		return "", ""
	}
	changed := false
	if st.Trial != nil && st.Trial.Version == st.Current {
		st.Trial.Attempts++
		changed = true
		if st.Trial.Attempts > MaxAttempts {
			st.rollback(dataDir, imageVersion)
		}
	}
	for st.Current != "" {
		v := st.Current
		in, ok := st.Versions[v]
		switch {
		case !update.Newer(v, imageVersion): // Image gleich oder neuer: bin/ nicht mehr noetig
			st.Current, st.Previous, st.Trial = "", "", nil
			st.cleanup(dataDir)
		case !ok || st.isBad(v) || fileOK(filepath.Join(binDir(dataDir), in.File), in) != nil:
			if !st.isBad(v) {
				st.Bad = append(st.Bad, v)
			}
			st.Current, st.Trial = st.Previous, nil
			st.Previous = ""
		default:
			if changed {
				_ = st.Save(dataDir)
			}
			return v, filepath.Join(binDir(dataDir), in.File)
		}
		changed = true
	}
	if changed {
		_ = st.Save(dataDir)
	}
	return "", ""
}

// ---------------------------------------------------------------- Laufende Version

// Running: Version, die gerade laeuft, und ob sie aus bin/ stammt.
func Running(current string) (version, origin, imageVersion string) {
	if v := os.Getenv(envChild); v != "" {
		return v, "update", os.Getenv(envImageVersion)
	}
	return current, "image", current
}

// MarkHealthy: die laufende Version gilt als gesund (nach HealthyAfter); alte Dateien weg. Liefert die vorige
// Version aus bin/ ("" = Image) und ob eine Probezeit beendet wurde.
func MarkHealthy(dataDir, running string) (from string, done bool, err error) {
	st, err := LoadState(dataDir)
	if err != nil {
		return "", false, err
	}
	if st.Trial == nil || st.Trial.Version != running {
		return "", false, nil
	}
	from = st.Previous
	st.Trial = nil
	st.cleanup(dataDir)
	return from, true, st.Save(dataDir)
}

// ---------------------------------------------------------------- Updater

// Updater prueft und installiert Updates.
type Updater struct {
	DataDir string
	Current string // eingebaute Version (main.Version)
	Base    string
	Client  *http.Client
	Backup  func(ctx context.Context, dest string) error // Datenbank sichern (Store.Backup)
	Restart func()                                       // sauber beenden und neu starten (main)

	mu   sync.Mutex
	busy bool
}

// New legt den Updater an (Base aus NODE64_UPDATE_URL, sonst DefaultBase).
func New(dataDir, current string) *Updater {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("NODE64_UPDATE_URL")), "/")
	if base == "" {
		base = DefaultBase
	}
	return &Updater{DataDir: dataDir, Current: current, Base: base, Client: &http.Client{Timeout: 5 * time.Minute}}
}

// Status ist der Zustand fuer Oberflaeche und API.
type Status struct {
	Running      string    `json:"running"`
	Origin       string    `json:"origin"` // image | update
	ImageVersion string    `json:"image_version,omitempty"`
	Previous     string    `json:"previous,omitempty"`
	Trial        *Trial    `json:"trial,omitempty"`
	Bad          []string  `json:"bad,omitempty"`
	Rollback     *Rollback `json:"rollback,omitempty"`
	KeysOK       bool      `json:"signing_key"`
	Arch         string    `json:"arch"`
	Dev          bool      `json:"dev"` // Entwicklungsstand: kein automatisches Update
}

// Rollback: letzter automatischer Rueckfall.
type Rollback struct {
	From string    `json:"from"`
	To   string    `json:"to"`
	At   time.Time `json:"at"`
}

func (u *Updater) Status() Status {
	run, origin, img := Running(u.Current)
	s := Status{Running: run, Origin: origin, ImageVersion: img, KeysOK: len(Keys()) > 0, Arch: Arch(), Dev: strings.Contains(run, "-dev")}
	if st, err := LoadState(u.DataDir); err == nil {
		s.Previous, s.Trial, s.Bad = st.Previous, st.Trial, st.Bad
		if p := strings.Split(st.Notice, "|"); len(p) == 3 {
			at, _ := time.Parse(time.RFC3339, p[2])
			s.Rollback = &Rollback{From: p[0], To: p[1], At: at}
		}
	}
	sort.Strings(s.Bad)
	return s
}

// allowed: nur URLs unterhalb von Base (gleicher Host, gleiches Schema).
func (u *Updater) allowed(raw string) bool {
	b, err1 := url.Parse(u.Base)
	x, err2 := url.Parse(raw)
	if err1 != nil || err2 != nil || x.Host != b.Host || x.Scheme != b.Scheme {
		return false
	}
	return x.Scheme == "https" || os.Getenv("NODE64_UPDATE_URL") != "" // http nur fuer eigene Test-Quellen
}

func (u *Updater) get(ctx context.Context, raw string, limit int64) ([]byte, error) {
	if !u.allowed(raw) {
		return nil, fmt.Errorf("url not allowed: %s", raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "node64/"+u.Current)
	resp, err := u.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", raw, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: too large", raw)
	}
	return b, nil
}

// Check holt und prueft das Manifest eines Kanals.
func (u *Updater) Check(ctx context.Context, channel string) (*Manifest, error) {
	if channel != "stable" && channel != "preview" {
		channel = "stable"
	}
	base := u.Base + "/" + channel + "/manifest.json"
	raw, err := u.get(ctx, base, maxManifest)
	if err != nil {
		return nil, err
	}
	sig, err := u.get(ctx, base+".sig", 1024)
	if err != nil {
		return nil, err
	}
	return Verify(raw, sig, Keys())
}

// Newer: ob das Manifest eine neuere Version als die laufende anbietet.
func (u *Updater) Newer(m *Manifest) bool {
	run, _, _ := Running(u.Current)
	return m != nil && update.Newer(m.Version, run)
}

// ErrBusy: ein Update laeuft schon.
var ErrBusy = errors.New("update already running")

// Apply laedt die Version des Manifests, prueft sie, sichert die Datenbank und startet neu (Restart).
func (u *Updater) Apply(ctx context.Context, m *Manifest) error {
	u.mu.Lock()
	if u.busy {
		u.mu.Unlock()
		return ErrBusy
	}
	u.busy = true
	u.mu.Unlock()
	defer func() { u.mu.Lock(); u.busy = false; u.mu.Unlock() }()

	run, _, img := Running(u.Current)
	if !update.Newer(m.Version, run) {
		return fmt.Errorf("version %s is not newer than %s", m.Version, run)
	}
	if img == "" { // Image-Version unbekannt (aelterer Starter): eingebaute Version
		img = u.Current
	}
	if m.MinVersion != "" && update.Newer(m.MinVersion, img) {
		return fmt.Errorf("image too old: update the container image to %s or newer first", m.MinVersion)
	}
	f, ok := m.Files[Arch()]
	if !ok {
		return fmt.Errorf("no build for %s", Arch())
	}
	if f.Size <= 0 || f.Size > maxBinary || len(f.SHA256) != 64 {
		return errors.New("manifest entry invalid")
	}
	if err := os.MkdirAll(binDir(u.DataDir), 0o750); err != nil {
		return err
	}
	bin, err := u.get(ctx, f.URL, f.Size)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(bin)
	if int64(len(bin)) != f.Size || hex.EncodeToString(sum[:]) != strings.ToLower(f.SHA256) {
		return errors.New("download does not match the manifest (size or checksum)")
	}
	name := "node64-" + safeName(m.Version)
	tmp := filepath.Join(binDir(u.DataDir), name+".tmp")
	if err := os.WriteFile(tmp, bin, 0o750); err != nil {
		return err
	}
	if err := syncFile(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(binDir(u.DataDir), name)); err != nil {
		return err
	}
	backup := "db-before-" + safeName(m.Version) + ".db"
	_ = os.Remove(filepath.Join(binDir(u.DataDir), backup)) // VACUUM INTO braucht ein freies Ziel
	if u.Backup != nil {
		if err := u.Backup(ctx, filepath.Join(binDir(u.DataDir), backup)); err != nil {
			return fmt.Errorf("database backup: %w", err)
		}
	}
	st, err := LoadState(u.DataDir)
	if err != nil {
		st = &State{Versions: map[string]Installed{}}
	}
	if st.Current != "" && st.Current != m.Version {
		st.Previous = st.Current
	}
	st.Current = m.Version
	st.Versions[m.Version] = Installed{File: name, SHA256: strings.ToLower(f.SHA256), Size: f.Size, Installed: time.Now().UTC()}
	st.Trial = &Trial{Version: m.Version, Since: time.Now().UTC(), Backup: backup}
	st.Bad = without(st.Bad, m.Version) // ausdruecklich erneut versucht
	st.Notice, st.NoticeSent = "", false
	st.cleanup(u.DataDir)
	if err := st.Save(u.DataDir); err != nil {
		return err
	}
	if u.Restart != nil {
		u.Restart()
	}
	return nil
}

// Reset: zurueck auf die Version aus dem Image (bin/ leeren) und neu starten.
func (u *Updater) Reset() error {
	st, _ := LoadState(u.DataDir)
	if st == nil {
		st = &State{}
	}
	st.Current, st.Previous, st.Trial, st.Notice = "", "", nil, ""
	st.Versions = map[string]Installed{}
	st.cleanup(u.DataDir)
	if err := st.Save(u.DataDir); err != nil {
		return err
	}
	if u.Restart != nil {
		u.Restart()
	}
	return nil
}

func without(list []string, v string) []string {
	out := list[:0]
	for _, x := range list {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// safeName: Version als Dateiname (nur Ziffern, Buchstaben, . und -).
func safeName(v string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r == '.', r == '-':
			return r
		}
		return '_'
	}, v)
}

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
