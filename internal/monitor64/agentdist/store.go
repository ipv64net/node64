package agentdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
	"github.com/ipv64net/node64/internal/selfupdate"
	"github.com/ipv64net/node64/internal/update"
)

// Zwischenspeicher der Node: holt agents.json (+ Signatur) von der ersten erreichbaren Quelle, laedt Programme und
// Skripte erst beim ersten Bedarf nach <Dir>/<version>/, prueft Groesse, SHA-256 und die signierte Kopfzeile und
// raeumt alte Versionen auf. Nichts wird ausgeliefert, was nicht geprueft ist.

const (
	indexTimeout = 30 * time.Second // je Quelle: Verzeichnis und Signatur
	fileTimeout  = 5 * time.Minute  // ein Programm (alle Quellen zusammen)
	maxRedirects = 3
	tmpPrefix    = ".dl-"
	tmpMaxAge    = time.Hour
)

var (
	// ErrNoIndex: noch kein geprueftes Verzeichnis (Quelle nicht erreichbar oder Signatur ungueltig).
	ErrNoIndex = errors.New("agent index not available")
	// ErrUnknownFile: die Datei steht nicht im Verzeichnis.
	ErrUnknownFile = errors.New("file not in the agent index")
)

// Options beschreibt den Zwischenspeicher.
type Options struct {
	Dir       string                     // Ablage, z. B. <data>/monitor64/agent
	Bases     []string                   // Quellen in dieser Reihenfolge (ohne Schraegstrich am Ende)
	AllowHTTP bool                       // http-Quellen erlauben (nur eigene Test-Quelle)
	Keys      func() []ed25519.PublicKey // Release-Schluessel (nil = die der Selbst-Updates)
	Client    *http.Client               // nil = eigener (Zeitlimits, keine Weiterleitung auf fremde Hosts)
	UserAgent string
	Logger    *slog.Logger
	Now       func() time.Time
}

// Status ist der Stand der Quelle fuer die Oberflaeche.
type Status struct {
	Bases   []string  `json:"bases"`
	Source  string    `json:"source,omitempty"` // Quelle des gespeicherten Verzeichnisses
	Checked time.Time `json:"checked,omitzero"` // letzter Versuch
	OK      time.Time `json:"ok,omitzero"`      // letzter Erfolg
	Error   string    `json:"error,omitempty"`  // Fehler des letzten Versuchs
}

type flight struct {
	done chan struct{}
	err  error
}

// Store ist der Zwischenspeicher. Sicher fuer gleichzeitige Nutzung.
type Store struct {
	opt Options

	mu       sync.Mutex
	ix       *Index
	raw      []byte
	st       Status
	verified map[string]m64proto.UpdateHeader // "<version>/<name>": Programm geprueft (seit dem Start)
	scripts  map[string][]byte                // "<version>/<name>": Skript geprueft
	flights  map[string]*flight               // laufende Abrufe (je Datei hoechstens einer)
	cancels  map[*flight]context.CancelFunc
}

// New legt den Zwischenspeicher an und liest ein schon abgelegtes Verzeichnis (ohne Netz).
func New(opt Options) *Store {
	if opt.Keys == nil {
		opt.Keys = selfupdate.Keys
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.Logger == nil {
		opt.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "node64"
	}
	for i, b := range opt.Bases {
		opt.Bases[i] = strings.TrimRight(strings.TrimSpace(b), "/")
	}
	if opt.Client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.ResponseHeaderTimeout = indexTimeout
		opt.Client = &http.Client{Transport: tr, CheckRedirect: sameHostRedirect}
	}
	s := &Store{opt: opt, verified: map[string]m64proto.UpdateHeader{}, scripts: map[string][]byte{}, flights: map[string]*flight{},
		cancels: map[*flight]context.CancelFunc{}}
	s.st.Bases = append([]string{}, opt.Bases...)
	raw, err1 := os.ReadFile(filepath.Join(opt.Dir, IndexFile))
	sig, err2 := os.ReadFile(filepath.Join(opt.Dir, IndexFile+".sig"))
	if err1 == nil && err2 == nil {
		if ix, err := Verify(raw, sig, opt.Keys()); err == nil {
			s.ix, s.raw = ix, raw
			s.cleanup(ix.Version)
		} else {
			opt.Logger.Warn("monitor64: stored agent index ignored", "err", err)
		}
	}
	return s
}

// sameHostRedirect folgt Weiterleitungen nur auf demselben Host und mit demselben Schema (hoechstens maxRedirects).
func sameHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > maxRedirects {
		return errors.New("too many redirects")
	}
	if first := via[0].URL; req.URL.Host != first.Host || req.URL.Scheme != first.Scheme {
		return errors.New("redirect to another host refused")
	}
	return nil
}

// Index liefert das gepruefte Verzeichnis (nil = noch keines). Nicht veraendern.
func (s *Store) Index() *Index {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ix
}

// Status liefert den Stand der Quelle.
func (s *Store) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st
}

// Due sagt, ob das Verzeichnis neu geholt werden soll: nie versucht, nach every seit dem letzten Erfolg bzw. nach
// retry seit einem Fehlschlag.
func (s *Store) Due(every, retry time.Duration) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.st.Checked.IsZero() {
		return true
	}
	if s.st.Error != "" {
		return s.opt.Now().Sub(s.st.Checked) >= retry
	}
	return s.opt.Now().Sub(s.st.Checked) >= every
}

// Cached sagt, ob das Programm name der aktuellen Version geprueft vorliegt (Anzeige; laedt nichts).
func (s *Store) Cached(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ix == nil {
		return false
	}
	if _, ok := s.verified[s.ix.Version+"/"+name]; ok {
		return true
	}
	_, err := os.Stat(filepath.Join(s.opt.Dir, s.ix.Version, name))
	return err == nil
}

// Abort bricht laufende Abrufe ab und wartet auf ihr Ende (Stopp des Moduls).
func (s *Store) Abort() {
	s.mu.Lock()
	wait := make([]*flight, 0, len(s.cancels))
	for f, c := range s.cancels {
		c()
		wait = append(wait, f)
	}
	s.mu.Unlock()
	for _, f := range wait {
		<-f.done
	}
}

// once fuehrt fn je key hoechstens einmal gleichzeitig aus; weitere Aufrufer warten auf dasselbe Ergebnis. Der Abruf
// laeuft mit eigenem Zeitlimit weiter, wenn der erste Aufrufer aufgibt (z. B. ein Host bricht den Download ab).
func (s *Store) once(ctx context.Context, key string, limit time.Duration, fn func(context.Context) error) error {
	s.mu.Lock()
	f := s.flights[key]
	if f == nil {
		f = &flight{done: make(chan struct{})}
		fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), limit)
		s.flights[key], s.cancels[f] = f, cancel
		go func() {
			defer func() {
				if r := recover(); r != nil {
					f.err = fmt.Errorf("agent files: %v", r)
				}
				cancel()
				s.mu.Lock()
				delete(s.flights, key)
				delete(s.cancels, f)
				s.mu.Unlock()
				close(f.done)
			}()
			f.err = fn(fctx)
		}()
	}
	s.mu.Unlock()
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Refresh holt das Verzeichnis von der ersten Quelle, die ein gueltig signiertes liefert. Ein aelteres als das
// gespeicherte wird nicht uebernommen (kein Rueckschritt, z. B. eine Ausweichquelle mit altem Stand).
func (s *Store) Refresh(ctx context.Context) error {
	return s.once(ctx, "index", indexTimeout*time.Duration(max(1, len(s.opt.Bases))), s.refresh)
}

func (s *Store) refresh(ctx context.Context) error {
	var errs []string
	for _, base := range s.opt.Bases {
		bctx, cancel := context.WithTimeout(ctx, indexTimeout)
		ix, raw, sig, err := s.fetchIndex(bctx, base)
		cancel()
		if err == nil {
			if cur := s.Index(); cur != nil && update.Newer(cur.Version, ix.Version) {
				err = fmt.Errorf("%s: version %s is older than the stored %s", base, ix.Version, cur.Version)
			}
		}
		if err == nil {
			err = s.adopt(ix, raw, sig, base)
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		now := s.opt.Now()
		s.mu.Lock()
		s.st.Source, s.st.Checked, s.st.OK, s.st.Error = base, now, now, ""
		s.mu.Unlock()
		return nil
	}
	if len(errs) == 0 {
		errs = append(errs, "no source configured")
	}
	err := errors.New(strings.Join(errs, "; "))
	s.mu.Lock()
	s.st.Checked, s.st.Error = s.opt.Now(), err.Error()
	s.mu.Unlock()
	return err
}

func (s *Store) fetchIndex(ctx context.Context, base string) (*Index, []byte, []byte, error) {
	raw, err := s.get(ctx, base+"/"+IndexFile, MaxIndexBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	sig, err := s.get(ctx, base+"/"+IndexFile+".sig", 1024)
	if err != nil {
		return nil, nil, nil, err
	}
	ix, err := Verify(raw, sig, s.opt.Keys())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", base, err)
	}
	return ix, raw, sig, nil
}

// adopt uebernimmt ein geprueftes Verzeichnis: ablegen (atomar), bei neuer Version alte Dateien aufraeumen.
func (s *Store) adopt(ix *Index, raw, sig []byte, base string) error {
	s.mu.Lock()
	same := bytes.Equal(raw, s.raw)
	s.mu.Unlock()
	if !same {
		if err := os.MkdirAll(s.opt.Dir, 0o750); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(s.opt.Dir, IndexFile+".sig"), sig); err != nil {
			return err
		}
		if err := writeAtomic(filepath.Join(s.opt.Dir, IndexFile), raw); err != nil {
			return err
		}
	}
	s.mu.Lock()
	changed := s.ix == nil || !same
	if changed { // auch gleiche Version mit anderem Inhalt: alles neu pruefen
		s.ix, s.raw = ix, raw
		s.verified, s.scripts = map[string]m64proto.UpdateHeader{}, map[string][]byte{}
	}
	s.mu.Unlock()
	if changed {
		s.opt.Logger.Info("monitor64: agent index", "version", ix.Version, "source", base)
		s.cleanup(ix.Version)
	}
	return nil
}

// cleanup loescht die Ordner anderer Versionen und liegen gebliebene Zwischendateien.
func (s *Store) cleanup(keep string) {
	ents, _ := os.ReadDir(s.opt.Dir)
	for _, e := range ents {
		if e.IsDir() && ValidVersion(e.Name()) && e.Name() != keep {
			_ = os.RemoveAll(filepath.Join(s.opt.Dir, e.Name()))
		}
	}
	ents, _ = os.ReadDir(filepath.Join(s.opt.Dir, keep))
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), tmpPrefix) {
			continue
		}
		if fi, err := e.Info(); err == nil && s.opt.Now().Sub(fi.ModTime()) > tmpMaxAge {
			_ = os.Remove(filepath.Join(s.opt.Dir, keep, e.Name()))
		}
	}
}

// Program liefert Pfad und signierte Kopfzeile des Programms name (monitor64-agent-<os>-<arch>[.exe]) der aktuellen
// Version; beim ersten Bedarf wird es geladen und geprueft.
func (s *Store) Program(ctx context.Context, name string) (string, m64proto.UpdateHeader, error) {
	ix := s.Index()
	if ix == nil {
		return "", m64proto.UpdateHeader{}, ErrNoIndex
	}
	f, prog, ok := ix.Lookup(name)
	if !ok || !prog {
		return "", m64proto.UpdateHeader{}, ErrUnknownFile
	}
	key := ix.Version + "/" + f.Name
	path := filepath.Join(s.opt.Dir, ix.Version, f.Name)
	hdr := func() (m64proto.UpdateHeader, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		h, ok := s.verified[key]
		return h, ok
	}
	if h, ok := hdr(); ok {
		if fi, err := os.Stat(path); err == nil && fi.Size() == f.Size {
			return path, h, nil
		}
	}
	if err := s.once(ctx, key, fileTimeout, func(c context.Context) error { return s.ensureProgram(c, ix, f) }); err != nil {
		return "", m64proto.UpdateHeader{}, err
	}
	h, ok := hdr()
	if !ok { // Verzeichnis hat inzwischen gewechselt
		return "", m64proto.UpdateHeader{}, ErrNoIndex
	}
	return path, h, nil
}

// ensureProgram prueft die abgelegte Datei bzw. laedt sie (Quelle des Verzeichnisses zuerst).
func (s *Store) ensureProgram(ctx context.Context, ix *Index, f File) error {
	dir := filepath.Join(s.opt.Dir, ix.Version)
	path := filepath.Join(dir, f.Name)
	key := ix.Version + "/" + f.Name
	mark := func(h m64proto.UpdateHeader) {
		s.mu.Lock()
		if s.ix == ix {
			s.verified[key] = h
		}
		s.mu.Unlock()
	}
	if fileMatches(path, f) == nil {
		if raw, err := os.ReadFile(path + HeaderSuffix); err == nil {
			if h, err := parseHeader(raw, ix.Version, f, s.opt.Keys()); err == nil {
				mark(h)
				return nil
			}
		}
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	var errs []string
	for _, base := range s.order() {
		u := base + "/" + ix.Version + "/" + f.Name
		h, raw, tmp, err := s.fetchProgram(ctx, u, dir, ix.Version, f)
		if err != nil {
			errs = append(errs, err.Error())
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if err = writeAtomic(path+HeaderSuffix, raw); err == nil {
			err = os.Rename(tmp, path)
		}
		if err != nil {
			_ = os.Remove(tmp)
			return err
		}
		mark(h)
		s.opt.Logger.Info("monitor64: agent file stored", "file", f.Name, "version", ix.Version, "source", base)
		return nil
	}
	if len(errs) == 0 {
		errs = append(errs, "no source configured")
	}
	return errors.New(strings.Join(errs, "; "))
}

// fetchProgram laedt Kopfzeile und Programm einer Quelle; das Programm liegt danach geprueft in einer Zwischendatei.
func (s *Store) fetchProgram(ctx context.Context, u, dir, version string, f File) (h m64proto.UpdateHeader, raw []byte, tmp string, err error) {
	// zuerst die kleine Kopfzeile: ohne gueltige Signatur wird das Programm gar nicht erst geladen
	if raw, err = s.get(ctx, u+HeaderSuffix, MaxHeaderBytes); err != nil {
		return h, nil, "", err
	}
	if h, err = parseHeader(raw, version, f, s.opt.Keys()); err != nil {
		return h, nil, "", fmt.Errorf("%s: %w", u, err)
	}
	out, err := os.CreateTemp(dir, tmpPrefix+"*")
	if err != nil {
		return h, nil, "", err
	}
	tmp = out.Name()
	err = s.download(ctx, u, f, out)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return h, nil, "", err
	}
	return h, raw, tmp, nil
}

func parseHeader(raw []byte, version string, f File, keys []ed25519.PublicKey) (m64proto.UpdateHeader, error) {
	var h m64proto.UpdateHeader
	if err := json.Unmarshal(bytes.TrimSpace(raw), &h); err != nil {
		return h, fmt.Errorf("update header of %s is not valid JSON", f.Name)
	}
	return h, CheckHeader(h, version, f, keys)
}

// fileMatches prueft eine abgelegte Datei gegen Groesse und SHA-256 des Verzeichnisses.
func fileMatches(path string, f File) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	hs := sha256.New()
	n, err := io.Copy(hs, io.LimitReader(in, f.Size+1))
	if err != nil {
		return err
	}
	if n != f.Size || hex.EncodeToString(hs.Sum(nil)) != f.SHA256 {
		return errors.New("checksum mismatch")
	}
	return nil
}

// Script liefert ein Skript (install.sh, install.ps1) der aktuellen Version, geprueft gegen das Verzeichnis.
func (s *Store) Script(ctx context.Context, name string) ([]byte, error) {
	ix := s.Index()
	if ix == nil {
		return nil, ErrNoIndex
	}
	f, prog, ok := ix.Lookup(name)
	if !ok || prog {
		return nil, ErrUnknownFile
	}
	key := ix.Version + "/" + f.Name
	cached := func() []byte {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.scripts[key]
	}
	if b := cached(); b != nil {
		return b, nil
	}
	err := s.once(ctx, key, indexTimeout*time.Duration(max(1, len(s.opt.Bases))), func(c context.Context) error {
		b, err := s.ensureScript(c, ix, f)
		if err == nil {
			s.mu.Lock()
			if s.ix == ix {
				s.scripts[key] = b
			}
			s.mu.Unlock()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	if b := cached(); b != nil {
		return b, nil
	}
	return nil, ErrNoIndex
}

func (s *Store) ensureScript(ctx context.Context, ix *Index, f File) ([]byte, error) {
	dir := filepath.Join(s.opt.Dir, ix.Version)
	path := filepath.Join(dir, f.Name)
	if b, err := os.ReadFile(path); err == nil && bytesMatch(b, f) {
		return b, nil
	}
	var errs []string
	for _, base := range s.order() {
		u := base + "/" + ix.Version + "/" + f.Name
		b, err := s.get(ctx, u, f.Size)
		if err == nil && !bytesMatch(b, f) {
			err = fmt.Errorf("%s: does not match the index (size or checksum)", u)
		}
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, err
		}
		if err := writeAtomic(path, b); err != nil {
			return nil, err
		}
		return b, nil
	}
	if len(errs) == 0 {
		errs = append(errs, "no source configured")
	}
	return nil, errors.New(strings.Join(errs, "; "))
}

func bytesMatch(b []byte, f File) bool {
	sum := sha256.Sum256(b)
	return int64(len(b)) == f.Size && hex.EncodeToString(sum[:]) == f.SHA256
}

// order: die Quelle des gespeicherten Verzeichnisses zuerst, dann die uebrigen.
func (s *Store) order() []string {
	s.mu.Lock()
	src := s.st.Source
	s.mu.Unlock()
	out := make([]string, 0, len(s.opt.Bases))
	if src != "" {
		out = append(out, src)
	}
	for _, b := range s.opt.Bases {
		if b != src {
			out = append(out, b)
		}
	}
	return out
}

// allowed: nur https (http nur fuer eine eigene Test-Quelle).
func (s *Store) allowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && s.opt.AllowHTTP)
}

func (s *Store) open(ctx context.Context, raw string) (*http.Response, error) {
	if !s.allowed(raw) {
		return nil, fmt.Errorf("url not allowed: %s", raw)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", s.opt.UserAgent)
	resp, err := s.opt.Client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("%s: HTTP %d", raw, resp.StatusCode)
	}
	return resp, nil
}

// get laedt eine kleine Datei (hoechstens limit Byte).
func (s *Store) get(ctx context.Context, raw string, limit int64) ([]byte, error) {
	resp, err := s.open(ctx, raw)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", raw, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: too large", raw)
	}
	return b, nil
}

// download schreibt ein Programm nach out und prueft Groesse und SHA-256 (nie mehr als f.Size Byte).
func (s *Store) download(ctx context.Context, raw string, f File, out *os.File) error {
	resp, err := s.open(ctx, raw)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.ContentLength >= 0 && resp.ContentLength != f.Size {
		return fmt.Errorf("%s: size %d differs from the index (%d)", raw, resp.ContentLength, f.Size)
	}
	hs := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, hs), io.LimitReader(resp.Body, f.Size+1))
	if err != nil {
		return fmt.Errorf("%s: %w", raw, err)
	}
	if n != f.Size || hex.EncodeToString(hs.Sum(nil)) != f.SHA256 {
		return fmt.Errorf("%s: does not match the index (size or checksum)", raw)
	}
	return out.Sync()
}

// writeAtomic schreibt eine Datei ueber eine Zwischendatei im selben Ordner.
func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), tmpPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(name, 0o640)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}
