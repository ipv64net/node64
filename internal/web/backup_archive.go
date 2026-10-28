package web

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/backup"
)

// Vollstaendiges Backup als Archiv mit Passwort (Datenbank, secret.key, Dateien der Module wie die
// DNS64-Freigabeliste und Zertifikate; auf Wunsch auch die Statistik-Datenbanken). Wiederherstellen
// legt den Inhalt unter restore.new ab; cmd/node64 setzt ihn beim naechsten Start ein.

const (
	RestoreDirName  = "restore.new"
	maxArchiveBytes = 8 << 30 // entpackt
)

// backupSkip: nicht ins Archiv (Caches, alte Sicherungen, Arbeitsdateien). geoip/ ist der Zwischenspeicher der
// Laenderdaten (laedt die Node von ipv64.net neu), Blocklisten ebenso. bin/ gehoert zum Selbst-Update (Programmdateien,
// Stand): ein Archiv darf keine alte Programmversion zurueckbringen.
func backupSkip(rel string, dir bool) bool {
	base := filepath.Base(rel)
	switch {
	case rel == "backups" || rel == "tmp" || rel == "geoip" || rel == "bin" || rel == RestoreDirName || strings.HasPrefix(base, ".backup-") || strings.HasPrefix(base, "restore."):
		return true
	case dir && (base == "lists" || base == "blocklists" || strings.Contains(base, ".bak")):
		return true
	case !dir && (base == RestoreFileName || base == ResetFileName || strings.HasSuffix(base, "-wal") || strings.HasSuffix(base, "-shm") || strings.HasSuffix(base, "-journal")):
		return true
	}
	return false
}

// backupFiles sammelt die Dateien fuer das Archiv; Datenbanken werden vorher konsistent nach tmp kopiert.
func (s *Server) backupFiles(ctx context.Context, tmp string, withStats bool) ([]backup.File, error) {
	db := filepath.Join(tmp, "node64.db")
	if err := s.Store.Backup(ctx, db); err != nil {
		return nil, err
	}
	files := []backup.File{{Name: "node64.db", Path: db}}
	main := filepath.Join(s.Cfg.DataDir, "node64.db")
	err := filepath.WalkDir(s.Cfg.DataDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(s.Cfg.DataDir, p)
		if rel == "." {
			return nil
		}
		if backupSkip(filepath.ToSlash(rel), d.IsDir()) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() || !d.Type().IsRegular() || p == main {
			return nil
		}
		name := filepath.ToSlash(rel)
		if strings.HasSuffix(name, ".db") { // Statistik der Module (Abfrage-Log, Zugriffs-Log)
			if !withStats {
				return nil
			}
			cp := filepath.Join(tmp, strings.ReplaceAll(name, "/", "_"))
			if err := vacuumInto(ctx, p, cp); err != nil {
				s.log.Warn("backup: statistics skipped", "file", name, "err", err)
				return nil
			}
			p = cp
		}
		files = append(files, backup.File{Name: name, Path: p})
		return nil
	})
	return files, err
}

func vacuumInto(ctx context.Context, src, dst string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(src)+"?mode=ro&_pragma=busy_timeout(5000)&_pragma=temp_store(MEMORY)")
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.ExecContext(ctx, `VACUUM INTO ?`, dst)
	return err
}

// writeArchive schreibt das verschluesselte Archiv nach w.
func (s *Server) writeArchive(ctx context.Context, w io.Writer, password string, withStats bool) error {
	tmp, err := os.MkdirTemp(s.Cfg.DataDir, ".backup-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	files, err := s.backupFiles(ctx, tmp, withStats)
	if err != nil {
		return err
	}
	enc, err := backup.NewWriter(w, password)
	if err != nil {
		return err
	}
	if err := backup.Pack(enc, files); err != nil {
		return err
	}
	return enc.Close()
}

func archiveName() string { return "node64-" + time.Now().Format("20060102-1504") + ".n64backup" }

// backupArchiveDownload: POST /settings/backup (Passwort, Statistik ja/nein).
func (s *Server) backupArchiveDownload(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	pw := r.PostFormValue("password")
	if len(pw) < 8 {
		s.flash(w, r, "danger", v.T("backup.password_short"))
		http.Redirect(w, r, "/settings/data#backup", http.StatusSeeOther)
		return
	}
	stats := r.PostFormValue("stats") == "on"
	s.serveArchive(w, r, pw, stats)
}

func (s *Server) serveArchive(w http.ResponseWriter, r *http.Request, pw string, stats bool) {
	longTransfer(w)
	s.audit(r, "backup.download", "archive", fmt.Sprintf("stats=%t", stats))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+archiveName()+`"`)
	w.Header().Set("Cache-Control", "no-store")
	if err := s.writeArchive(r.Context(), w, pw, stats); err != nil {
		// Kopf ist schon gesendet: abbrechen, damit keine unvollstaendige Datei als gueltig gilt
		s.log.Error("backup archive", "err", err)
		panic(http.ErrAbortHandler)
	}
}

// apiBackupArchive: POST /api/backup {"password": "...", "stats": true}.
func (s *Server) apiBackupArchive(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Stats    bool   `json:"stats"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if len(in.Password) < 8 {
		writeErr(w, http.StatusUnprocessableEntity, errPasswordShort.Error())
		return
	}
	s.serveArchive(w, r, in.Password, in.Stats)
}

// restoreArchive entpackt ein Archiv nach restore.new (vorher geprueft); errPasswordNeeded/errPasswordWrong/
// errRestoreInvalid.
func (s *Server) restoreArchive(ctx context.Context, src io.Reader, password string) (int64, error) {
	if password == "" {
		return 0, errPasswordNeeded
	}
	dec, err := backup.NewReader(src, password)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errRestoreInvalid, err)
	}
	stage, err := os.MkdirTemp(s.Cfg.DataDir, "restore.tmp-")
	if err != nil {
		return 0, err
	}
	names, err := backup.Unpack(dec, stage, maxArchiveBytes)
	if err != nil {
		os.RemoveAll(stage)
		if errors.Is(err, backup.ErrPassword) {
			return 0, errPasswordWrong
		}
		return 0, fmt.Errorf("%w: %v", errRestoreInvalid, err)
	}
	_ = os.RemoveAll(filepath.Join(stage, "bin")) // aeltere Archive enthielten noch das Selbst-Update (backupSkip)
	if err := validateSQLite(ctx, filepath.Join(stage, "node64.db")); err != nil {
		os.RemoveAll(stage)
		return 0, fmt.Errorf("%w: %v", errRestoreInvalid, err)
	}
	dest := filepath.Join(s.Cfg.DataDir, RestoreDirName)
	_ = os.RemoveAll(dest)
	_ = os.Remove(filepath.Join(s.Cfg.DataDir, RestoreFileName)) // nur eine Wiederherstellung gleichzeitig
	if err := os.Rename(stage, dest); err != nil {
		os.RemoveAll(stage)
		return 0, err
	}
	return int64(len(names)), nil
}

// restoreAny erkennt Archiv oder reine Datenbank am Kopf der Datei.
func (s *Server) restoreAny(ctx context.Context, src io.Reader, password string) (int64, error) {
	br := bufio.NewReader(src)
	head, _ := br.Peek(len(backup.Magic))
	if backup.IsArchive(head) {
		return s.restoreArchive(ctx, br, password)
	}
	n, err := s.restoreFrom(ctx, br)
	if err == nil {
		_ = os.RemoveAll(filepath.Join(s.Cfg.DataDir, RestoreDirName))
	}
	return n, err
}
