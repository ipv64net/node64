package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ipv64net/node64/internal/module"
	"github.com/ipv64net/node64/internal/notify"
	"github.com/ipv64net/node64/internal/secrets"
	nodesync "github.com/ipv64net/node64/internal/sync"
)

// Backup der Datenbank, Wiederherstellung, Export und Import der Konfiguration.

const (
	RestoreFileName = "node64.db.restore"
	ResetFileName   = "node64.reset" // Merker: beim naechsten Start das Datenverzeichnis leeren
	maxUpload       = 1 << 30        // 1 GB fuer Datenbank-Wiederherstellung
	maxImport       = 16 << 20
)

func (s *Server) backupRoutes() {
	s.mux.Handle("GET /settings/backup", s.auth(s.backupDownload))
	s.mux.Handle("POST /settings/restore", s.auth(s.restoreUpload))
	s.mux.Handle("POST /settings/export", s.auth(s.exportConfig))
	s.mux.Handle("POST /settings/import", s.auth(s.importConfig))
	s.mux.Handle("POST /settings/reset", s.auth(s.resetNode))
}

// bodyLimitFor erlaubt fuer Uploads groessere Bodys.
func bodyLimitFor(path string) int64 {
	switch path {
	case "/settings/restore":
		return maxUpload
	case "/settings/import":
		return maxImport
	}
	return maxBody
}

// backupDownload liefert eine konsistente Kopie der Datenbank.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	tmp, err := os.CreateTemp("", "agent-backup-*.db")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tmp.Close()
	defer os.Remove(tmp.Name())
	if err := s.Store.Backup(r.Context(), tmp.Name()); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "backup.download", "", "")
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="node64-`+time.Now().Format("20060102-1504")+`.db"`)
	http.ServeFile(w, r, tmp.Name())
}

// restoreUpload prueft die Datei, legt sie als node64.db.restore ab und startet
// den Node neu; beim Start wird sie eingesetzt (siehe cmd/node64).
func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	f, _, err := r.FormFile("file")
	if err != nil {
		s.flash(w, r, "danger", v.T("backup.no_file"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	defer f.Close()
	dest := filepath.Join(s.Cfg.DataDir, RestoreFileName)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	n, err := io.Copy(out, io.LimitReader(f, maxUpload))
	out.Close()
	if err != nil || n < 1024 {
		os.Remove(dest)
		s.flash(w, r, "danger", v.T("backup.invalid"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := validateSQLite(r.Context(), dest); err != nil {
		os.Remove(dest)
		s.log.Warn("restore rejected", "err", err)
		s.flash(w, r, "danger", v.T("backup.invalid")+" ("+err.Error()+")")
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	s.audit(r, "backup.restore", "", fmt.Sprintf("%d bytes", n))
	s.flash(w, r, "warning", v.T("backup.restarting"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	if s.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			s.log.Warn("restarting for database restore")
			s.Restart()
		}()
	}
}

// resetNode setzt den Node auf den Auslieferungszustand zurueck: nach Passwort-Pruefung wird eine
// bestehende Verknuepfung sauber getrennt, ein Merker abgelegt und neu gestartet; beim Start
// leert cmd/node64 dann das Datenverzeichnis (Datenbank, Schluessel, Zertifikat, Backups).
func (s *Server) resetNode(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "settings.title")
	if !VerifyPassword(v.User.PasswordHash, r.PostFormValue("password")) {
		s.audit(r, "node.reset_denied", "", "wrong password")
		s.flash(w, r, "danger", v.T("settings.password_wrong"))
		http.Redirect(w, r, "/settings#reset", http.StatusSeeOther)
		return
	}
	if s.Linker != nil && s.Store.SettingOr(ctx, nodesync.SetToken, "") != "" {
		keep := r.PostFormValue("keep_checks") == "on"
		if err := s.Linker.Unlink(ctx, keep); err != nil {
			s.log.Warn("reset: unlink failed, resetting anyway", "err", err)
		}
	}
	if err := os.WriteFile(filepath.Join(s.Cfg.DataDir, ResetFileName), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600); err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "node.reset", "", "")
	s.log.Warn("factory reset requested", "user", v.User.Username)
	s.flash(w, r, "warning", v.T("reset.restarting"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	if s.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			s.log.Warn("restarting for factory reset")
			s.Restart()
		}()
	}
}

// validateSQLite prueft Kopf und Kernschema einer hochgeladenen Datenbank.
func validateSQLite(ctx context.Context, path string) error {
	fh, err := os.Open(path)
	if err != nil {
		return err
	}
	head := make([]byte, 16)
	_, _ = io.ReadFull(fh, head)
	fh.Close()
	if !bytes.HasPrefix(head, []byte("SQLite format 3\x00")) {
		return fmt.Errorf("not a SQLite database")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=busy_timeout(2000)")
	if err != nil {
		return err
	}
	defer db.Close()
	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations WHERE scope = 'core'`).Scan(&n); err != nil || n == 0 {
		return fmt.Errorf("no node64 schema found")
	}
	var users int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&users); err != nil {
		return fmt.Errorf("users table missing")
	}
	return nil
}

// ---------------------------------------------------------------- Export / Import

type configFile struct {
	Format     string                     `json:"format"`
	Version    int                        `json:"version"`
	ExportedAt time.Time                  `json:"exported_at"`
	Node       map[string]string          `json:"node"`
	Secrets    *configSecrets             `json:"secrets,omitempty"`
	Settings   map[string]string          `json:"settings"`
	Channels   []configChannel            `json:"channels"`
	Modules    map[string]json.RawMessage `json:"modules"`
}

type configSecrets struct {
	Mode string `json:"mode"` // none, password
	Salt string `json:"salt,omitempty"`
}

type configChannel struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Enabled    bool              `json:"enabled"`
	Default    bool              `json:"default"`
	Lang       string            `json:"lang"`
	NotifyDown bool              `json:"notify_down"`
	NotifyUp   bool              `json:"notify_up"`
	Config     map[string]string `json:"config"`
}

var exportedSettings = []string{SettingNodeName, SettingNodeLocation, SettingNodeTimezone, notify.SetBaseURL, notify.SetQuietEnabled, notify.SetQuietFrom,
	notify.SetQuietTo, notify.SetQuietDays, notify.SetQuietTZ, notify.SetRatePerHour, notify.SetBatchThreshold, notify.SetBatchWindow}

func deriveBox(password string, salt []byte) (*secrets.Box, error) {
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return secrets.New(key)
}

func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "settings.title")
	mode := r.PostFormValue("secrets")
	password := r.PostFormValue("password")
	if mode == "password" && len(password) < 8 {
		s.flash(w, r, "danger", v.T("backup.password_short"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	cf := configFile{Format: "node64-config", Version: 1, ExportedAt: time.Now().UTC(), Node: map[string]string{"version": s.Version},
		Settings: map[string]string{}, Channels: []configChannel{}, Modules: map[string]json.RawMessage{}}
	for _, k := range exportedSettings {
		if val, ok, _ := s.Store.Setting(ctx, k); ok {
			cf.Settings[k] = val
		}
	}
	var box *secrets.Box
	if mode == "password" {
		salt := make([]byte, 16)
		_, _ = rand.Read(salt)
		b, err := deriveBox(password, salt)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		box = b
		cf.Secrets = &configSecrets{Mode: "password", Salt: base64.StdEncoding.EncodeToString(salt)}
	} else {
		cf.Secrets = &configSecrets{Mode: "none"}
	}
	if s.Notify != nil {
		chans, err := s.Notify.Channels(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, ch := range chans {
			cfg := map[string]string{}
			for k, val := range ch.Config {
				if notify.IsSecret(ch.Type, k) {
					if box == nil {
						continue
					}
					val = box.Encrypt(val)
				}
				cfg[k] = val
			}
			cf.Channels = append(cf.Channels, configChannel{Name: ch.Name, Type: string(ch.Type), Enabled: ch.Enabled, Default: ch.Default, Lang: ch.Lang, NotifyDown: ch.NotifyDown, NotifyUp: ch.NotifyUp, Config: cfg})
		}
	}
	for _, m := range s.Modules.Modules() {
		ex, ok := m.(module.Exporter)
		if !ok {
			continue
		}
		data, err := ex.Export(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		raw, _ := json.Marshal(data)
		cf.Modules[m.Info().Name] = raw
	}
	s.audit(r, "config.export", "", "secrets="+cf.Secrets.Mode)
	out, _ := json.MarshalIndent(cf, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="node64-config-`+time.Now().Format("20060102-1504")+`.json"`)
	_, _ = w.Write(out)
}

func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	v := s.view(r, "settings.title")
	f, _, err := r.FormFile("file")
	if err != nil {
		s.flash(w, r, "danger", v.T("backup.no_file"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxImport))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var cf configFile
	if err := json.Unmarshal(raw, &cf); err != nil || cf.Format != "node64-config" {
		s.flash(w, r, "danger", v.T("backup.invalid_config"))
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	var box *secrets.Box
	if cf.Secrets != nil && cf.Secrets.Mode == "password" {
		salt, err := base64.StdEncoding.DecodeString(cf.Secrets.Salt)
		pw := r.PostFormValue("password")
		if err != nil || pw == "" {
			s.flash(w, r, "danger", v.T("backup.password_needed"))
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		if box, err = deriveBox(pw, salt); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	count := 0
	for k, val := range cf.Settings {
		allowed := false
		for _, x := range exportedSettings {
			if x == k {
				allowed = true
			}
		}
		if allowed {
			if err := s.Store.SetSetting(ctx, k, val); err == nil {
				count++
			}
		}
	}
	if s.Notify != nil {
		existing, _ := s.Notify.Channels(ctx)
		byName := map[string]*notify.Channel{}
		for _, ch := range existing {
			byName[ch.Name] = ch
		}
		for _, in := range cf.Channels {
			ch, ok := byName[in.Name]
			if !ok {
				ch = &notify.Channel{Config: map[string]string{}}
			}
			ch.Name, ch.Type, ch.Enabled, ch.Default, ch.Lang, ch.NotifyDown, ch.NotifyUp = in.Name, notify.Type(in.Type), in.Enabled, in.Default, in.Lang, in.NotifyDown, in.NotifyUp
			for k, val := range in.Config {
				if secrets.IsEncrypted(val) {
					if box == nil {
						continue
					}
					plain, err := box.Decrypt(val)
					if err != nil {
						s.flash(w, r, "danger", v.T("backup.password_wrong"))
						http.Redirect(w, r, "/settings", http.StatusSeeOther)
						return
					}
					val = plain
				}
				ch.Config[k] = val
			}
			if err := ch.Validate(); err != nil {
				s.log.Warn("import: channel skipped", "name", in.Name, "err", err)
				continue
			}
			if ok {
				err = s.Notify.Update(ctx, ch)
			} else {
				err = s.Notify.Insert(ctx, ch)
			}
			if err == nil {
				count++
			}
		}
	}
	var problems []string
	for _, m := range s.Modules.Modules() {
		ex, ok := m.(module.Exporter)
		raw, present := cf.Modules[m.Info().Name]
		if !ok || !present {
			continue
		}
		if !s.Modules.IsRunning(m.Info().Name) {
			if err := s.Modules.Enable(ctx, m.Info().Name); err != nil {
				problems = append(problems, m.Info().Name+": "+err.Error())
				continue
			}
		}
		n, err := ex.Import(ctx, raw)
		count += n
		if err != nil {
			problems = append(problems, err.Error())
		}
	}
	s.audit(r, "config.import", "", fmt.Sprintf("%d items", count))
	if len(problems) > 0 {
		s.flash(w, r, "warning", v.T("backup.imported", "count", count)+" "+strings.Join(problems, "; "))
	} else {
		s.flash(w, r, "success", v.T("backup.imported", "count", count))
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}
