package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ipv64net/node64/internal/certs"
	"github.com/ipv64net/node64/internal/healthchecks"
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
	transferTimeout = 2 * time.Hour // Zeitlimit fuer Backup-Download und Wiederherstellung (longTransfer)
)

func (s *Server) backupRoutes() {
	s.mux.Handle("GET /settings/backup", s.auth(s.backupDownload))
	s.mux.Handle("POST /settings/backup", s.auth(s.backupArchiveDownload))
	s.mux.Handle("POST /settings/restore", s.auth(s.restoreUpload))
	s.mux.Handle("POST /settings/export", s.auth(s.exportConfig))
	s.mux.Handle("POST /settings/import", s.auth(s.importConfig))
	s.mux.Handle("POST /settings/reset", s.auth(s.resetNode))
}

// bodyLimitFor erlaubt fuer Uploads groessere Bodys.
func bodyLimitFor(path string) int64 {
	switch path {
	case "/settings/restore", "/api/backup/restore":
		return maxUpload
	case "/settings/import", "/api/import":
		return maxImport
	}
	return maxBody
}

// backupDownload liefert eine konsistente Kopie der Datenbank.
func (s *Server) backupDownload(w http.ResponseWriter, r *http.Request) {
	longTransfer(w)
	tmp, err := os.CreateTemp(s.Cfg.DataDir, ".backup-*.db") // im Container gibt es kein /tmp
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

// restoreUpload nimmt eine Datenbank zur Wiederherstellung an (Neustart danach).
func (s *Server) restoreUpload(w http.ResponseWriter, r *http.Request) {
	longTransfer(w)
	v := s.view(r, "settings.title")
	f, _, err := r.FormFile("file")
	if err != nil {
		s.flash(w, r, "danger", v.T("backup.no_file"))
		http.Redirect(w, r, "/settings/data#restore", http.StatusSeeOther)
		return
	}
	defer f.Close()
	n, err := s.restoreAny(r.Context(), f, r.PostFormValue("password"))
	switch {
	case errors.Is(err, errPasswordNeeded), errors.Is(err, errPasswordWrong):
		key := "backup.password_needed"
		if errors.Is(err, errPasswordWrong) {
			key = "backup.password_wrong"
		}
		s.flash(w, r, "danger", v.T(key))
		http.Redirect(w, r, "/settings/data#restore", http.StatusSeeOther)
		return
	case errors.Is(err, errRestoreInvalid):
		msg := v.T("backup.invalid")
		if detail := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(err.Error(), errRestoreInvalid.Error()), ":")); detail != "" {
			msg += " (" + detail + ")"
		}
		s.flash(w, r, "danger", msg)
		http.Redirect(w, r, "/settings/data#restore", http.StatusSeeOther)
		return
	case err != nil:
		s.fail(w, r, err)
		return
	}
	s.audit(r, "backup.restore", "", fmt.Sprintf("%d bytes", n))
	s.flash(w, r, "warning", v.T("backup.restarting"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	s.restartSoon("restarting for database restore")
}

var (
	errRestoreInvalid = errors.New("not a valid node64 database")
	errPasswordShort  = errors.New("password must have at least 8 characters")
	errConfigInvalid  = errors.New("not a node64 config file")
	errPasswordNeeded = errors.New("the file contains encrypted secrets: password required")
	errPasswordWrong  = errors.New("wrong password for the encrypted secrets")
)

// restoreFrom legt eine Datenbank fuer die Wiederherstellung beim naechsten Start ab (Oberflaeche und API);
// sie wird vorher geprueft. Fehler errRestoreInvalid (mit Grund) oder ein Dateifehler.
func (s *Server) restoreFrom(ctx context.Context, src io.Reader) (int64, error) {
	dest := filepath.Join(s.Cfg.DataDir, RestoreFileName)
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(out, io.LimitReader(src, maxUpload))
	out.Close()
	if err != nil || n < 1024 {
		os.Remove(dest)
		return n, errRestoreInvalid
	}
	if err := validateSQLite(ctx, dest); err != nil {
		os.Remove(dest)
		s.log.Warn("restore rejected", "err", err)
		return n, fmt.Errorf("%w: %v", errRestoreInvalid, err)
	}
	return n, nil
}

// restartSoon startet den Node kurz nach der Antwort neu (Docker startet ihn wieder).
func (s *Server) restartSoon(reason string) {
	if s.Restart != nil {
		go func() {
			time.Sleep(1500 * time.Millisecond)
			s.log.Warn(reason)
			s.Restart()
		}()
	}
}

// resetNode setzt den Node auf den Auslieferungszustand zurueck: nach Passwort-Pruefung wird eine
// bestehende Verknuepfung sauber getrennt, ein Merker abgelegt und neu gestartet; beim Start
// leert cmd/node64 dann das Datenverzeichnis (Datenbank, Schluessel, Zertifikat, Backups).
func (s *Server) resetNode(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	if !VerifyPassword(v.User.PasswordHash, r.PostFormValue("password")) {
		s.audit(r, "node.reset_denied", "", "wrong password")
		s.flash(w, r, "danger", v.T("settings.password_wrong"))
		http.Redirect(w, r, "/settings/data#reset", http.StatusSeeOther)
		return
	}
	problems, err := s.requestReset(r.Context(), r.PostFormValue("keep_checks") == "on")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "node.reset", "", strings.Join(problems, "; "))
	s.log.Warn("factory reset requested", "user", v.User.Username)
	s.flash(w, r, "warning", v.T("reset.restarting"))
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	s.restartSoon("restarting for factory reset")
}

// requestReset meldet die Node vorher online ab (Module mit module.Resetter, auch ausgeschaltete, z. B. CDN64 online; lokale Gruppe;
// Verknuepfung mit ipv64) und legt den Merker fuer den Werksreset beim naechsten Start ab (Oberflaeche und API; das
// Passwort prueft der Aufrufer). problems = was online nicht aufgeraeumt werden konnte; der Reset laeuft trotzdem.
func (s *Server) requestReset(ctx context.Context, keepChecks bool) (problems []string, err error) {
	rctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	for _, m := range s.Modules.Modules() {
		rs, ok := m.(module.Resetter)
		if !ok {
			continue
		}
		if err := rs.BeforeReset(rctx); err != nil {
			s.log.Warn("reset: module cleanup failed, resetting anyway", "module", m.Info().Name, "err", err)
			problems = append(problems, m.Info().Name+": "+err.Error())
		}
	}
	if s.Peer != nil {
		if err := s.Peer.Leave(rctx); err != nil {
			s.log.Warn("reset: leaving the local group failed, resetting anyway", "err", err)
			problems = append(problems, "peer: "+err.Error())
		}
	}
	if s.Linker != nil && s.Store.SettingOr(ctx, nodesync.SetToken, "") != "" {
		if err := s.Linker.Unlink(rctx, keepChecks); err != nil {
			s.log.Warn("reset: unlink failed, resetting anyway", "err", err)
			problems = append(problems, "sync: "+err.Error())
		}
	}
	return problems, os.WriteFile(filepath.Join(s.Cfg.DataDir, ResetFileName), []byte(time.Now().UTC().Format(time.RFC3339)), 0o600)
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
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&_pragma=busy_timeout(2000)&_pragma=temp_store(MEMORY)")
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
	Certs      string                     `json:"certs,omitempty"` // Zertifikatsverwaltung, nur mit Passwort (verschluesselt)
	Modules    map[string]json.RawMessage `json:"modules"`
}

type configSecrets struct {
	Mode string `json:"mode"` // none, password
	Salt string `json:"salt,omitempty"`
}

type configChannel struct {
	ID         int64             `json:"id,omitempty"` // fuer die Zuordnung der Kanaele von Checks beim Import
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
	notify.SetQuietTo, notify.SetQuietDays, notify.SetQuietTZ, notify.SetRatePerHour, notify.SetBatchThreshold, notify.SetBatchWindow,
	// Datenhaltung (ungueltige Werte gelten beim Lesen als Standard) und der Schalter der MCP-Schnittstelle (ihre
	// Schluessel gehoeren zum Benutzer dieser Node und fehlen im Export immer)
	healthchecks.SettingRawDays, healthchecks.SettingHourlyDays, healthchecks.SettingChartDetail, SettingAuditDays, setMCPEnabled}

func deriveBox(password string, salt []byte) (*secrets.Box, error) {
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return secrets.New(key)
}

// exportConfig liefert die Konfiguration als Datei (Geheimnisse weggelassen oder mit Passwort verschluesselt).
func (s *Server) exportConfig(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	cf, err := s.buildExport(r.Context(), r.PostFormValue("secrets"), r.PostFormValue("password"))
	if errors.Is(err, errPasswordShort) {
		s.flash(w, r, "danger", v.T("backup.password_short"))
		http.Redirect(w, r, "/settings/data#export", http.StatusSeeOther)
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.audit(r, "config.export", "", "secrets="+cf.Secrets.Mode)
	out, _ := json.MarshalIndent(cf, "", "  ")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="node64-config-`+time.Now().Format("20060102-1504")+`.json"`)
	_, _ = w.Write(out)
}

// buildExport stellt die Konfiguration zusammen (Oberflaeche und API). mode "password" verschluesselt die
// Geheimnisse der Kanaele mit password (mind. 8 Zeichen), sonst fehlen sie.
func (s *Server) buildExport(ctx context.Context, mode, password string) (*configFile, error) {
	if mode == "password" && len(password) < 8 {
		return nil, errPasswordShort
	}
	cf := &configFile{Format: "node64-config", Version: 1, ExportedAt: time.Now().UTC(), Node: map[string]string{"version": s.Version},
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
			return nil, err
		}
		box = b
		cf.Secrets = &configSecrets{Mode: "password", Salt: base64.StdEncoding.EncodeToString(salt)}
	} else {
		cf.Secrets = &configSecrets{Mode: "none"}
	}
	// Zertifikate mit Schluesseln nur verschluesselt (ohne Passwort fehlen sie im Export)
	if box != nil && s.Certs != nil {
		b, err := s.Certs.ExportAll(ctx)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		cf.Certs = box.Encrypt(string(raw))
	}
	if s.Notify != nil {
		chans, err := s.Notify.Channels(ctx)
		if err != nil {
			return nil, err
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
			cf.Channels = append(cf.Channels, configChannel{ID: ch.ID, Name: ch.Name, Type: string(ch.Type), Enabled: ch.Enabled, Default: ch.Default, Lang: ch.Lang, NotifyDown: ch.NotifyDown, NotifyUp: ch.NotifyUp, Config: cfg})
		}
	}
	if box != nil { // mit Passwort: Module duerfen Geheimnisse verschluesselt mitgeben (z. B. Proxmox-Token)
		ctx = module.WithSecretSealer(ctx, box)
	}
	for _, m := range s.Modules.Modules() {
		ex, ok := m.(module.Exporter)
		if !ok || !s.Modules.IsRunning(m.Info().Name) {
			continue // nur laufende Module: ein nie eingeschaltetes hat noch keine Tabellen (Export brach sonst ab)
		}
		data, err := ex.Export(ctx)
		if err != nil {
			return nil, err
		}
		raw, _ := json.Marshal(data)
		cf.Modules[m.Info().Name] = raw
	}
	return cf, nil
}

// importConfig uebernimmt eine exportierte Konfiguration aus einer Datei.
func (s *Server) importConfig(w http.ResponseWriter, r *http.Request) {
	v := s.view(r, "settings.title")
	f, _, err := r.FormFile("file")
	if err != nil {
		s.flash(w, r, "danger", v.T("backup.no_file"))
		http.Redirect(w, r, "/settings/data#import", http.StatusSeeOther)
		return
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxImport))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	count, problems, err := s.applyImport(r.Context(), raw, r.PostFormValue("password"))
	switch {
	case errors.Is(err, errConfigInvalid):
		s.flash(w, r, "danger", v.T("backup.invalid_config"))
	case errors.Is(err, errPasswordNeeded):
		s.flash(w, r, "danger", v.T("backup.password_needed"))
	case errors.Is(err, errPasswordWrong):
		s.flash(w, r, "danger", v.T("backup.password_wrong"))
	case err != nil:
		s.fail(w, r, err)
		return
	default:
		s.audit(r, "config.import", "", fmt.Sprintf("%d items", count))
		if len(problems) > 0 {
			s.flash(w, r, "warning", v.T("backup.imported", "count", count)+" "+strings.Join(problems, "; "))
		} else {
			s.flash(w, r, "success", v.T("backup.imported", "count", count))
		}
	}
	http.Redirect(w, r, "/settings/data#import", http.StatusSeeOther)
}

// applyImport uebernimmt eine exportierte Konfiguration (Oberflaeche und API): Einstellungen, Kanaele (gleicher
// Name = aktualisieren) und Module (werden dafuer eingeschaltet). count = uebernommene Eintraege, problems =
// Hinweise je Modul. Fehler: errConfigInvalid, errPasswordNeeded, errPasswordWrong.
func (s *Server) applyImport(ctx context.Context, raw []byte, password string) (count int, problems []string, err error) {
	var cf configFile
	if err := json.Unmarshal(raw, &cf); err != nil || cf.Format != "node64-config" {
		return 0, nil, errConfigInvalid
	}
	var box *secrets.Box
	if cf.Secrets != nil && cf.Secrets.Mode == "password" {
		salt, err := base64.StdEncoding.DecodeString(cf.Secrets.Salt)
		if err != nil || password == "" {
			return 0, nil, errPasswordNeeded
		}
		if box, err = deriveBox(password, salt); err != nil {
			return 0, nil, err
		}
	}
	// Geheimnisse zuerst entschluesseln: bei falschem Passwort wird nichts uebernommen
	plain := make([]map[string]string, len(cf.Channels))
	for i, in := range cf.Channels {
		plain[i] = map[string]string{}
		for k, val := range in.Config {
			if secrets.IsEncrypted(val) {
				if box == nil {
					continue
				}
				p, err := box.Decrypt(val)
				if err != nil {
					return 0, nil, errPasswordWrong
				}
				val = p
			}
			plain[i][k] = val
		}
	}
	plainCerts := ""
	if cf.Certs != "" && box != nil {
		p, err := box.Decrypt(cf.Certs)
		if err != nil {
			return 0, nil, errPasswordWrong
		}
		plainCerts = p
	}
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
	chMap := map[int64]int64{}
	if s.Notify != nil {
		existing, _ := s.Notify.Channels(ctx)
		byName := map[string]*notify.Channel{}
		for _, ch := range existing {
			byName[ch.Name] = ch
		}
		for i, in := range cf.Channels {
			ch, ok := byName[in.Name]
			if !ok {
				ch = &notify.Channel{Config: map[string]string{}}
			}
			ch.Name, ch.Type, ch.Enabled, ch.Default, ch.Lang, ch.NotifyDown, ch.NotifyUp = in.Name, notify.Type(in.Type), in.Enabled, in.Default, in.Lang, in.NotifyDown, in.NotifyUp
			for k, val := range plain[i] {
				ch.Config[k] = val
			}
			if err := ch.Validate(); err != nil {
				s.log.Warn("import: channel skipped", "name", in.Name, "err", err)
				problems = append(problems, in.Name+": "+err.Error())
				continue
			}
			var err error
			if ok {
				err = s.Notify.Update(ctx, ch)
			} else {
				err = s.Notify.Insert(ctx, ch)
			}
			if err == nil {
				count++
				if in.ID > 0 {
					chMap[in.ID] = ch.ID
				}
			}
		}
	}
	if len(chMap) > 0 {
		ctx = module.WithChannelMap(ctx, chMap)
	}
	if cf.Certs != "" {
		switch {
		case box == nil:
			problems = append(problems, "certificates: "+errPasswordNeeded.Error())
		case s.Certs == nil:
			problems = append(problems, "certificates: not available on this node")
		default:
			var cb certs.Backup
			if err := json.Unmarshal([]byte(plainCerts), &cb); err != nil {
				problems = append(problems, "certificates: "+err.Error())
				break
			}
			res, err := s.Certs.ImportAll(ctx, &cb)
			if res != nil {
				for _, n := range res.Added {
					count += n
				}
				ctx = module.WithCertMap(ctx, res.CertIDs)
			}
			if err != nil {
				problems = append(problems, "certificates: "+err.Error())
			}
		}
	}
	if box != nil {
		ctx = module.WithSecretSealer(ctx, box)
	}
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
	return count, problems, nil
}
