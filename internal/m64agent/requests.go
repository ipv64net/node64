package m64agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ipv64net/node64/internal/m64proto"
)

const (
	maxSections   = 32
	maxSectionLen = 16
)

// handleSession wartet auf genau eine exec-Anfrage mit einem der vier Befehle. Alles andere (shell, pty-req,
// subsystem, env, x11-req, auth-agent-req ...) wird abgelehnt. allowed prueft den Schluessel erneut gegen die
// aktuelle Liste (er kann seit der Anmeldung entfernt worden sein).
func (s *Server) handleSession(ctx context.Context, ch ssh.Channel, reqs <-chan *ssh.Request, remote, fp string,
	allowed func() bool) {
	defer ch.Close()
	timer := time.NewTimer(s.cfg.HandshakeTimeout)
	defer timer.Stop()
	for {
		select {
		case req, ok := <-reqs:
			if !ok {
				return
			}
			if req.Type != "exec" {
				s.log.Debug("monitor64-agent: request refused", "remote", remote, "type", req.Type)
				_ = req.Reply(false, nil)
				continue
			}
			var p struct{ Cmd string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil || len(p.Cmd) > maxExecCommandBytes {
				_ = req.Reply(false, nil)
				continue
			}
			if !allowed() {
				_ = req.Reply(false, nil)
				return
			}
			cmd, sections, err := parseCommand(p.Cmd)
			if err != nil {
				s.log.Warn("monitor64-agent: command refused", "remote", remote, "key", fp, "cmd", sanitizeLog(p.Cmd))
				_ = req.Reply(false, nil)
				continue
			}
			_ = req.Reply(true, nil)
			go ssh.DiscardRequests(reqs) // weitere Anfragen (signal, window-change ...) ablehnen
			s.run(ctx, ch, cmd, sections, remote, fp)
			return
		case <-timer.C:
			return
		case <-ctx.Done():
			return
		}
	}
}

// parseCommand prueft den exec-Befehl: genau "info", "info latest=<version>", "update", "keys", "collect" oder
// "collect a,b,c". Bei "info latest=" steht die Version im zweiten Rueckgabewert.
func parseCommand(cmd string) (string, []string, error) {
	switch cmd {
	case m64proto.ReqInfo, m64proto.ReqUpdate, m64proto.ReqKeys, m64proto.ReqCollect:
		return cmd, nil, nil
	}
	if v, ok := strings.CutPrefix(cmd, m64proto.ReqInfo+" latest="); ok {
		if !validLatest(v) {
			return "", nil, errors.New("invalid version")
		}
		return m64proto.ReqInfo, []string{v}, nil
	}
	arg, ok := strings.CutPrefix(cmd, m64proto.ReqCollect+" ")
	if !ok || arg == "" {
		return "", nil, errors.New("unknown command")
	}
	var secs []string
	for _, sec := range strings.Split(arg, ",") {
		if sec == "" || len(sec) > maxSectionLen {
			return "", nil, errors.New("invalid section")
		}
		for _, r := range sec {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
				return "", nil, errors.New("invalid section")
			}
		}
		if !slices.Contains(secs, sec) {
			secs = append(secs, sec)
		}
		if len(secs) > maxSections {
			return "", nil, errors.New("too many sections")
		}
	}
	return m64proto.ReqCollect, secs, nil
}

// sanitizeLog kuerzt fremde Texte fuer das Log.
func sanitizeLog(s string) string {
	return cleanText(s, 80)
}

func (s *Server) run(ctx context.Context, ch ssh.Channel, cmd string, secs []string, remote, fp string) {
	switch cmd {
	case m64proto.ReqInfo:
		if len(secs) == 1 { // die Node nennt die verfuegbare Version (Anzeige am Host)
			s.SetLatest(secs[0], time.Now())
		}
		s.noteRequest()
		s.doInfo(ctx, ch)
	case m64proto.ReqCollect:
		s.noteRequest()
		s.doCollect(ctx, ch, secs)
	case m64proto.ReqKeys:
		s.doKeys(ctx, ch, remote, fp)
	case m64proto.ReqUpdate:
		s.doUpdate(ctx, ch, remote, fp)
	}
}

// writeJSON schreibt v als JSON, wenn es in limit passt, und beendet den Kanal mit code.
func writeJSON(ch ssh.Channel, v any, limit int, code uint32) {
	b, err := json.Marshal(v)
	if err != nil {
		fail(ch, "encode: "+err.Error())
		return
	}
	if len(b) > limit {
		fail(ch, fmt.Sprintf("answer too large (%d bytes, limit %d)", len(b), limit))
		return
	}
	b = append(b, '\n')
	if _, err := ch.Write(b); err != nil {
		_ = ch.Close()
		return
	}
	exitStatus(ch, code)
}

// Info liefert die Antwort auf "info".
func (s *Server) Info() *m64proto.Info {
	info := &m64proto.Info{
		V:       m64proto.Version,
		Agent:   Name,
		Version: s.cfg.Version,
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
	info.Hostname, _ = os.Hostname()
	info.Platform, info.Kernel, info.BootTime = hostInfo()
	if cp, ok := s.cfg.Collector.(CapsProvider); ok {
		info.Caps = append(info.Caps, cp.Caps()...)
	}
	if s.local != nil && !slices.Contains(info.Caps, m64proto.SecLocal) {
		info.Caps = append(info.Caps, m64proto.SecLocal)
	}
	return info
}

func (s *Server) doInfo(ctx context.Context, ch ssh.Channel) {
	writeJSON(ch, s.Info(), m64proto.MaxInfoBytes, 0)
}

// Collect erstellt einen Report (Werte des Collectors und eigene Skripte) innerhalb von CollectTimeout. Eigene
// Skripte laufen im Hintergrund an; was bis kurz vor Ablauf nicht fertig ist, liefert der Agent aus der letzten
// Runde nach (wie CheckMK "cached").
func (s *Server) Collect(ctx context.Context, secs []string) (*m64proto.Report, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, s.cfg.CollectTimeout)
	defer cancel()
	select {
	case s.collectMu <- struct{}{}:
	case <-ctx.Done():
		return nil, errors.New("busy: another collect is still running")
	}
	defer func() { <-s.collectMu }()

	wantLocal := len(secs) == 0 || slices.Contains(secs, m64proto.SecLocal)
	other := slices.DeleteFunc(slices.Clone(secs), func(x string) bool { return x == m64proto.SecLocal })
	var round *localRound
	if wantLocal && s.local != nil {
		round = s.local.begin() // Skripte starten, waehrend der Collector liest
	}
	var rep *m64proto.Report
	if s.cfg.Collector != nil && (len(secs) == 0 || len(other) > 0) {
		rep = s.cfg.Collector.Collect(ctx, other)
	}
	if rep == nil {
		rep = &m64proto.Report{}
		if s.cfg.Collector == nil && (len(secs) == 0 || len(other) > 0) {
			rep.Errors = append(rep.Errors, m64proto.SectionErr{Section: "*", Error: "no collector for " + runtime.GOOS})
		}
	}
	rep.V = m64proto.Version
	if rep.Time == 0 {
		rep.Time = time.Now().UnixMilli()
	}
	if round != nil {
		// Auf frisch gestartete Skripte hoechstens bis kurz vor Ablauf warten (Rest fuer JSON und Uebertragung).
		wctx, wcancel := context.WithDeadline(ctx, start.Add(s.cfg.CollectTimeout*3/4))
		rep.Local = nil
		s.local.finish(wctx, round, rep)
		wcancel()
	}
	return rep, nil
}

func (s *Server) doCollect(ctx context.Context, ch ssh.Channel, secs []string) {
	stop := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer stop()
	rep, err := s.Collect(ctx, secs)
	if err != nil {
		fail(ch, err.Error())
		return
	}
	writeJSON(ch, rep, m64proto.MaxReportBytes, 0)
}

// readStdin liest hoechstens limit Byte; mehr ist ein Fehler.
func readStdin(ch ssh.Channel, limit int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(ch, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("input larger than %d bytes", limit)
	}
	return b, nil
}

func (s *Server) doKeys(ctx context.Context, ch ssh.Channel, remote, fp string) {
	ctx, cancel := context.WithTimeout(ctx, keysTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer stop()
	res := m64proto.KeysResult{}
	data, err := readStdin(ch, m64proto.MaxKeysBytes)
	if err == nil {
		res.Count, err = ParseKeys(data)
		if err == nil && res.Count == 0 {
			err = errors.New("empty key list refused")
		}
	}
	if err == nil {
		err = WriteKeysFile(s.cfg.KeysFile, data)
		s.keys.invalidate()
		// Verbindungen mit entfernten Schluesseln schliessen - kurz nach der Antwort, damit sie die anfragende
		// Node (Schluesselwechsel) noch erreicht.
		time.AfterFunc(time.Second, s.revoke)
	}
	if err != nil {
		res.Count = 0
		res.Error = err.Error()
		s.log.Warn("monitor64-agent: keys refused", "remote", remote, "key", fp, "err", err)
		writeJSON(ch, res, m64proto.MaxKeysBytes, 1)
		return
	}
	res.OK = true
	s.log.Info("monitor64-agent: keys replaced", "remote", remote, "key", fp, "count", res.Count)
	writeJSON(ch, res, m64proto.MaxKeysBytes, 0)
}

// WriteKeysFile ersetzt die Schluesseldatei atomar (0600).
func WriteKeysFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func (s *Server) doUpdate(ctx context.Context, ch ssh.Channel, remote, fp string) {
	ctx, cancel := context.WithTimeout(ctx, updateTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = ch.Close() })
	defer stop()
	res := m64proto.UpdateResult{}
	refuse := func(err error) {
		res.Error = err.Error()
		s.log.Warn("monitor64-agent: update refused", "remote", remote, "key", fp, "err", err)
		writeJSON(ch, res, m64proto.MaxInfoBytes, 1)
	}
	if !s.updateMu.TryLock() {
		refuse(errors.New("another update is running"))
		return
	}
	defer s.updateMu.Unlock()
	br := bufio.NewReaderSize(ch, 4096)
	h, err := readUpdateHeader(br)
	if err != nil {
		refuse(err)
		return
	}
	if err := checkUpdateHeader(h, s.cfg.Version, s.cfg.ReleaseKeys); err != nil {
		refuse(err)
		return
	}
	exe := s.cfg.ExePath
	if exe == "" {
		if exe, err = os.Executable(); err == nil {
			exe, err = filepath.EvalSymlinks(exe)
		}
		if err != nil {
			refuse(fmt.Errorf("own file not found: %w", err))
			return
		}
	}
	if err := applyUpdate(br, h, exe); err != nil {
		refuse(err)
		return
	}
	// Neue Datei probeweise starten; startet sie nicht, gleich die alte zurueck (Version wird kuenftig abgelehnt).
	if s.cfg.Probe != nil {
		if err := s.cfg.Probe(exe, h.Version); err != nil {
			if rerr := RollbackUpdate(exe, h.Version); rerr != nil {
				err = fmt.Errorf("%w (restore old file: %v)", err, rerr)
			}
			refuse(fmt.Errorf("new version does not start: %w", err))
			return
		}
	}
	if err := WriteUpdateMarker(exe, s.cfg.Version, h.Version); err != nil {
		s.log.Warn("monitor64-agent: update marker not written - no automatic fallback", "err", err)
	}
	res.OK = true
	res.Version = h.Version
	s.log.Info("monitor64-agent: updated - restarting", "remote", remote, "key", fp, "from", s.cfg.Version, "to", h.Version)
	writeJSON(ch, res, m64proto.MaxInfoBytes, 0)
	if s.cfg.OnUpdated != nil {
		go s.cfg.OnUpdated(h.Version)
	}
}
