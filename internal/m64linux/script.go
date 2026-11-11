package m64linux

import (
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Script ist das feste Skript fuer die SSH-Abfrage ohne Agent ("sh -s -- [smart] [updates]", Skript auf stdin).
// Es liest nur und bekommt keine Werte von Hosts oder Benutzern; die einzigen Argumente sind die festen Woerter
// ScriptArgSmart und ScriptArgUpdates. Die Ausgabe wertet ParseScriptOutput aus.
//
// Jedes Programm laeuft mit Zeitlimit (smartctl 20 s je Platte, Paketverwalter 90 s, df/zpool/systemctl 10 s);
// was abbricht, meldet das Skript als Fehler-Abschnitt statt die ganze Ausgabe zu verlieren. Schnelle Werte und
// SMART/Updates koennen getrennt abgefragt werden (ohne Argumente laeuft nur der schnelle Teil).
//
//go:embed script.sh
var Script string

// Feste Argumente fuer Script.
const (
	ScriptArgSmart   = "smart"   // SMART lesen (root oder "sudo -n smartctl")
	ScriptArgUpdates = "updates" // Paket-Updates und needs-restarting pruefen (Node: hoechstens stuendlich)
)

// ScriptCommand ist der Befehl fuer die SSH-Sitzung; das Skript kommt auf stdin.
func ScriptCommand(smart, updates bool) string {
	cmd := "sh -s --"
	if smart {
		cmd += " " + ScriptArgSmart
	}
	if updates {
		cmd += " " + ScriptArgUpdates
	}
	return cmd
}

const (
	secPrefix   = "<<<m64:"
	secSuffix   = ">>>"
	maxSections = 50000
	maxLines    = 20000 // Zeilen je attr-Abschnitt
	maxFiles    = 20000 // Eintraege der Dateitabelle
	maxErrs     = 64    // Fehler- und Hinweis-Abschnitte
)

// errSections sind die Abschnitte, fuer die das Skript "err:NAME" meldet.
var errSections = map[string]bool{
	m64proto.SecFS: true, m64proto.SecZFS: true, m64proto.SecSystemd: true, m64proto.SecUpdates: true,
	m64proto.SecSmart: true, m64proto.SecReboot: true,
}

// mgrNameRE: Name des Paketverwalters in "updates:MGR".
var mgrNameRE = regexp.MustCompile(`^[a-z]{2,16}$`)

// knownSection sagt, ob name ein Abschnitt des Skripts ist. Nur dann gilt eine Zeile als Kopf; alles andere bleibt
// Inhalt (eine fremde Zeile wie ein FUSE-Geraetename "<<<m64:..." in df schneidet so keinen Abschnitt ab).
func knownSection(name string) bool {
	switch name {
	case "start", "end", "attr", "note", "df", "df_i", "zpool_list", "zpool_list_rc", "zpool_status",
		"systemd_failed", "systemd_state", "needs_restarting":
		return true
	}
	kind, rest, ok := strings.Cut(name, ":")
	if !ok || rest == "" {
		return false
	}
	switch kind {
	case "file":
		return validHostPath(rest) && !strings.ContainsAny(rest, " \t")
	case "smart":
		return DeviceRE.MatchString(rest)
	case "updates", "updates_sec":
		return mgrNameRE.MatchString(rest)
	case "err":
		sec, dev, hasDev := strings.Cut(rest, ":")
		if !errSections[sec] {
			return false
		}
		return !hasDev || (sec == m64proto.SecSmart && DeviceRE.MatchString(dev))
	}
	return false
}

type scriptSection struct {
	name string
	body []byte
}

// splitSections zerlegt die Ausgabe in Abschnitte (Reihenfolge bleibt, Namen duerfen mehrfach vorkommen). Ein Kopf
// ist eine ganze Zeile "<<<m64:NAME>>>" mit bekanntem NAME (knownSection).
func splitSections(out []byte) []scriptSection {
	var secs []scriptSection
	s := string(out)
	cur := -1
	start := 0
	pos := 0
	for pos <= len(s) {
		end := strings.IndexByte(s[pos:], '\n')
		var ln string
		next := 0
		if end < 0 {
			ln, next = s[pos:], len(s)+1
		} else {
			ln, next = s[pos:pos+end], pos+end+1
		}
		ln = strings.TrimSuffix(ln, "\r")
		if len(ln) <= 600 && len(ln) > len(secPrefix)+len(secSuffix) && strings.HasPrefix(ln, secPrefix) &&
			strings.HasSuffix(ln, secSuffix) && knownSection(ln[len(secPrefix):len(ln)-len(secSuffix)]) {
			if cur >= 0 {
				secs[cur].body = sectionBody(s, start, pos)
			}
			if len(secs) >= maxSections {
				return secs
			}
			name := ln[len(secPrefix) : len(ln)-len(secSuffix)]
			secs = append(secs, scriptSection{name: name})
			cur = len(secs) - 1
			start = min(next, len(s))
		}
		pos = next
	}
	if cur >= 0 {
		secs[cur].body = sectionBody(s, start, len(s))
	}
	return secs
}

// sectionBody schneidet den Inhalt aus; der Zeilenumbruch vor dem naechsten Kopf gehoert zum Trenner.
func sectionBody(s string, start, end int) []byte {
	if start > end {
		return nil
	}
	b := s[start:end]
	b = strings.TrimSuffix(b, "\n")
	b = strings.TrimSuffix(b, "\n")
	return []byte(b)
}

// validHostPath prueft Pfade aus der Skript-Ausgabe (nur fuer die Tabelle, es wird nie darauf zugegriffen).
func validHostPath(p string) bool {
	return strings.HasPrefix(p, "/") && len(p) <= 512 && !strings.ContainsAny(p, "\x00\n")
}

// firstLine liefert die erste nicht leere Zeile (Text eines Fehler-Abschnitts).
func firstLine(b []byte) string {
	for _, ln := range lines(b) {
		if t := strings.TrimSpace(ln); t != "" {
			return t
		}
	}
	return m64proto.HintUnknownError
}

// ParseScriptOutput wertet die Ausgabe von Script aus. now ist die Empfangszeit (Report.Time).
// Fehler nur bei zu grosser oder fremder Ausgabe; fehlende Teile ergeben Errors bzw. Notes im Report. Abschnitte,
// die das Skript als "err:NAME" meldet (Zeitlimit, Exit-Code), stehen in Errors; "err:smart:GERAET" wird wie beim
// Agent zu SMART.Error der Platte.
func ParseScriptOutput(out []byte, now time.Time) (*m64proto.Report, error) {
	if len(out) > m64proto.MaxReportBytes {
		return nil, errors.New(m64proto.Hint(m64proto.HintTooLarge, strconv.Itoa(len(out)), strconv.Itoa(m64proto.MaxReportBytes)))
	}
	secs := splitSections(out)
	if len(secs) == 0 {
		return nil, errors.New(m64proto.HintNoOutput)
	}
	r := &m64proto.Report{V: m64proto.Version, Time: now.UnixMilli()}
	files := map[string][]byte{}
	addFile := func(p string, b []byte) {
		if _, ok := files[p]; ok || len(files) < maxFiles {
			files[p] = b
		}
	}
	cmd := map[string][]byte{}
	type smartOut struct {
		dev  string
		body []byte
	}
	var smarts []smartOut
	smartErr := map[string]string{}
	errSec := map[string]bool{}
	updMgr := ""
	ended := false
	for _, sec := range secs {
		name := sec.name
		switch {
		case strings.HasPrefix(name, "file:"):
			addFile(name[len("file:"):], sec.body)
		case name == "attr":
			for i, ln := range lines(sec.body) {
				if i >= maxLines {
					break
				}
				p, v, ok := strings.Cut(ln, "\t")
				if !ok || !validHostPath(p) {
					continue
				}
				if hp, isHex := strings.CutSuffix(p, ".hex"); isHex { // Binaerdatei (vpd_pg80)
					if b, err := hex.DecodeString(strings.TrimSpace(v)); err == nil && len(b) > 0 && len(b) <= 4096 {
						addFile(hp, b)
					}
					continue
				}
				addFile(p, []byte(v))
			}
		case strings.HasPrefix(name, "smart:"):
			if len(smarts) < maxSmartDevices {
				smarts = append(smarts, smartOut{dev: name[len("smart:"):], body: sec.body})
			}
		case strings.HasPrefix(name, "updates:"):
			updMgr = name[len("updates:"):]
			cmd["updates"] = sec.body
		case strings.HasPrefix(name, "updates_sec:"):
			cmd["updates_sec"] = sec.body
		case strings.HasPrefix(name, "err:"):
			s, dev, _ := strings.Cut(name[len("err:"):], ":")
			switch {
			case dev != "":
				smartErr[dev] = clip(firstLine(sec.body))
			case len(r.Errors) < maxErrs:
				addErr(r, s, errors.New(firstLine(sec.body)))
				errSec[s] = true
			}
		case name == "note":
			for _, ln := range lines(sec.body) {
				s, t, _ := strings.Cut(ln, " ")
				if len(r.Notes) < maxErrs && s != "" {
					addNote(r, clip(s), t)
				}
			}
		case name == "end":
			ended = true
		default:
			cmd[name] = sec.body
		}
	}
	if !ended {
		addNote(r, "script", m64proto.HintIncomplete)
	}

	src := newMapSource(files)
	all := func(string) bool { return true }
	readProcBasics(src, r, all)

	// Dateisysteme aus df, Typ und "ro" aus /proc/mounts
	if df, ok := cmd["df"]; ok {
		var mounts []Mount
		if b, err := src.ReadFile("/proc/mounts"); err == nil {
			mounts = ParseMounts(b)
		}
		r.FS = FSFromDF(ParseDF(df), mounts, ParseDFInodes(cmd["df_i"]))
	} else if !errSec[m64proto.SecFS] {
		addErr(r, m64proto.SecFS, errors.New(m64proto.Hint(m64proto.HintMissing, "df")))
	}
	ds, err := readDisks(src)
	r.Disks = ds
	addErr(r, m64proto.SecDisk, err)
	ns, err := readNet(src)
	r.Net = ns
	addErr(r, m64proto.SecNet, err)
	bs, errs := readBonds(src)
	r.Bonds = bs
	for _, e := range errs {
		addErr(r, m64proto.SecBond, e)
	}
	if b, err := src.ReadFile("/proc/mdstat"); err == nil {
		r.RAID = ParseMdstat(b)
	}
	r.Btrfs = readBtrfs(src)
	r.Temps = readTemps(src)
	r.Power = readPower(src)

	if zl, ok := cmd["zpool_list"]; ok {
		pools := ParseZpoolList(zl)
		if len(pools) > 0 {
			MergeZpoolStatus(pools, ParseZpoolStatus(cmd["zpool_status"]))
			r.ZFS = pools
		} else if rc := strings.TrimSpace(string(cmd["zpool_list_rc"])); rc != "" && rc != "0" && len(lines(zl)) > 0 {
			addErr(r, m64proto.SecZFS, errors.New("zpool list: "+m64proto.Hint(m64proto.HintExitCode, rc)))
		}
	}
	if f, ok := cmd["systemd_failed"]; ok {
		r.Systemd = newSystemd(f, cmd["systemd_state"])
	} else if !errSec[m64proto.SecSystemd] {
		addNote(r, m64proto.SecSystemd, m64proto.HintNoSystemd)
	}
	rb := readReboot(src)
	if nr, ok := cmd["needs_restarting"]; ok && !rb.Required {
		if code, err := strconv.Atoi(strings.TrimSpace(string(nr))); err == nil {
			if req, ok := ParseNeedsRestarting(code); ok {
				rb.Required = req
			}
		}
	}
	r.Reboot = rb

	if updMgr != "" {
		u, err := ParseUpdates(updMgr, cmd["updates"], cmd["updates_sec"])
		if err != nil {
			addErr(r, m64proto.SecUpdates, fmt.Errorf("%s: %w", clip(updMgr), err))
		} else {
			u.Checked = now.Unix()
			r.Updates = u
		}
	}
	if len(smarts) > 0 {
		r.SMART = []m64proto.SMART{}
		for _, s := range smarts {
			if !DeviceRE.MatchString(s.dev) || strings.Contains(s.dev, "..") {
				continue
			}
			if e, ok := smartErr[s.dev]; ok {
				r.SMART = append(r.SMART, m64proto.SMART{Device: s.dev, Error: e})
				continue
			}
			if len(strings.TrimSpace(string(s.body))) == 0 {
				r.SMART = append(r.SMART, m64proto.SMART{Device: s.dev, Error: m64proto.Hint(m64proto.HintNoOutputOf, "smartctl")})
				continue
			}
			r.SMART = append(r.SMART, ParseSmartctl(s.dev, s.body))
		}
		fillSmartSerials(r.SMART, r.Disks)
	}
	return r, nil
}
