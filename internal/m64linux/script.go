package m64linux

import (
	_ "embed"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Script ist das feste Skript fuer die SSH-Abfrage ohne Agent ("sh -s -- [smart] [updates]", Skript auf stdin).
// Es liest nur und bekommt keine Werte von Hosts oder Benutzern; die einzigen Argumente sind die festen Woerter
// ScriptArgSmart und ScriptArgUpdates. Die Ausgabe wertet ParseScriptOutput aus.
//
//go:embed script.sh
var Script string

// Feste Argumente fuer Script.
const (
	ScriptArgSmart   = "smart"   // SMART lesen (root oder "sudo -n smartctl")
	ScriptArgUpdates = "updates" // Paket-Updates pruefen (Node: hoechstens stuendlich)
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
)

type scriptSection struct {
	name string
	body []byte
}

// splitSections zerlegt die Ausgabe in Abschnitte (Reihenfolge bleibt, Namen duerfen mehrfach vorkommen).
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
		if strings.HasPrefix(ln, secPrefix) && strings.HasSuffix(ln, secSuffix) && len(ln) <= 600 {
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

// ParseScriptOutput wertet die Ausgabe von Script aus. now ist die Empfangszeit (Report.Time).
// Fehler nur bei zu grosser oder fremder Ausgabe; fehlende Teile ergeben Errors bzw. Notes im Report.
func ParseScriptOutput(out []byte, now time.Time) (*m64proto.Report, error) {
	if len(out) > m64proto.MaxReportBytes {
		return nil, fmt.Errorf("Ausgabe zu gross (%d Bytes, hoechstens %d)", len(out), m64proto.MaxReportBytes)
	}
	secs := splitSections(out)
	if len(secs) == 0 {
		return nil, errors.New("keine Monitor64-Ausgabe")
	}
	r := &m64proto.Report{V: m64proto.Version, Time: now.UnixMilli()}
	files := map[string][]byte{}
	cmd := map[string][]byte{}
	type smartOut struct {
		dev  string
		body []byte
	}
	var smarts []smartOut
	updMgr := ""
	ended := false
	for _, sec := range secs {
		name := sec.name
		switch {
		case strings.HasPrefix(name, "file:"):
			if p := name[len("file:"):]; validHostPath(p) {
				files[p] = sec.body
			}
		case name == "attr":
			for _, ln := range lines(sec.body) {
				p, v, ok := strings.Cut(ln, "\t")
				if ok && validHostPath(p) {
					files[p] = []byte(v)
				}
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
		case name == "note":
			for _, ln := range lines(sec.body) {
				s, t, _ := strings.Cut(ln, " ")
				if len(r.Notes) < 64 && s != "" {
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
		addNote(r, "script", "Ausgabe unvollstaendig (Zeitlimit oder Abbruch)")
	}

	src := mapSource{files: files}
	all := func(string) bool { return true }
	readProcBasics(src, r, all)

	// Dateisysteme aus df, Typ und "ro" aus /proc/mounts
	if df, ok := cmd["df"]; ok {
		var mounts []Mount
		if b, err := src.ReadFile("/proc/mounts"); err == nil {
			mounts = ParseMounts(b)
		}
		r.FS = FSFromDF(ParseDF(df), mounts, ParseDFInodes(cmd["df_i"]))
	} else {
		addErr(r, m64proto.SecFS, errors.New("df fehlt"))
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
	r.Temps = readTemps(src)

	if zl, ok := cmd["zpool_list"]; ok {
		if pools := ParseZpoolList(zl); len(pools) > 0 {
			mergeZpoolStatus(pools, ParseZpoolStatus(cmd["zpool_status"]))
			r.ZFS = pools
		}
	}
	if f, ok := cmd["systemd_failed"]; ok {
		r.Systemd = newSystemd(f, cmd["systemd_state"])
	} else {
		addNote(r, m64proto.SecSystemd, "kein systemd")
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
			if len(strings.TrimSpace(string(s.body))) == 0 {
				r.SMART = append(r.SMART, m64proto.SMART{Device: s.dev, Error: "keine Ausgabe von smartctl"})
				continue
			}
			r.SMART = append(r.SMART, ParseSmartctl(s.dev, s.body))
		}
	}
	return r, nil
}
