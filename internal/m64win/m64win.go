// Package m64win liest Windows-Werte fuer den Monitor64-Agent (Plan docs/PLAN-NODE64-MONITOR64.md, Abschnitt
// "Monitor64-Agent", Punkt "Windows") und liefert denselben m64proto.Report wie m64linux.
//
//   - Schnelle Werte ueber die Windows-API (golang.org/x/sys/windows, ohne cgo): CPU (GetSystemTimes), Speicher
//     (GlobalMemoryStatusEx, Auslagerungsdatei), feste Laufwerke, Platten-I/O (IOCTL_DISK_PERFORMANCE), Netzwerk
//     (GetIfTable2), Dienste mit Starttyp Automatisch, "Neustart noetig" (Registry). Collect blockiert dafuer nie
//     lange.
//   - Langsame Werte ueber PowerShell mit festen Skripten (keine Eingaben von aussen, Zeitlimit, Ausgabe als JSON,
//     Groesse begrenzt): Get-PhysicalDisk/Get-StorageReliabilityCounter (SMART-Ersatz), Storage Spaces
//     (Get-VirtualDisk), Windows Update (Microsoft.Update.Session). Ein Cache liest sie im Hintergrund (SMART 30 min,
//     Updates 60 min) und liefert sofort den letzten Stand.
//
// Die Auswertung (JSON der Skripte, Puffer aus der API, Filter) steht in dieser Datei und ist plattformunabhaengig
// testbar; die Aufrufe der Windows-API stehen in den *_windows.go-Dateien.
//
// Alles, was vom Host kommt, ist nicht vertrauenswuerdig: Groessen und Anzahlen sind begrenzt, Texte gekuerzt.
package m64win

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ipv64net/node64/internal/m64proto"
)

// Grenzen gegen ausufernde Hosts.
const (
	maxItems    = 512     // Eintraege je Abschnitt (Laufwerke, Schnittstellen, Platten, Dienste)
	maxText     = 300     // Laenge freier Texte (Fehler, Namen)
	maxPSOutput = 1 << 20 // Ausgabe eines PowerShell-Skripts
	maxPSErr    = 4 << 10 // stderr eines PowerShell-Skripts (nur fuer Fehlertexte)
	maxDrives   = 64      // \\.\PhysicalDrive0..63
)

// Zeitlimits.
const (
	timeoutStorage = 2 * time.Minute  // Get-PhysicalDisk und Zuverlaessigkeitszaehler
	timeoutUpdates = 10 * time.Minute // Windows-Update-Suche (erste Suche kann dauern)
	timeoutRefresh = 15 * time.Minute // Erneuern im Hintergrund insgesamt
	slowRetry      = 5 * time.Minute  // gescheiterter langsamer Abschnitt: so bald neu versuchen
	slowFirstWait  = 2 * time.Second  // erster Lauf: so lange auf das Ergebnis warten, dann Hinweis
	raidEvery      = 5 * time.Minute  // Storage Spaces (nur wenn vorhanden) oefter als SMART
	deadlineMargin = 3 * time.Second  // Collect endet so viel vor der ctx-Deadline
)

// NoteReading steht in Notes (SMART, Updates), solange der erste Lauf im Hintergrund noch nicht fertig ist
// (gleicher Text wie m64linux.NoteReading).
const NoteReading = "wird gelesen"

// Schluessel im Cache.
const (
	keyStorage = "storage" // SMART und Storage Spaces
	keyRAID    = "raid"    // nur Storage Spaces (oefter, wenn vorhanden)
	keyUpdates = "updates"
)

// PSFunc fuehrt ein festes PowerShell-Skript aus und liefert stdout (hoechstens maxPSOutput Byte). Tests setzen einen
// Ersatz.
type PSFunc func(ctx context.Context, script string) ([]byte, error)

// Options steuern Collect.
type Options struct {
	Sections []string         // gewuenschte Abschnitte (m64proto.Sec*), leer = alle
	Cache    *Cache           // Puffer fuer langsame Abschnitte; nil = Paket-Puffer
	Now      func() time.Time // nil = time.Now
	PS       PSFunc           // nil = powershell.exe (nur Windows)
}

// wantFunc liefert die Abschnittsauswahl (leer = alle).
func wantFunc(secs []string) func(string) bool {
	if len(secs) == 0 {
		return func(string) bool { return true }
	}
	m := map[string]bool{}
	for _, s := range secs {
		m[s] = true
	}
	return func(s string) bool { return m[s] }
}

// ---- Cache fuer langsame Abschnitte (wie m64linux) ----

// Cache puffert langsame Abschnitte. Ist ein Stand veraltet, liefert slow ihn sofort und erneuert ihn im
// Hintergrund; beim ersten Mal wartet slow hoechstens slowFirstWait (bzw. bis ctx endet) und meldet sonst
// NoteReading. Ein Lauf mit Fehlern gilt nur slowRetry lang; ein abgebrochener Lauf ersetzt keinen guten Stand.
type Cache struct {
	mu      sync.Mutex
	entries map[string]*slowEntry
	wg      sync.WaitGroup
}

type slowEntry struct {
	res  slowResult
	have bool
	at   time.Time
	next time.Time
	run  chan struct{}
}

// slowResult ist das Ergebnis eines langsamen Abschnitts.
type slowResult struct {
	smart   []m64proto.SMART
	raid    []m64proto.RAID
	vdisks  int // Anzahl virtueller Datentraeger (Storage Spaces)
	updates *m64proto.Updates
	reboot  bool // Windows Update meldet "Neustart noetig"
	errs    []m64proto.SectionErr
	notes   []m64proto.SectionNote
}

// NewCache legt einen leeren Puffer an.
func NewCache() *Cache { return &Cache{entries: map[string]*slowEntry{}} }

// Wait wartet auf laufende Erneuerungen im Hintergrund (Tests, Beenden).
func (c *Cache) Wait() { c.wg.Wait() }

var defaultCache = NewCache()

// peek liefert den letzten fertigen Stand ohne neuen Lauf.
func (c *Cache) peek(key string) (slowResult, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e := c.entries[key]; e != nil && e.have {
		return e.res, true
	}
	return slowResult{}, false
}

// slow liefert einen gepufferten Abschnitt; gelesen wird immer im Hintergrund (hoechstens ein Lauf je Schluessel).
// sec ist der Abschnitt fuer den Hinweis NoteReading.
func (c *Cache) slow(ctx context.Context, now func() time.Time, key, sec string, maxAge time.Duration, fn func(context.Context) slowResult) slowResult {
	c.mu.Lock()
	if c.entries == nil {
		c.entries = map[string]*slowEntry{}
	}
	e := c.entries[key]
	if e == nil {
		e = &slowEntry{}
		c.entries[key] = e
	}
	t := now()
	stale := !e.have || t.Before(e.at) || !t.Before(e.next)
	if stale && e.run == nil {
		done := make(chan struct{})
		e.run = done
		c.wg.Add(1)
		go func() {
			defer c.wg.Done()
			bg, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeoutRefresh)
			defer cancel()
			nr := fn(bg)
			aborted := bg.Err() != nil
			c.mu.Lock()
			defer c.mu.Unlock()
			t := now()
			if !aborted || !e.have {
				e.res, e.have = nr, true
			}
			e.at = t
			if aborted || len(nr.errs) > 0 {
				e.next = t.Add(slowRetry)
			} else {
				e.next = t.Add(maxAge)
			}
			e.run = nil
			close(done)
		}()
	}
	if e.have {
		res := e.res
		c.mu.Unlock()
		return res
	}
	done := e.run
	c.mu.Unlock()
	tm := time.NewTimer(slowFirstWait)
	defer tm.Stop()
	select {
	case <-done:
	case <-tm.C:
	case <-ctx.Done():
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if e.have {
		return e.res
	}
	return slowResult{notes: []m64proto.SectionNote{{Section: sec, Note: NoteReading}}}
}

// ---- Texte und Fehler ----

// clip kuerzt freie Texte vom Host, ersetzt ungueltiges UTF-8 und Steuerzeichen.
func clip(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxText {
		i := maxText
		for i > 0 && !utf8.RuneStart(s[i]) {
			i--
		}
		s = strings.TrimSpace(s[:i])
	}
	return s
}

func addErr(r *m64proto.Report, sec string, err error) {
	if err == nil {
		return
	}
	r.Errors = append(r.Errors, m64proto.SectionErr{Section: sec, Error: clip(err.Error())})
}

func addNote(r *m64proto.Report, sec, note string) {
	r.Notes = append(r.Notes, m64proto.SectionNote{Section: sec, Note: clip(note)})
}

func ptrU64(v uint64) *uint64   { return &v }
func ptrF64(v float64) *float64 { return &v }
func ptrBool(v bool) *bool      { return &v }

// ---- CPU, Speicher, Laufzeit ----

// ticksPerJiffy rechnet 100-ns-Einheiten (FILETIME) in Hundertstelsekunden um (wie USER_HZ unter Linux), damit
// die Zaehler dieselbe Groessenordnung haben; die Node rechnet nur Anteile.
const ticksPerJiffy = 100000

// cpuFromTimes baut die CPU-Zaehler aus GetSystemTimes (Summe ueber alle Kerne, 100 ns; kernel enthaelt idle).
func cpuFromTimes(idle, kernel, user uint64, cores int) *m64proto.CPU {
	sys := uint64(0)
	if kernel > idle {
		sys = kernel - idle
	}
	return &m64proto.CPU{Cores: cores, User: user / ticksPerJiffy, System: sys / ticksPerJiffy, Idle: idle / ticksPerJiffy}
}

// parsePagefiles liest SYSTEM_PAGEFILE_INFORMATION (NtQuerySystemInformation, Klasse 18): Eintraege mit
// NextEntryOffset (uint32), TotalSize, TotalInUse (Seiten, uint32). Liefert Gesamt und belegt in Bytes.
func parsePagefiles(buf []byte, pageSize uint64) (total, used uint64, ok bool) {
	off := 0
	for i := 0; i < 64; i++ {
		if off < 0 || off+16 > len(buf) {
			return total, used, ok
		}
		next := binary.LittleEndian.Uint32(buf[off:])
		size := uint64(binary.LittleEndian.Uint32(buf[off+4:]))
		inUse := uint64(binary.LittleEndian.Uint32(buf[off+8:]))
		total += size * pageSize
		used += min(inUse, size) * pageSize
		ok = true
		if next == 0 || next > uint32(len(buf)) {
			return total, used, ok
		}
		off += int(next)
	}
	return total, used, ok
}

// ---- Laufwerke und Platten ----

// diskPerf ist der Teil von DISK_PERFORMANCE, den der Agent braucht.
type diskPerf struct {
	bytesRead, bytesWritten uint64
	idle, query             int64 // 100 ns
	reads, writes           uint32
}

// parseDiskPerf liest DISK_PERFORMANCE (IOCTL_DISK_PERFORMANCE): BytesRead 0, BytesWritten 8, ReadTime 16,
// WriteTime 24, IdleTime 32, ReadCount 40, WriteCount 44, QueueDepth 48, SplitCount 52, QueryTime 56.
func parseDiskPerf(b []byte) (diskPerf, bool) {
	if len(b) < 64 {
		return diskPerf{}, false
	}
	le := binary.LittleEndian
	return diskPerf{
		bytesRead:    le.Uint64(b[0:]),
		bytesWritten: le.Uint64(b[8:]),
		idle:         int64(le.Uint64(b[32:])),
		reads:        le.Uint32(b[40:]),
		writes:       le.Uint32(b[44:]),
		query:        int64(le.Uint64(b[56:])),
	}, true
}

// ioTimeMs: beschaeftigte Zeit in ms als steigender Zaehler (Abfragezeit minus Leerlauf); die Node rechnet die
// Auslastung aus der Differenz zweier Berichte.
func (p diskPerf) ioTimeMs() uint64 {
	if p.query <= p.idle || p.idle < 0 {
		return 0
	}
	return uint64(p.query-p.idle) / 10000
}

// storageDesc ist der Teil von STORAGE_DEVICE_DESCRIPTOR (IOCTL_STORAGE_QUERY_PROPERTY), den der Agent braucht.
type storageDesc struct {
	vendor, product, serial string
	bus                     uint32
	removable               bool
}

// parseStorageDesc liest STORAGE_DEVICE_DESCRIPTOR: Version 0, Size 4, DeviceType 8, Modifier 9, RemovableMedia 10,
// CommandQueueing 11, VendorIdOffset 12, ProductIdOffset 16, ProductRevisionOffset 20, SerialNumberOffset 24,
// BusType 28. Die Texte sind ASCII mit Nullbyte am Ende.
func parseStorageDesc(b []byte) (storageDesc, bool) {
	if len(b) < 32 {
		return storageDesc{}, false
	}
	le := binary.LittleEndian
	if sz := le.Uint32(b[4:]); sz >= 32 && int(sz) < len(b) {
		b = b[:sz]
	}
	str := func(off uint32) string {
		if off == 0 || int(off) >= len(b) {
			return ""
		}
		s := b[off:]
		if i := bytes.IndexByte(s, 0); i >= 0 {
			s = s[:i]
		}
		if len(s) > 128 {
			s = s[:128]
		}
		return clip(string(s))
	}
	return storageDesc{
		vendor:    str(le.Uint32(b[12:])),
		product:   str(le.Uint32(b[16:])),
		serial:    strings.TrimRight(str(le.Uint32(b[24:])), ". "), // NVMe: "0000_..._001E."
		bus:       le.Uint32(b[28:]),
		removable: b[10] != 0,
	}, true
}

// model fasst Hersteller und Produkt zusammen (ohne doppelte Angaben).
func (d storageDesc) model() string {
	v, p := strings.TrimSpace(d.vendor), strings.TrimSpace(d.product)
	if v == "" || strings.HasPrefix(strings.ToLower(p), strings.ToLower(v)) {
		return p
	}
	return clip(v + " " + p)
}

// fillSmartSerials uebernimmt die Seriennummer aus den Platten-Zaehlern (gleiche PhysicalDriveN), damit SMART und
// I/O in der Node dieselbe Platte ergeben, auch wenn PowerShell die Nummer anders schreibt.
func fillSmartSerials(sm []m64proto.SMART, disks []m64proto.DiskIO) {
	by := map[string]string{}
	for _, d := range disks {
		if d.Serial != "" {
			by[d.Name] = d.Serial
		}
	}
	for i := range sm {
		if s := by[sm[i].Device]; s != "" {
			sm[i].Serial = s
		}
	}
}

// ---- Netzwerk ----

// Bits in MIB_IF_ROW2.InterfaceAndOperStatusFlags.
const (
	ifFlagHardware  = 0x01
	ifFlagFilter    = 0x02
	ifFlagConnector = 0x04
)

// Typen aus ipifcons.h.
const (
	ifTypeLoopback = 24
	ifTypeTunnel   = 131
)

// netKind ordnet eine Schnittstelle ein: physical (Hardware mit Anschluss) oder virtual; skip fuer Filter-Treiber
// (WFP, QoS ...), Loopback und Tunnel (Teredo, 6to4), die keine eigenen Ports sind.
func netKind(flags uint8, ifType uint32) (kind string, skip bool) {
	if flags&ifFlagFilter != 0 || ifType == ifTypeLoopback || ifType == ifTypeTunnel {
		return "", true
	}
	if flags&ifFlagHardware != 0 && flags&ifFlagConnector != 0 {
		return "physical", false
	}
	return "virtual", false
}

// linkSpeedMbit rechnet bit/s in Mbit/s um (unbekannt bzw. unsinnig gross = 0).
func linkSpeedMbit(bps uint64) int {
	if bps == 0 || bps >= 1e13 {
		return 0
	}
	return int(bps / 1e6)
}

// macString formatiert eine Hardware-Adresse (leer ohne Adresse oder nur Nullen).
func macString(b []byte) string {
	if len(b) == 0 || len(b) > 8 {
		return ""
	}
	zero := true
	parts := make([]string, len(b))
	for i, x := range b {
		parts[i] = fmt.Sprintf("%02x", x)
		if x != 0 {
			zero = false
		}
	}
	if zero {
		return ""
	}
	return strings.Join(parts, ":")
}

// ---- Dienste ----

// Zustaende und Starttypen aus winsvc.h.
const (
	svcAutoStart = 2
	svcStopped   = 1
	svcRunning   = 4
)

// svcState liefert den Zustand als Text.
func svcState(st uint32) string {
	switch st {
	case 1:
		return "stopped"
	case 2:
		return "start_pending"
	case 3:
		return "stop_pending"
	case 4:
		return "running"
	case 5:
		return "continue_pending"
	case 6:
		return "pause_pending"
	case 7:
		return "paused"
	}
	return "unknown"
}

// svcInfo beschreibt einen Dienst fuer die Auswahl.
type svcInfo struct {
	name, display      string
	startType          uint32
	delayed            bool
	triggers           uint32
	state              uint32
	exitCode, specific uint32
}

// svcWanted: in den Bericht kommen Dienste mit Starttyp Automatisch, deren Zustand etwas aussagt. Dienste mit
// Trigger-Start laufen nur bei Bedarf (gestoppt ist normal) und fehlen; ebenso Dienste mit verzoegertem Start, die
// sich sauber beendet haben (Exit-Code 0, z. B. Update-Dienste von Browsern) - laufen sie, stehen sie drin.
func svcWanted(s svcInfo) bool {
	if s.startType != svcAutoStart || s.triggers > 0 {
		return false
	}
	if s.delayed && s.state == svcStopped && s.exitCode == 0 && s.specific == 0 {
		return false
	}
	return true
}

// ---- Neustart noetig ----

// rebootFrom baut den Abschnitt aus den Registry-Merkmalen und dem Stand von Windows Update.
func rebootFrom(wuKey, cbsKey, renames, wuCOM bool) *m64proto.Reboot {
	r := &m64proto.Reboot{}
	if wuKey || wuCOM {
		r.Packages = append(r.Packages, "Windows Update")
	}
	if cbsKey {
		r.Packages = append(r.Packages, "Component Based Servicing")
	}
	if renames {
		r.Packages = append(r.Packages, "PendingFileRenameOperations")
	}
	r.Required = len(r.Packages) > 0
	return r
}

// ---- Ausgabe der PowerShell-Skripte ----

// flexStr nimmt Text oder Zahl (Aufzaehlungen kommen je nach PowerShell-Version als Name oder Zahl).
type flexStr string

func (f *flexStr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexStr(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexStr(n.String())
	return nil
}

// flexList nimmt eine Liste oder einen einzelnen Wert (PowerShell 5.1 entpackt Listen mit einem Element).
type flexList []flexStr

func (f *flexList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '[' {
		var l []flexStr
		if err := json.Unmarshal(b, &l); err != nil {
			return err
		}
		*f = l
		return nil
	}
	var s flexStr
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*f = nil
	} else {
		*f = flexList{s}
	}
	return nil
}

func (f flexList) has(names ...string) bool {
	for _, x := range f {
		for _, n := range names {
			if strings.EqualFold(strings.ReplaceAll(string(x), " ", ""), strings.ReplaceAll(n, " ", "")) {
				return true
			}
		}
	}
	return false
}

// num liest eine Zahl (null/fehlend = nil, negativ, NaN/Inf und Unsinn verworfen).
type num struct {
	v  float64
	ok bool
}

func (n *num) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*n = num{}
		return nil
	}
	if b[0] == '"' { // Zahl als Text
		var s string
		if json.Unmarshal(b, &s) != nil {
			*n = num{}
			return nil
		}
		b = []byte(strings.TrimSpace(s))
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e18 {
		*n = num{}
		return nil
	}
	*n = num{v: f, ok: true}
	return nil
}

func (n num) u64() *uint64 {
	if !n.ok {
		return nil
	}
	return ptrU64(uint64(n.v))
}

// psMember ist eine Platte eines virtuellen Datentraegers.
type psMember struct {
	Name   flexStr `json:"name"`
	Health flexStr `json:"health"`
}

// psStorage ist die Ausgabe von storageScript.
type psStorage struct {
	Disks []struct {
		ID     flexStr  `json:"id"`
		Name   flexStr  `json:"name"`
		Serial flexStr  `json:"serial"`
		Bus    flexStr  `json:"bus"`
		Media  flexStr  `json:"media"`
		Size   num      `json:"size"`
		Health flexStr  `json:"health"`
		Op     flexList `json:"op"`
		Temp   num      `json:"temp"`
		Wear   num      `json:"wear"`
		POH    num      `json:"poh"`
		RErr   num      `json:"rerr"`
		WErr   num      `json:"werr"`
		CErr   flexStr  `json:"cerr"` // Zaehler nicht lesbar (meist fehlende Rechte)
	} `json:"disks"`
	VDisks []struct {
		Name    flexStr    `json:"name"`
		Level   flexStr    `json:"level"`
		Health  flexStr    `json:"health"`
		Op      flexList   `json:"op"`
		Members []psMember `json:"members"`
	} `json:"vdisks"`
	Errors flexList `json:"errors"`
	Fatal  flexStr  `json:"fatal"`
}

// Werte von HealthStatus (MSFT_PhysicalDisk/MSFT_VirtualDisk) als Name oder Zahl.
func health(s flexStr) string {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case "healthy", "0":
		return "healthy"
	case "warning", "1":
		return "warning"
	case "unhealthy", "2":
		return "unhealthy"
	}
	return "unknown"
}

// busType ordnet BusType (Name oder Zahl, STORAGE_BUS_TYPE) einem SMART-Typ zu.
func busType(s flexStr) string {
	switch strings.ToLower(strings.TrimSpace(string(s))) {
	case "nvme", "17":
		return "nvme"
	case "sata", "11", "ata", "3":
		return "ata"
	case "sas", "10", "scsi", "1", "iscsi", "9", "fibre channel", "6":
		return "scsi"
	case "usb", "7":
		return "usb"
	case "raid", "8":
		return "raid"
	case "", "unknown", "0":
		return ""
	}
	return strings.ToLower(clip(string(s)))
}

// isSSD: Verschleiss gibt es nur bei SSD/NVMe (Platten melden 0).
func isSSD(media, bus flexStr) bool {
	m := strings.ToLower(strings.TrimSpace(string(media)))
	return m == "ssd" || m == "4" || busType(bus) == "nvme"
}

// ParseStorage wertet die Ausgabe von storageScript aus: Platten (SMART-Ersatz), virtuelle Datentraeger
// (Storage Spaces als RAID), Fehler und Hinweise.
func ParseStorage(b []byte) (slowResult, error) {
	var out slowResult
	var ps psStorage
	if err := json.Unmarshal(b, &ps); err != nil {
		return out, fmt.Errorf("Ausgabe nicht lesbar: %w", err)
	}
	if ps.Fatal != "" {
		return out, errors.New(clip(string(ps.Fatal)))
	}
	note := func(sec, s string) {
		out.notes = append(out.notes, m64proto.SectionNote{Section: sec, Note: clip(s)})
	}
	for _, e := range ps.Errors {
		if len(out.errs) >= 5 {
			break
		}
		sec := m64proto.SecSmart
		if strings.HasPrefix(string(e), "Get-VirtualDisk") {
			sec = m64proto.SecRAID
		}
		out.errs = append(out.errs, m64proto.SectionErr{Section: sec, Error: clip(string(e))})
	}
	counterErr := ""
	out.smart = []m64proto.SMART{}
	for _, d := range ps.Disks {
		if len(out.smart) >= maxItems {
			break
		}
		id := strings.TrimSpace(string(d.ID))
		if _, err := strconv.Atoi(id); err != nil {
			continue // ohne Plattennummer keine Zuordnung zu \\.\PhysicalDriveN
		}
		s := m64proto.SMART{Device: "PhysicalDrive" + id, Type: busType(d.Bus), Model: clip(string(d.Name)),
			Serial: strings.TrimRight(clip(string(d.Serial)), ". ")}
		if v := d.Size.u64(); v != nil {
			s.CapacityBytes = *v
		}
		switch health(d.Health) {
		case "healthy":
			s.Passed = ptrBool(true)
		case "unhealthy":
			s.Passed = ptrBool(false)
		case "warning":
			// "Predictive Failure" ist die SMART-Vorhersage; andere Warnungen (z. B. Transient Error) nur als Hinweis
			s.Passed = ptrBool(!d.Op.has("Predictive Failure"))
			if *s.Passed {
				note(m64proto.SecSmart, fmt.Sprintf("%s: HealthStatus Warning (%s)", s.Device, joinFlex(d.Op)))
			}
		}
		if d.CErr != "" && counterErr == "" {
			counterErr = string(d.CErr)
		}
		if d.Temp.ok && d.Temp.v > 0 && d.Temp.v < 150 {
			s.TempC = ptrF64(d.Temp.v)
		}
		if d.Wear.ok && d.Wear.v <= 100 && isSSD(d.Media, d.Bus) {
			s.WearPercentUsed = ptrF64(d.Wear.v)
		}
		if d.POH.ok && d.POH.v > 0 {
			s.PowerOnHours = d.POH.u64()
		}
		if d.RErr.ok || d.WErr.ok {
			s.Uncorrectable = ptrU64(uint64(d.RErr.v) + uint64(d.WErr.v))
		}
		out.smart = append(out.smart, s)
	}
	if counterErr != "" {
		note(m64proto.SecSmart, "Zuverlaessigkeitszaehler nicht lesbar (Administratorrechte noetig?): "+counterErr)
	}
	if len(ps.Disks) == 0 && len(out.errs) == 0 {
		note(m64proto.SecSmart, "keine Platten gefunden")
	}
	for _, v := range ps.VDisks {
		if len(out.raid) >= maxItems {
			break
		}
		out.raid = append(out.raid, vdiskRAID(v.Name, v.Level, v.Health, v.Op, v.Members))
	}
	out.vdisks = len(ps.VDisks)
	return out, nil
}

func joinFlex(l flexList) string {
	s := make([]string, 0, len(l))
	for _, x := range l {
		s = append(s, string(x))
	}
	return strings.Join(s, ", ")
}

// vdiskRAID bildet einen virtuellen Datentraeger (Storage Spaces) auf m64proto.RAID ab.
func vdiskRAID(name, level, hs flexStr, op flexList, members []psMember) m64proto.RAID {
	r := m64proto.RAID{Name: clip(string(name)), Level: strings.ToLower(clip(string(level)))}
	if r.Name == "" {
		r.Name = "virtual disk"
	}
	h := health(hs)
	switch {
	case h == "unhealthy" || op.has("Detached", "Lost Communication", "Error", "Failed"):
		r.State = "failed"
	case op.has("In Service", "InService"):
		r.State = "recovering"
	case h == "warning" || op.has("Degraded", "No Redundancy", "Incomplete"):
		r.State = "degraded"
	case h == "healthy":
		r.State = "clean"
	default:
		r.State = "unknown"
	}
	for i, m := range members {
		if i >= 64 {
			break
		}
		r.Devices++
		switch health(m.Health) {
		case "healthy":
			r.Active++
		case "unhealthy":
			r.Failed++
		}
		r.Members = append(r.Members, clip(string(m.Name)))
	}
	return r
}

// psUpdates ist die Ausgabe von updatesScript.
type psUpdates struct {
	Pending  num     `json:"pending"`
	Security num     `json:"security"`
	Reboot   bool    `json:"reboot"`
	Fatal    flexStr `json:"fatal"`
}

// ParseUpdates wertet die Ausgabe von updatesScript aus.
func ParseUpdates(b []byte, now time.Time) (*m64proto.Updates, bool, error) {
	var ps psUpdates
	if err := json.Unmarshal(b, &ps); err != nil {
		return nil, false, fmt.Errorf("Ausgabe nicht lesbar: %w", err)
	}
	if ps.Fatal != "" {
		return nil, false, errors.New(clip("Windows Update: " + string(ps.Fatal)))
	}
	if !ps.Pending.ok {
		return nil, false, errors.New("Windows Update: keine Anzahl geliefert")
	}
	u := &m64proto.Updates{Manager: "windows", Pending: int(min(ps.Pending.v, 1e6)), Checked: now.Unix()}
	if ps.Security.ok {
		u.Security = int(min(ps.Security.v, ps.Pending.v))
	}
	return u, ps.Reboot, nil
}
