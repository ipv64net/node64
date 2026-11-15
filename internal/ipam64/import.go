package ipam64

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// CSV-Import (Plan Stufe I6): Praefixe oder Adressen aus einer Tabelle (Komma oder Semikolon, erste Zeile = Spalten,
// Gross/Klein egal, unbekannte Spalten werden uebergangen - der eigene CSV-Export laesst sich wieder einlesen).
//   - Adressen, wenn es eine Spalte ip/address/adresse gibt: name, mac, status, role, description, tags, dns, dns_zone,
//     ptr, dhcp. Eine vorhandene Adresse wird ergaenzt (leere Zellen aendern nichts). Ein voller Name (nas.home.lan)
//     ergibt Rechnername und Zone.
//   - sonst Praefixe mit Spalte prefix: name, status, vlan, role, description, tags, dns_zone, scan, dynamic.
// Erst eine Vorschau mit Pruefung je Zeile, dann das Uebernehmen der gueltigen Zeilen (Adressen ueber ApplyAddress,
// also samt DNS64). Eine kaputte Zeile (z. B. Anfuehrungszeichen mitten im Feld) ist ein Fehler dieser Zeile, der Rest
// wird weiter gelesen.

const (
	maxImportBytes = 2 << 20
	maxImportRows  = 10000
)

// ErrImport: Datei leer, zu gross oder ohne passende Spalten.
var ErrImport = errors.New("ipam64: invalid import file")

// ErrCSVLine: Zeile der CSV-Datei laesst sich nicht lesen.
var ErrCSVLine = errors.New("ipam64: invalid csv line")

// ImportRow ist eine Zeile der Vorschau.
type ImportRow struct {
	Line    int
	Kind    string // address | prefix
	Key     string
	Address Address
	Prefix  Prefix
	Exists  bool
	Err     error
}

var importAlias = map[string]string{
	"ip": "address", "adresse": "address", "address": "address", "präfix": "prefix", "praefix": "prefix", "prefix": "prefix",
	"name": "name", "host": "name", "hostname": "name", "rechnername": "name", "mac": "mac", "status": "status", "role": "role", "rolle": "role",
	"description": "description", "beschreibung": "description", "comment": "description", "kommentar": "description", "tags": "tags",
	"dns": "dns", "dns_zone": "dns_zone", "zone": "dns_zone", "ptr": "ptr", "dhcp": "dhcp", "vlan": "vlan", "scan": "scan", "dynamic": "dynamic",
	"dynamisch": "dynamic",
}

// parseBool: leer = nicht gesetzt.
func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return false, false
	case "1", "true", "ja", "yes", "x", "an", "on":
		return true, true
	}
	return false, true
}

// ParseImport liest eine CSV-Datei und prueft jede Zeile (ohne zu speichern).
func (m *Module) ParseImport(ctx context.Context, data []byte) ([]ImportRow, error) {
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf")) // BOM aus Tabellenkalkulationen
	if len(data) == 0 || len(data) > maxImportBytes {
		return nil, ErrImport
	}
	first, _, _ := bytes.Cut(data, []byte("\n"))
	r := csv.NewReader(bytes.NewReader(data))
	if bytes.Count(first, []byte(";")) > bytes.Count(first, []byte(",")) {
		r.Comma = ';'
	}
	r.FieldsPerRecord, r.TrimLeadingSpace = -1, true
	head, err := r.Read()
	if err != nil {
		return nil, ErrImport
	}
	col := map[string]int{}
	for i, h := range head {
		if k, ok := importAlias[strings.ToLower(strings.TrimSpace(h))]; ok {
			if _, dup := col[k]; !dup {
				col[k] = i
			}
		}
	}
	_, hasAddr := col["address"]
	_, hasPrefix := col["prefix"]
	if !hasAddr && !hasPrefix {
		return nil, ErrImport
	}
	snap, err := m.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	var rows []ImportRow
	var newPrefixes []netip.Prefix
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if len(rows) >= maxImportRows {
			return nil, ErrImport
		}
		if err != nil {
			var pe *csv.ParseError
			if !errors.As(err, &pe) {
				return nil, ErrImport
			}
			kind := "address"
			if !hasAddr {
				kind = "prefix"
			}
			rows = append(rows, ImportRow{Line: pe.StartLine, Kind: kind, Err: ErrCSVLine})
			continue
		}
		line, _ := r.FieldPos(0) // Zeile in der Datei (Felder mit Zeilenumbruch zaehlen mit)
		get := func(k string) string {
			if i, ok := col[k]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		row := ImportRow{Line: line}
		if hasAddr {
			row.Kind, row.Key = "address", get("address")
			if row.Key == "" {
				continue
			}
			row.Address, row.Exists, row.Err = m.importAddress(ctx, snap, newPrefixes, get)
		} else {
			row.Kind, row.Key = "prefix", get("prefix")
			if row.Key == "" {
				continue
			}
			row.Prefix, row.Exists, row.Err = m.importPrefix(ctx, get)
			if p, err := netip.ParsePrefix(row.Prefix.Prefix); err == nil && row.Err == nil {
				newPrefixes = append(newPrefixes, p)
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (m *Module) importAddress(ctx context.Context, snap *Snapshot, extra []netip.Prefix, get func(string) string) (Address, bool, error) {
	ip, err := ParseAddr(get("address"))
	if err != nil {
		return Address{Address: get("address")}, false, err
	}
	a := Address{Address: ip.String(), Status: StatusActive, PTR: true}
	cur, err := m.addressWhere(ctx, `address = ?`, a.Address)
	if err != nil {
		return a, false, err
	}
	if cur != nil {
		a = *cur
	}
	if v := strings.ToLower(get("name")); v != "" {
		label, zone, _ := strings.Cut(v, ".")
		a.Name = label
		if zone != "" && get("dns_zone") == "" && zone != zoneOf(snap, a) {
			a.DNSZone = zone
		}
	}
	for k, dst := range map[string]*string{"mac": &a.MAC, "status": &a.Status, "role": &a.Role, "description": &a.Description, "dns_zone": &a.DNSZone} {
		if v := get(k); v != "" {
			*dst = v
		}
	}
	if v := get("tags"); v != "" {
		a.Tags = []string{v}
	}
	for k, dst := range map[string]*bool{"dns": &a.DNS, "ptr": &a.PTR, "dhcp": &a.DHCP} {
		if b, ok := parseBool(get(k)); ok {
			*dst = b
		}
	}
	if err := normalizeAddress(&a); err != nil {
		return a, cur != nil, err
	}
	inside := snap.NetOf(ip) != nil
	for _, p := range extra {
		inside = inside || p.Contains(ip)
	}
	if !inside {
		return a, cur != nil, ErrNoNet
	}
	return a, cur != nil, nil
}

func (m *Module) importPrefix(ctx context.Context, get func(string) string) (Prefix, bool, error) {
	p := Prefix{Prefix: get("prefix"), Status: StatusActive, Scan: ScanPassive}
	if pp, err := ParsePrefix(p.Prefix); err == nil {
		var uid string
		if m.core.Reader().QueryRowContext(ctx, `SELECT uid FROM ipam_prefixes WHERE prefix = ?`, pp.String()).Scan(&uid) == nil {
			cur, err := m.prefixByUID(ctx, uid)
			if err != nil {
				return p, false, err
			}
			p = *cur
		}
	}
	exists := p.UID != ""
	for k, dst := range map[string]*string{"name": &p.Name, "status": &p.Status, "role": &p.Role, "description": &p.Description, "dns_zone": &p.DNSZone, "scan": &p.Scan} {
		if v := get(k); v != "" {
			*dst = v
		}
	}
	if v := get("tags"); v != "" {
		p.Tags = []string{v}
	}
	if v := get("vlan"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return p, exists, ErrVLAN
		}
		p.VLAN = n
	}
	if b, ok := parseBool(get("dynamic")); ok {
		p.DynSource = ""
		if b {
			p.DynSource = DynAuto
		}
	}
	return p, exists, normalizePrefix(&p)
}

// ApplyImport uebernimmt die gueltigen Zeilen (Praefixe zuerst). errText uebersetzt Fehler.
func (m *Module) ApplyImport(ctx context.Context, rows []ImportRow, actor string, errText func(error) string) (int, []SetupSkip) {
	n := 0
	var failed []SetupSkip
	for _, r := range rows {
		if r.Err != nil || r.Kind != "prefix" {
			continue
		}
		if _, err := m.SavePrefix(ctx, r.Prefix, actor); err != nil {
			failed = append(failed, SetupSkip{What: r.Key, Reason: errText(err)})
			continue
		}
		n++
	}
	if vctx, err := m.withView(ctx); err == nil { // Praefixe stehen fest: einmal lesen statt je Adresse
		ctx = vctx
	}
	_ = m.batch(ctx, func(ctx context.Context) error {
		for _, r := range rows {
			if r.Err != nil || r.Kind != "address" {
				continue
			}
			if _, err := m.ApplyAddress(ctx, r.Address, actor); err != nil {
				failed = append(failed, SetupSkip{What: r.Key, Reason: errText(err)})
				continue
			}
			n++
		}
		return nil
	})
	return n, failed
}
