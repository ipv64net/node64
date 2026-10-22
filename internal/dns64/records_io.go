package dns64

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Eigene Eintraege bearbeiten, importieren und exportieren. Import erkennt das Format selbst: JSON (Liste wie
// GET /api/dns64/records), CSV (name,type,value,ttl,comment; Kopfzeile optional) oder eine Hosts-Datei
// ("192.168.1.10 nas nas.home.lan" -> je Name ein A/AAAA-Eintrag). Export als Hosts-Datei (nur A/AAAA), CSV oder JSON.

// importResult: angelegt, schon vorhanden (bzw. Hosts-Eintraege wie localhost), ungueltig.
type importResult struct {
	Added   int `json:"added"`
	Skipped int `json:"skipped"`
	Invalid int `json:"invalid"`
}

// hostsSkip: Namen aus Standard-Hosts-Dateien, die nicht als eigener Eintrag taugen.
var hostsSkip = map[string]bool{"localhost": true, "localhost.localdomain": true, "broadcasthost": true, "ip6-localhost": true,
	"ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true, "ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true}

// parseRecords liest die Eintraege eines Imports; bad zaehlt Zeilen, die sich nicht lesen lassen.
func parseRecords(text string) (list []Record, skipped, bad int) {
	text = strings.TrimPrefix(strings.TrimSpace(text), "\ufeff")
	if strings.HasPrefix(text, "[") {
		if json.Unmarshal([]byte(text), &list) != nil {
			return nil, 0, 1
		}
		return list, 0, 0
	}
	first := text
	if i := strings.IndexByte(first, '\n'); i >= 0 {
		first = first[:i]
	}
	if f := strings.Fields(first); len(f) > 0 {
		if _, err := netip.ParseAddr(f[0]); err != nil && strings.ContainsAny(first, ",;") {
			return parseCSV(text)
		}
	}
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil || len(f) < 2 {
			bad++
			continue
		}
		if a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() { // Standardzeilen und Sperrlisten (0.0.0.0 werbung.de)
			skipped += len(f) - 1
			continue
		}
		typ := "A"
		if a.Is6() && !a.Is4In6() {
			typ = "AAAA"
		}
		for _, n := range f[1:] {
			if hostsSkip[strings.ToLower(n)] {
				skipped++
				continue
			}
			list = append(list, Record{Name: n, Type: typ, Value: a.Unmap().String()})
		}
	}
	return list, skipped, bad
}

func parseCSV(text string) (list []Record, skipped, bad int) {
	sep := ','
	if strings.Count(text, ";") > strings.Count(text, ",") {
		sep = ';'
	}
	cr := csv.NewReader(strings.NewReader(text))
	cr.Comma, cr.FieldsPerRecord, cr.TrimLeadingSpace, cr.Comment = sep, -1, true, '#'
	for i := 0; ; i++ {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			bad++
			continue
		}
		if i == 0 && strings.EqualFold(strings.TrimSpace(row[0]), "name") {
			continue // Kopfzeile
		}
		if len(row) < 3 {
			bad++
			continue
		}
		r := Record{Name: row[0], Type: row[1], Value: row[2]}
		if len(row) > 3 && strings.TrimSpace(row[3]) != "" {
			if r.TTL, err = strconv.Atoi(strings.TrimSpace(row[3])); err != nil {
				bad++
				continue
			}
		}
		if len(row) > 4 {
			r.Comment = row[4]
		}
		list = append(list, r)
	}
	return list, skipped, bad
}

// ImportRecords legt die Eintraege eines Imports an; vorhandene (gleicher Name, Typ, Wert) bleiben.
func (m *Module) ImportRecords(ctx context.Context, text string) (importResult, error) {
	return m.importText(ctx, text, "")
}

// importText: wie ImportRecords, auch Zonendateien (BIND-Format); zone gilt fuer relative Namen ohne $ORIGIN.
func (m *Module) importText(ctx context.Context, text, zone string) (importResult, error) {
	if isZoneFile(text) {
		if zone == "" {
			zone = "."
		}
		return m.importZoneFile(ctx, text, zone)
	}
	list, skipped, bad := parseRecords(text)
	res := importResult{Skipped: skipped, Invalid: bad}
	return res, m.addBatch(ctx, list, &res)
}

// addBatch legt die Eintraege eines Imports in einer Transaktion an und laedt danach einmal neu (statt je Eintrag:
// bei tausenden Eintraegen sonst quadratisch). Doppelte bzw. CNAME neben anderen Typen zaehlen als uebersprungen,
// ungueltige als ungueltig; Fehler nur, wenn die Datenbank streikt.
func (m *Module) addBatch(ctx context.Context, list []Record, res *importResult) error {
	existing, err := m.Records(ctx)
	if err != nil {
		return err
	}
	byName := map[string][]Record{}
	for _, x := range existing {
		byName[x.Name] = append(byName[x.Name], x)
	}
	tx, err := m.core.Writer().BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC().Format(time.RFC3339)
	for _, r := range list {
		if normalizeRecord(&r) != nil {
			res.Invalid++
			continue
		}
		skip := false
		for _, x := range byName[r.Name] {
			if x.Type == r.Type && x.Value == r.Value || x.Type == "CNAME" || r.Type == "CNAME" {
				skip = true
			}
		}
		if skip {
			res.Skipped++
			continue
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO dns64_records (name, type, value, ttl, comment, no_ptr, local_only, enabled, created_at) VALUES (?,?,?,?,?,?,?,1,?)`,
			r.Name, r.Type, r.Value, r.TTL, r.Comment, r.NoPTR, r.LocalOnly, now); err != nil {
			return err
		}
		byName[r.Name] = append(byName[r.Name], r)
		res.Added++
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return m.loadRecords(ctx)
}

// exportRecords schreibt die Eintraege als hosts, csv oder json; liefert Inhalt, Typ und Dateiendung.
func exportRecords(list []Record, format string) ([]byte, string, string) {
	var b bytes.Buffer
	switch format {
	case "csv":
		cw := csv.NewWriter(&b)
		_ = cw.Write([]string{"name", "type", "value", "ttl", "comment"})
		for _, r := range list {
			_ = cw.Write([]string{r.Name, r.Type, r.Value, strconv.Itoa(r.TTL), r.Comment})
		}
		cw.Flush()
		return b.Bytes(), "text/csv; charset=utf-8", "csv"
	case "json":
		_ = json.NewEncoder(&b).Encode(list)
		return b.Bytes(), "application/json; charset=utf-8", "json"
	}
	byIP, order := map[string][]string{}, []string{}
	for _, r := range list {
		if (r.Type != "A" && r.Type != "AAAA") || strings.HasPrefix(r.Name, "*.") || !r.Enabled {
			continue
		}
		if _, ok := byIP[r.Value]; !ok {
			order = append(order, r.Value)
		}
		byIP[r.Value] = append(byIP[r.Value], r.Name)
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, _ := netip.ParseAddr(order[i])
		c, _ := netip.ParseAddr(order[j])
		return a.Less(c)
	})
	b.WriteString("# Node64 DNS64 – eigene Eintraege (A/AAAA)\n")
	for _, ip := range order {
		b.WriteString(ip + "\t" + strings.Join(byIP[ip], " ") + "\n")
	}
	return b.Bytes(), "text/plain; charset=utf-8", "hosts"
}

func (m *Module) writeExport(w http.ResponseWriter, r *http.Request) {
	list, err := m.Records(r.Context())
	if err != nil {
		m.fail(w, err)
		return
	}
	body, typ, ext := exportRecords(list, r.URL.Query().Get("format"))
	name := "dns64-records." + ext
	if ext == "hosts" {
		name = "hosts"
	}
	w.Header().Set("Content-Type", typ)
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(body)
}

// ---- Seite ----

func (m *Module) pageRecordEdit(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rec, err := m.UpdateRecord(r.Context(), id, recordForm(r))
	if err == nil {
		m.log.Info("record changed", "id", id, "name", rec.Name, "type", rec.Type, "value", rec.Value, "by", m.g.Actor(r))
		m.audit(r, "dns64.record.edit", rec.Name, rec.Type+" "+rec.Value)
	}
	m.recordBack(w, r, err, "dns64.records.saved")
}

// recordForm liest einen Eintrag aus dem Formular der Seite; mit Zone ist der Name relativ ("@" = die Zone selbst).
func recordForm(r *http.Request) Record {
	ttl := formInt(r, "ttl")
	if ttl < 0 {
		ttl = 0
	}
	return Record{Name: qualify(r.PostFormValue("name"), r.PostFormValue("zone")), Type: r.PostFormValue("type"), Value: r.PostFormValue("value"), TTL: ttl,
		Comment: r.PostFormValue("comment"), NoPTR: r.PostFormValue("no_ptr") == "1", LocalOnly: r.PostFormValue("local_only") == "1"}
}

// qualify haengt die Zone an einen relativen Namen ("@" oder leer = die Zone, Name mit Punkt am Ende = absolut).
func qualify(name, zone string) string {
	name, zone = strings.TrimSpace(name), strings.TrimSuffix(strings.TrimSpace(zone), ".")
	switch {
	case zone == "":
		return name
	case name == "@" || name == "":
		return zone
	case strings.HasSuffix(name, "."):
		return name
	case strings.EqualFold(name, zone) || strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(zone)):
		return name
	}
	return name + "." + zone
}

func (m *Module) pageRecordImport(w http.ResponseWriter, r *http.Request) {
	text := r.PostFormValue("text")
	if f, _, err := r.FormFile("file"); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, 2<<20))
		f.Close()
		text = string(b) + "\n" + text
	}
	res, err := m.importText(r.Context(), text, r.PostFormValue("zone"))
	if err == nil {
		m.log.Info("records imported", "added", res.Added, "skipped", res.Skipped, "invalid", res.Invalid, "by", m.g.Actor(r))
		m.audit(r, "dns64.record.import", strconv.Itoa(res.Added)+" records", strconv.Itoa(res.Invalid)+" invalid")
		m.g.Flash(w, r, "success", m.g.T(r, "dns64.records.imported", "n", res.Added, "skipped", res.Skipped, "bad", res.Invalid))
	}
	m.recordBack(w, r, err, "")
}

// ---- API ----

func (m *Module) apiRecordUpdate(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var in Record
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	rec, err := m.UpdateRecord(r.Context(), id, in)
	var ce *cfgError
	switch {
	case errors.As(err, &ce):
		writeErr(w, http.StatusBadRequest, m.errText(r, err))
		return
	case errors.Is(err, errNotFound):
		writeErr(w, http.StatusNotFound, m.errText(r, err))
		return
	case err != nil:
		m.fail(w, err)
		return
	}
	m.audit(r, "dns64.record.edit", rec.Name, rec.Type+" "+rec.Value)
	writeJSON(w, http.StatusOK, rec)
}

func (m *Module) apiRecordImport(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "body too large")
		return
	}
	res, err := m.importText(r.Context(), string(b), r.URL.Query().Get("zone"))
	if err != nil {
		m.fail(w, err)
		return
	}
	m.audit(r, "dns64.record.import", strconv.Itoa(res.Added)+" records", strconv.Itoa(res.Invalid)+" invalid")
	writeJSON(w, http.StatusOK, res)
}
